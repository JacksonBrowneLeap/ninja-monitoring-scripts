#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - KMS Activation Monitor
    Runs daily. Checks Windows and Office activation status, attempts activation
    if not activated, and creates/resolves Halo PSA tickets based on outcome.

.DESCRIPTION
    - Checks Windows activation via SoftwareLicensingProduct WMI
    - Checks Office activation via OfficeSoftwareProtectionPlatform WMI namespace
    - Attempts slmgr /ato for unactivated Windows before raising a ticket
    - Office activation is reported only — no automated remediation (M365 is user-based)
    - Resolves open ticket automatically when all products are activated

.NOTES
    Version           : 1.5.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Added SQL Server edition check (Evaluation/Express flagging)
        1.2.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)
        1.3.0 - Per-device check exclusions via kmsmonitorexclude custom field
        1.4.0 - Removed SQL Express flagging (Express is free and legitimately licensed —
                was raising daily false-positive P2 tickets); Evaluation edition still flagged
        1.5.0 - New-HaloTicket now retries transient failures (HTTP 5xx/429/network) up to
                3 attempts with 5s/10s backoff; 4xx still fails fast

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Daily
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        monitorhealth           - Text    - Device - Managed by the script: one OK/FAIL line per monitor. Alert on "|FAIL|" (multi-line text)
        kmsmonitorticketid  - Text  - managed by script; do not edit manually
        kmsmonitorexclude   - Text  - optional; comma-separated list of check types to SKIP.
                                      Valid values: Windows, Office, SQL (case-insensitive).
                                      Leave blank to run all checks (default).
                                      Examples: "SQL"  |  "Windows,SQL"  |  "Office"
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------------------------------------
# HALO CONFIG
# -----------------------------------------------------------------------
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
$MonitorName = 'KMS'
if (-not $HaloLibUrl) { $HaloLibUrl = "https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/lib/HaloCommon.ps1" }
try { Invoke-Expression (Invoke-RestMethod -Uri $HaloLibUrl -UseBasicParsing -ErrorAction Stop) }
catch {
    $loadErr = ($_.Exception.Message -replace '[\r\n"]', ' ')
    Write-Output "ERROR: could not load shared library from $HaloLibUrl - $loadErr"
    # Library not available, so report through the Windows event log (Ninja Windows Event condition: source NinjaMonitor, ID 905)
    & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D "${MonitorName} on ${env:COMPUTERNAME}: could not load shared library - $loadErr" 2>&1 | Out-Null
    exit 1
}
# Any terminating error that escapes this script is recorded as a monitorhealth FAIL (see HaloCommon.ps1).
trap { Invoke-MonitorCrash $_ }
$HaloServiceType  = 1     # Service/Incident board
$HaloAlertType    = 21    # Alerts board
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2

# -----------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------
$ActivationTimeoutSec = 60    # max time to wait for slmgr /ato to complete

$LicenseStatusText = @{
    0 = "Unlicensed"
    1 = "Licensed"
    2 = "Out of Box Grace Period"
    3 = "Out of Tolerance Grace Period"
    4 = "Non-Genuine Grace Period"
    5 = "Notification (not activated)"
    6 = "Extended Grace Period"
}

# -----------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------
function Get-LicenseStatusText {
    param([int]$Status)
    if ($LicenseStatusText.ContainsKey($Status)) { return $LicenseStatusText[$Status] }
    return "Unknown ($Status)"
}

function Get-GraceDaysRemaining {
    param($Product)
    if ($Product.GracePeriodRemaining -and $Product.GracePeriodRemaining -gt 0) {
        return [math]::Round($Product.GracePeriodRemaining / 1440, 0)
    }
    return $null
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== KMS Activation Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $lastTicketId      = Ninja-Property-Get kmsmonitorticketid  } catch { $lastTicketId      = "" }
try { $excludeRaw        = Ninja-Property-Get kmsmonitorexclude   } catch { $excludeRaw        = "" }

$excludeList   = ($excludeRaw -split ',') | ForEach-Object { $_.Trim().Trim('"').Trim("'").ToLower() } | Where-Object { $_ }
$CheckWindows  = -not ($excludeList -contains 'windows')
$CheckOffice   = -not ($excludeList -contains 'office')
$CheckSQL      = -not ($excludeList -contains 'sql')

if ($excludeList) {
    Write-Output "Exclusions: $($excludeRaw.Trim())  (skipping: $(($excludeList) -join ', '))"
}

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken  = Get-HaloToken
$clientSite = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client."
} else { "" }

Write-Output "Halo      : $($clientSite.Source)"
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# CHECK WINDOWS ACTIVATION
# -----------------------------------------------------------------------
$problems = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Output ""
Write-Output "--- Windows ---"

if (-not $CheckWindows) {
    Write-Output "Windows: excluded via kmsmonitorexclude — skipping."
} else {
    $allSLP = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
        Where-Object { $_.PartialProductKey }

    $winProduct = $allSLP | Where-Object { $_.Name -match "Windows" } | Select-Object -First 1

    if (-not $winProduct) {
        Write-Output "Windows: No licensed product found via WMI."
    } else {
        $winStatusText = Get-LicenseStatusText -Status ([int]$winProduct.LicenseStatus)
        $winGrace      = Get-GraceDaysRemaining -Product $winProduct
        Write-Output "Product : $($winProduct.Name)"
        Write-Output "Status  : $winStatusText"
        if ($winGrace) { Write-Output "Grace   : $winGrace day(s) remaining" }

        if ($winProduct.LicenseStatus -ne 1) {
            Write-Output "Attempting activation (slmgr /ato)..."
            $proc = Start-Process -FilePath "cscript.exe" `
                -ArgumentList "//nologo `"$env:windir\System32\slmgr.vbs`" /ato" `
                -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($proc) { $proc | Wait-Process -Timeout $ActivationTimeoutSec -ErrorAction SilentlyContinue }

            $winProduct = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
                Where-Object { $_.PartialProductKey -and $_.Name -match "Windows" } | Select-Object -First 1
            $winStatusText = Get-LicenseStatusText -Status ([int]$winProduct.LicenseStatus)
            $winGrace      = Get-GraceDaysRemaining -Product $winProduct
            Write-Output "Post-activation status: $winStatusText"

            if ($winProduct.LicenseStatus -ne 1) {
                $problems.Add([PSCustomObject]@{
                    Type    = "Windows"
                    Product = $winProduct.Name
                    Status  = $winStatusText
                    Grace   = if ($winGrace) { "$winGrace day(s)" } else { "N/A" }
                    Note    = "slmgr /ato was attempted and did not resolve the issue. Check KMS server connectivity."
                })
            }
        } else {
            Write-Output "Windows activation OK."
        }
    }
}

# -----------------------------------------------------------------------
# CHECK OFFICE ACTIVATION
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "--- Office ---"

if (-not $CheckOffice) {
    Write-Output "Office: excluded via kmsmonitorexclude — skipping."
} else {
    $officeProducts = try {
        Get-CimInstance -ClassName OfficeSoftwareProtectionProduct `
            -Namespace root/OfficeSoftwareProtectionPlatform -ErrorAction Stop |
            Where-Object { $_.PartialProductKey }
    } catch { $null }

    if (-not $officeProducts) {
        Write-Output "Office: Not installed or WMI namespace not available — skipping."
    } else {
        foreach ($op in $officeProducts) {
            $opStatus = Get-LicenseStatusText -Status ([int]$op.LicenseStatus)
            $opGrace   = Get-GraceDaysRemaining -Product $op
            Write-Output "Product : $($op.Name)"
            Write-Output "Status  : $opStatus"
            if ($opGrace) { Write-Output "Grace   : $opGrace day(s) remaining" }

            if ($op.LicenseStatus -ne 1) {
                $problems.Add([PSCustomObject]@{
                    Type    = "Office"
                    Product = $op.Name
                    Status  = $opStatus
                    Grace   = if ($opGrace) { "$opGrace day(s)" } else { "N/A" }
                    Note    = "Office activation is user-based (M365) or requires KMS/MAK — no automated fix attempted."
                })
            } else {
                Write-Output "OK."
            }
        }
    }
}

# -----------------------------------------------------------------------
# CHECK SQL SERVER LICENSING
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "--- SQL Server ---"

if (-not $CheckSQL) {
    Write-Output "SQL Server: excluded via kmsmonitorexclude — skipping."
} else {
    $sqlRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"

    if (-not (Test-Path $sqlRegPath)) {
        Write-Output "SQL Server: Not installed — skipping."
    } else {
        $instanceMap = Get-ItemProperty -Path $sqlRegPath -ErrorAction SilentlyContinue
        $instanceNames = $instanceMap.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            Select-Object -ExpandProperty Name

        if (-not $instanceNames) {
            Write-Output "SQL Server: No instances found."
        } else {
            foreach ($instanceName in $instanceNames) {
                $regKey    = $instanceMap.$instanceName
                $setupPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$regKey\Setup"

                if (-not (Test-Path $setupPath)) {
                    Write-Output "[$instanceName] Setup registry key not found — skipping."
                    continue
                }

                $setup   = Get-ItemProperty -Path $setupPath -ErrorAction SilentlyContinue
                $edition = $setup.Edition
                $version = $setup.Version

                Write-Output "[$instanceName] Edition: $edition  Version: $version"

                if ($edition -match "Evaluation") {
                    # Try to estimate days remaining from install date
                    $installDateRaw = $setup.SQLBinRoot
                    $installKey     = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$regKey\Setup"
                    $installDate    = (Get-Item $installKey -ErrorAction SilentlyContinue).LastWriteTime
                    $daysInstalled  = if ($installDate) { [math]::Round(((Get-Date) - $installDate).TotalDays, 0) } else { $null }
                    $daysRemaining  = if ($daysInstalled) { [math]::Max(0, 180 - $daysInstalled) } else { $null }
                    $graceText      = if ($daysRemaining -ne $null) { "$daysRemaining day(s) remaining (approx)" } else { "Unknown" }

                    Write-Output "[$instanceName] WARNING: Evaluation edition — ~$graceText before expiry"
                    $problems.Add([PSCustomObject]@{
                        Type    = "SQL Server"
                        Product = "SQL Server $instanceName ($version)"
                        Status  = "Evaluation Edition"
                        Grace   = $graceText
                        Note    = "Evaluation expires 180 days after install and becomes read-only. Apply a valid licence key via SQL Server Installation Center."
                    })
                } else {
                    Write-Output "[$instanceName] $edition — OK."
                }
            }
        }
    }
}

# -----------------------------------------------------------------------
# TICKET LOGIC
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "====================================================="

$existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }
$hasOpenTicket  = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

if ($problems.Count -eq 0) {
    Write-Output "All products activated — no action required."
    if ($hasOpenTicket) {
        Write-Output "Closing ticket #$lastTicketId (activation resolved)."
        $resolvedNote = @"
<h4>KMS Activation — Resolved</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
<p>All Windows and Office products are now showing as activated. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
        try { Ninja-Property-Set kmsmonitorticketid "none" } catch { Write-Output "WARNING: Could not clear kmsmonitorticketid" }
    }

} else {
    Write-Output "$($problems.Count) activation problem(s) found."

    $problemRows = ($problems | ForEach-Object {
        "<tr><td>$($_.Type)</td><td>$($_.Product)</td><td>$($_.Status)</td><td>$($_.Grace)</td><td>$($_.Note)</td></tr>"
    }) -join ""

    if ($hasOpenTicket) {
        Write-Output "Open ticket #$lastTicketId found — adding re-check note."
        $recheckNote = @"
<h4>KMS Activation Re-Check — Still Not Activated</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
<h4>Problem Products</h4>
<table>
<tr><th>Type</th><th>Product</th><th>Status</th><th>Grace Remaining</th><th>Note</th></tr>
$problemRows
</table>
<p>Automated re-check ran. Products are still not activated. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $recheckNote

    } else {
        Write-Output "No open ticket — creating new service ticket."
        $serviceBody = @"
<h3>Activation Problem — Manual Action Required</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
<h4>Problem Products</h4>
<table>
<tr><th>Type</th><th>Product</th><th>Status</th><th>Grace Remaining</th><th>Note</th></tr>
$problemRows
</table>
<h4>Next Steps</h4>
<ul>
<li>Check KMS server is reachable: <code>nslookup _vlmcs._tcp</code></li>
<li>Check KMS activation manually: <code>cscript slmgr.vbs /ato</code></li>
<li>Check current license info: <code>cscript slmgr.vbs /dlv</code></li>
<li>Check KMS host: <code>cscript slmgr.vbs /skms &lt;KMS-server&gt;</code></li>
<li>For Office: verify M365 user is signed in, or check MAK/KMS licence assignment in admin portal.</li>
<li>If grace period is short, prioritise — activation failure locks the OS after grace expires.</li>
</ul>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

        $newId = New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -AssetId    $clientSite.AssetId `
            -Summary    "ACTIVATION | $env:COMPUTERNAME — $($problems.Count) product(s) not activated" `
            -Details    $serviceBody `
            -TicketType $HaloServiceType `
            -Priority   2 `
            -Status     1 `
            -Urgency    2

        if ($newId) {
            try { Ninja-Property-Set kmsmonitorticketid "$newId" } catch { Write-Output "WARNING: Could not write kmsmonitorticketid" }
        }
    }
}

Write-Output ""
Write-Output "=== KMS Activation Monitor Complete ==="
Write-Output "Completed : $timestamp"
Complete-Monitor
