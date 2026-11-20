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
# Instance-specific values are read from Ninja custom fields (Global scope, Scripts = Read)
# so no tenant details live in this public script. See "Ninja Custom Fields required" above.
function Get-NinjaConfig {
    param([string]$Name, $Default = "")
    try { $v = Ninja-Property-Get $Name; if ($v) { return $v } } catch {}
    return $Default
}
$HaloBaseUrl      = (Get-NinjaConfig "halopsaurl" "https://yourtenant.halopsa.com").TrimEnd('/')
$HaloAuthUrl      = "$HaloBaseUrl/auth/token"
$HaloTenant       = ([uri]$HaloBaseUrl).Host.Split('.')[0]
$HaloClientId     = Get-NinjaConfig "halopsaclientid" ""
try { $HaloClientSecret = Ninja-Property-Get halopsasecret } catch { $HaloClientSecret = "" }
$HaloServiceType  = 1     # Service/Incident board
$HaloAlertType    = 21    # Alerts board
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2
$FallbackClientId = [int](Get-NinjaConfig "halopsafallbackclientid" 0)
$FallbackSiteId   = [int](Get-NinjaConfig "halopsafallbacksiteid" 0)

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
# HALO FUNCTIONS
# -----------------------------------------------------------------------
function Get-HaloToken {
    try {
        $response = Invoke-RestMethod `
            -Uri         $HaloAuthUrl `
            -Method      POST `
            -Headers     @{ "halo-tenant" = $HaloTenant } `
            -Body        @{
                grant_type    = "client_credentials"
                client_id     = $HaloClientId
                client_secret = $HaloClientSecret
                scope         = "read:tickets edit:tickets read:customers read:assets"
            } `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        return $response.access_token
    } catch {
        Write-Host "WARNING: Halo auth failed - $($_.Exception.Message)"
        return $null
    }
}

function Get-HaloClientSite {
    param([string]$Token)
    $fallback = @{ ClientId = $FallbackClientId; SiteId = $FallbackSiteId; Source = "fallback (default client)"; IsFallback = $true }
    if (-not $Token) { return $fallback }
    try {
        $results = Invoke-RestMethod `
            -Uri     "$HaloBaseUrl/api/asset?search=$env:COMPUTERNAME&count=10" `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -ErrorAction Stop
        $asset = $results.assets | Where-Object { $_.inventory_number -eq $env:COMPUTERNAME } | Select-Object -First 1
        if ($asset -and $asset.client_id -and $asset.site_id) {
            return @{ ClientId = $asset.client_id; SiteId = $asset.site_id; Source = "Halo asset ($($asset.client_name) / $($asset.site_name))"; IsFallback = $false }
        }
    } catch {
        Write-Host "WARNING: Asset lookup failed - $($_.Exception.Message). Using fallback."
    }
    return $fallback
}

function New-HaloTicket {
    param(
        [string]$Token, [int]$ClientId, [int]$SiteId,
        [string]$Summary, [string]$Details, [int]$TicketType,
        [int]$Priority = 3, [int]$Status = 1, [int]$Urgency = 2
    )
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping ticket creation."; return $null }
    $ticket = @{
        summary       = $Summary
        details_html  = $Details
        tickettype_id = $TicketType
        client_id     = $ClientId
        site_id       = $SiteId
        category_1    = $HaloCategoryId
        impact        = $HaloImpactId
        urgency       = $Urgency
        priority_id   = $Priority
        status_id     = $Status
        customfields  = @(@{ id = 218; value = 1 })
    }
    $body = "[" + ($ticket | ConvertTo-Json -Depth 5) + "]"

    # Retry on transient failures only: HTTP 5xx, 429, or no response (network).
    # 4xx (e.g. malformed payload) is not retried — resending won't help.
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $r = Invoke-WebRequest -UseBasicParsing `
                -Uri     "$HaloBaseUrl/api/tickets" `
                -Method  POST `
                -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
                -Body    $body -ErrorAction Stop
            if ($r.StatusCode -in 200, 201) {
                $created = $r.Content | ConvertFrom-Json
                Write-Host "Halo ticket created: #$($created[0].id)"
                return $created[0].id
            }
            Write-Host "WARNING: Ticket creation failed - $($r.Content)"
            return $null
        } catch {
            $code      = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            $retryable = (-not $code) -or ($code -ge 500) -or ($code -eq 429)
            if ($retryable -and $attempt -lt $maxAttempts) {
                $delay = 5 * $attempt   # 5s, then 10s
                Write-Host "WARNING: Ticket creation attempt $attempt/$maxAttempts failed (HTTP $code) - retrying in ${delay}s: $($_.Exception.Message)"
                Start-Sleep -Seconds $delay
                continue
            }
            Write-Host "WARNING: Ticket creation failed after $attempt attempt(s) (HTTP $code) - $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

function Get-HaloTicketStatus {
    param([string]$Token, [string]$TicketId)
    if (-not $Token -or -not $TicketId) { return $null }
    try {
        $r = Invoke-RestMethod -Uri "$HaloBaseUrl/api/tickets/$TicketId" -Headers @{ "Authorization" = "Bearer $Token" } -ErrorAction Stop
        return $r.status_id
    } catch {
        Write-Host "WARNING: Could not query ticket #$TicketId - $($_.Exception.Message)"
        return $null
    }
}

function Close-HaloTicket {
    param([string]$Token, [string]$TicketId)
    if (-not $Token) { return }
    $body = "[" + (@{ id = [int]$TicketId; status_id = 9 } | ConvertTo-Json -Depth 3) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/tickets" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) { Write-Host "Halo ticket #$TicketId closed." }
        else { Write-Host "WARNING: Could not close ticket #$TicketId - $($r.Content)" }
    } catch { Write-Host "WARNING: Could not close ticket #$TicketId - $($_.Exception.Message)" }
}

function Add-HaloTicketNote {
    param([string]$Token, [string]$TicketId, [string]$Note)
    if (-not $Token) { return }
    $body = "[" + (@{ ticket_id = [int]$TicketId; note = $Note; hiddenfromclient = $true; outcome = "none" } | ConvertTo-Json -Depth 5) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/actions" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) { Write-Host "Note added to ticket #$TicketId" }
        else { Write-Host "WARNING: Could not add note to ticket #$TicketId - $($r.Content)" }
    } catch { Write-Host "WARNING: Could not add note to ticket #$TicketId - $($_.Exception.Message)" }
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
exit 0
