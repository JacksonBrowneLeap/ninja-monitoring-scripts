#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - Service Health Monitor
    Scheduled via Ninja policy. Checks configured services, attempts restart if stopped,
    and creates/resolves Halo PSA tickets based on outcome.

.DESCRIPTION
    - Reads monitored service names from Ninja custom field 'monitoredservices' (comma-separated)
    - Reads open ticket map from Ninja custom field 'servicemonitortickets' (managed by script)
    - For each service:
        * Running + open ticket  → add resolved note + close ticket
        * Running + no ticket    → silent OK
        * Stopped → attempt restart, wait, recheck
            - Now running + open ticket  → add restart note + close ticket
            - Now running + no ticket    → closed Type 21 alert (FYI)
            - Still stopped + open ticket → add re-check note
            - Still stopped + no ticket   → new open Type 1 service ticket

.NOTES
    Version           : 1.5.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Never-restart safety list (NTDS/EventLog/RpcSs); disabled-service skip;
                transient-state guard; case-insensitive exclusion; flapping dedup
                (restart-succeeded ticket now open, auto-closes next run); tamper-protected
                service notes in ticket body (SentinelOne, Defender)
        1.2.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)
        1.3.0 - Tamper-protected services no longer attempt restart; escalate directly like never-restart services
        1.4.0 - Removed WinDefend from built-in list; disabled by design when SentinelOne is installed
        1.5.0 - Built-in list now OS-aware: server roles/TermService skipped on workstations, Netlogon/NTDS/DFSR
                skipped when not domain-joined, stopped non-Automatic services ignored (built-in list only)

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Every 15 minutes
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        monitorhealth           - Text    - Device - Managed by the script: one OK/FAIL line per monitor. Alert on "|FAIL|" (multi-line text)
        monitoredservices     - Text  - comma-separated service names to monitor; leave blank for built-in list
        servicemonitorexclude - Text  - comma-separated service names to skip on this device (case-insensitive)
        servicemonitortickets - Text  - managed by script; do not edit manually
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------------------------------------
# HALO CONFIG
# -----------------------------------------------------------------------
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
$MonitorName = 'Service'
if (-not $HaloLibUrl) { $HaloLibUrl = "https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/lib/HaloCommon.ps1" }
try { Invoke-Expression (Invoke-RestMethod -Uri $HaloLibUrl -UseBasicParsing -ErrorAction Stop) }
catch {
    $loadErr = ($_.Exception.Message -replace '[\r\n"]', ' ')
    Write-Output "ERROR: could not load shared library from $HaloLibUrl - $loadErr"
    # Library not available, so report through the Windows event log (Ninja Windows Event condition: source NinjaMonitor, ID 905)
    & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D "${MonitorName} on ${env:COMPUTERNAME}: could not load shared library - $loadErr" 2>&1 | Out-Null
    exit 1
}
$HaloAlertType    = 21    # Alerts board
$HaloServiceType  = 1     # Service/Incident board
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2     # Multiple Users

# -----------------------------------------------------------------------
# SERVICE CONFIG
# -----------------------------------------------------------------------
$RestartWaitSec = 30    # seconds to wait after restart before rechecking

# Services that must NEVER be auto-restarted — go straight to ticket.
# NTDS: AD corruption risk on DCs. EventLog/RpcSs: OS-foundational.
$NeverRestart = @("NTDS", "EventLog", "RpcSs")

# Services where Start-Service may fail due to vendor tamper protection.
# Ticket Next Steps will flag this so technicians know not to force-restart.
$TamperProtected = @("SentinelAgent", "WinDefend", "MpsSvc")

# Built-in-list entries skipped on workstations (Windows 10/11): server roles and RDP host.
$ServerOnlyServices = @(
    "TermService",
    "DNS", "NTDS", "DFSR", "DHCPServer", "W3SVC", "WAS",
    "MSSQLSERVER", "SQLSERVERAGENT", "MSSQL`$SQLEXPRESS", "ReportServer",
    "MSExchangeIS", "MSExchangeTransport", "MSExchangeFrontEndTransport"
)
# Built-in-list entries skipped when the device is not domain-joined.
$DomainOnlyServices = @("Netlogon", "NTDS", "DFSR")

# Built-in default list — used when 'monitoredservices' Ninja field is empty.
# Services not installed on the machine are silently skipped.
$BuiltInServices = @(
    # ── Core Windows ────────────────────────────────────────────────────
    "EventLog"              # Windows Event Log          (always critical)
    "Spooler"               # Print Spooler
    "MpsSvc"                # Windows Firewall
    "W32Time"               # Windows Time               (important on domain members)
    "Dnscache"              # DNS Client

    # ── Networking / File Services ───────────────────────────────────────
    "LanmanServer"          # Server (SMB file/print sharing)
    "LanmanWorkstation"     # Workstation
    "Netlogon"              # Netlogon                   (domain members only)

    # ── Remote Access ────────────────────────────────────────────────────
    "TermService"           # Remote Desktop Services
    "RpcSs"                 # Remote Procedure Call       (foundational; almost never stops, but catastrophic if it does)

    # ── Server Roles (skipped silently if role not installed) ────────────
    "DNS"                   # DNS Server
    "NTDS"                  # Active Directory DS         (domain controllers only)
    "DFSR"                  # DFS Replication
    "DHCPServer"            # DHCP Server
    "W3SVC"                 # IIS — World Wide Web Publishing
    "WAS"                   # IIS — Windows Process Activation Service
    "MSSQLSERVER"           # SQL Server (default instance)
    "SQLSERVERAGENT"        # SQL Server Agent (default instance)
    "MSSQL`$SQLEXPRESS"     # SQL Server Express named instance
    "ReportServer"          # SQL Server Reporting Services

    # ── Exchange On-Premises ─────────────────────────────────────────────
    "MSExchangeIS"          # Exchange Information Store
    "MSExchangeTransport"   # Exchange Hub Transport
    "MSExchangeFrontEndTransport"

    # ── Security / EDR ───────────────────────────────────────────────────
    "SentinelAgent"         # SentinelOne EDR agent
    "perch-winlogbeat"      # Perch Security — log shipper (SIEM)

    # ── Endpoint Management ──────────────────────────────────────────────
    "ImmyBot Agent"         # ImmyBot agent

    # ── Backup / RMM Agents ──────────────────────────────────────────────
    "NinjaRMMAgent"         # NinjaOne RMM agent
    "VeeamBackupSvc"        # Veeam Backup Service
    "VeeamTransportSvc"     # Veeam Transport Service
    "VeeamDeploymentSvc"    # Veeam Deployment Service
    "BackupExecAgentAccelerator"   # Veritas Backup Exec Agent
    "BackupExecRPCService"         # Veritas Backup Exec RPC
    "AcronisMMS"            # Acronis Managed Machine Service
    "ShadowProtectSvc"      # StorageCraft ShadowProtect
    "DattoAgent"            # Datto RMM Agent
)

# -----------------------------------------------------------------------
# TICKET MAP HELPERS
# Stored format: "ServiceName=TicketId;ServiceName=TicketId"
# -----------------------------------------------------------------------
function Read-TicketMap {
    param([string]$Raw)
    $map = @{}
    if (-not $Raw -or $Raw -eq "none") { return $map }
    $Raw -split ";" | ForEach-Object {
        $parts = $_ -split "=", 2
        if ($parts.Count -eq 2 -and $parts[0].Trim() -ne "" -and $parts[1].Trim() -match '^\d+$') {
            $map[$parts[0].Trim()] = [int]$parts[1].Trim()
        }
    }
    return $map
}

function ConvertTo-TicketMapString {
    param([hashtable]$Map)
    if ($Map.Count -eq 0) { return "none" }
    return ($Map.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";"
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$csInfo    = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction SilentlyContinue

# ProductType: 1 = workstation, 2 = domain controller, 3 = server. Treat unknown as server (monitor everything).
$isWorkstation = ($osInfo -and $osInfo.ProductType -eq 1)
$isDomainJoined = ($csInfo -and $csInfo.PartOfDomain)

Write-Output "=== Service Health Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)  ($(if ($isWorkstation) { 'workstation' } else { 'server' }), $(if ($isDomainJoined) { 'domain-joined' } else { 'workgroup/Entra-joined' }))"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $monitoredServicesRaw = Ninja-Property-Get monitoredservices      } catch { $monitoredServicesRaw = "" }
try { $ticketMapRaw         = Ninja-Property-Get servicemonitortickets  } catch { $ticketMapRaw = "" }
try { $excludeRaw           = Ninja-Property-Get servicemonitorexclude  } catch { $excludeRaw = "" }

$excludedServices = @(
    $excludeRaw -split "," |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" }
)

$fieldServices = @(
    $monitoredServicesRaw -split "," |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" }
)

if ($fieldServices.Count -gt 0) {
    $serviceNames  = $fieldServices
    $usingBuiltIn  = $false
    Write-Output "Service list : field ($($serviceNames.Count) service(s)): $($serviceNames -join ', ')"
} else {
    $serviceNames  = $BuiltInServices | Select-Object -Unique
    $usingBuiltIn  = $true
    # Built-in list is server-oriented: drop entries that don't apply to this device type.
    if ($isWorkstation) {
        $serviceNames = @($serviceNames | Where-Object { $_ -notin $ServerOnlyServices })
    }
    if (-not $isDomainJoined) {
        $serviceNames = @($serviceNames | Where-Object { $_ -notin $DomainOnlyServices })
    }
    Write-Output "Service list : built-in default ($($serviceNames.Count) entries — not-installed services skipped silently)"
}

if ($excludedServices.Count -gt 0) {
    Write-Output "Excluded     : $($excludedServices -join ', ')"
    $excludedLower = $excludedServices | ForEach-Object { $_.ToLower() }
    $serviceNames  = @($serviceNames | Where-Object { $_.ToLower() -notin $excludedLower })
}

$ticketMap = Read-TicketMap -Raw $ticketMapRaw

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken     = Get-HaloToken
$haloTokenTime = Get-Date
$clientSite    = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client. Verify correct client before actioning."
} else { "" }

Write-Output "Halo      : $($clientSite.Source)"
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# SERVICE LOOP
# -----------------------------------------------------------------------
foreach ($svcName in $serviceNames) {

    if (((Get-Date) - $haloTokenTime).TotalMinutes -gt 50) {
        Write-Host "Refreshing Halo token (approaching expiry)..."
        $refreshed = Get-HaloToken
        if ($refreshed) { $haloToken = $refreshed; $haloTokenTime = Get-Date }
    }

    Write-Output ""
    Write-Output "--- [$svcName] ---"

    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        if ($usingBuiltIn) {
            Write-Output "[$svcName] Not installed — skipping."
        } else {
            Write-Output "[$svcName] WARNING: Service not found on this machine — check the service name in 'monitoredservices' field."
        }
        continue
    }

    if ($svc.StartType -eq 'Disabled') {
        Write-Output "[$svcName] Startup type is Disabled — skipping (intentionally disabled by administrator)."
        continue
    }

    # Built-in list only: a stopped Manual/trigger-start service is normal (e.g. Netlogon, TermService,
    # Spooler on clients) — only alert on services that are meant to be always running.
    # Services explicitly listed in the 'monitoredservices' field are always monitored.
    if ($usingBuiltIn -and $svc.Status -eq 'Stopped' -and $svc.StartType -ne 'Automatic') {
        Write-Output "[$svcName] Stopped but startup type is $($svc.StartType) — skipping (not expected to be always running)."
        continue
    }

    if ($svc.Status -notin @("Running", "Stopped")) {
        Write-Output "[$svcName] Status is $($svc.Status) — skipping (transient state)."
        continue
    }

    $existingTicketId = if ($ticketMap.ContainsKey($svcName)) { $ticketMap[$svcName] } else { $null }
    $existingStatus   = if ($existingTicketId) { Get-HaloTicketStatus -Token $haloToken -TicketId $existingTicketId } else { $null }
    $hasOpenTicket    = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

    Write-Output "[$svcName] Status: $($svc.Status)"

    # ── CASE 1: Running ─────────────────────────────────────────────────
    if ($svc.Status -eq "Running") {
        if ($hasOpenTicket) {
            Write-Output "[$svcName] Running — resolving open ticket #$existingTicketId."
            $resolvedNote = @"
<h4>Service Health — Now Running</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Service</b></td><td>$svcName</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
<p>Service is now running. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $existingTicketId -Note $resolvedNote
            Close-HaloTicket   -Token $haloToken -TicketId $existingTicketId
            $ticketMap.Remove($svcName)
        } else {
            Write-Output "[$svcName] Running — no action required."
        }
        continue
    }

    # ── CASE 2: Stopped — attempt restart ───────────────────────────────
    $restartError = $null

    if ($svcName -in $NeverRestart -or $svcName -in $TamperProtected) {
        $skipReason = if ($svcName -in $NeverRestart) { "never-restart list" } else { "tamper-protected list" }
        Write-Output "[$svcName] In $skipReason — escalating directly without restart attempt."
        $restartError = "never-restart"
    } else {
        Write-Output "[$svcName] Attempting restart..."
        try {
            Start-Service -Name $svcName -ErrorAction Stop
        } catch {
            $restartError = $_.Exception.Message
            Write-Output "[$svcName] Restart command failed: $restartError"
        }

        if (-not $restartError) {
            Start-Sleep -Seconds $RestartWaitSec
        }
        $svc.Refresh()
        Write-Output "[$svcName] Post-restart status: $($svc.Status)"
    }

    # ── CASE 2a: Restart succeeded ───────────────────────────────────────
    if ($svc.Status -eq "Running") {

        if ($hasOpenTicket) {
            Write-Output "[$svcName] Restarted OK — resolving open ticket #$existingTicketId."
            $restartNote = @"
<h4>Service Health — Restarted Successfully</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Service</b></td><td>$svcName</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Restart Attempted</b></td><td>Yes</td></tr>
<tr><td><b>Restart Result</b></td><td>Success</td></tr>
</table>
<p>Service was found stopped and was restarted successfully. No further action required, but investigate root cause if this recurs.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $existingTicketId -Note $restartNote
            Close-HaloTicket   -Token $haloToken -TicketId $existingTicketId
            $ticketMap.Remove($svcName)

        } else {
            Write-Output "[$svcName] Restarted OK — creating alert ticket (auto-closes next run if still healthy)."
            $alertBody = @"
<h3>Service Stopped — Restarted Automatically</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Service</b></td><td>$svcName</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Restart Attempted</b></td><td>Yes</td></tr>
<tr><td><b>Restart Result</b></td><td>Success — service is running</td></tr>
</table>
<p>Service was detected as stopped and was restarted automatically. It is now running. This ticket will be closed automatically on the next scheduled check if the service remains healthy. If this recurs frequently, investigate the root cause.</p>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. No billable time was spent.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            $newTicketId = New-HaloTicket `
                -Token      $haloToken `
                -ClientId   $clientSite.ClientId `
                -SiteId     $clientSite.SiteId `
                -AssetId    $clientSite.AssetId `
                -Summary    "SERVICE ALERT | $env:COMPUTERNAME | $svcName — Stopped, auto-restarted" `
                -Details    $alertBody `
                -TicketType $HaloAlertType `
                -Priority   4 `
                -Status     1 `
                -Urgency    3
            if ($newTicketId) {
                $ticketMap[$svcName] = $newTicketId
            }
        }
        continue
    }

    # ── CASE 2b: Still stopped (or never-restart) ────────────────────────
    $escalateMsg = if ($svcName -in $NeverRestart -or $svcName -in $TamperProtected) { "Never-restart/tamper-protected service — escalating directly." } else { "Still stopped after restart attempt — escalating." }
    Write-Output "[$svcName] $escalateMsg"

    $restartAttempted  = if ($svcName -in $NeverRestart) { "No (never-restart list)" } elseif ($svcName -in $TamperProtected) { "No (tamper-protected list)" } else { "Yes" }
    $restartResultText = if ($svcName -in $NeverRestart) {
        "Not attempted — this service is in the never-restart safety list"
    } elseif ($svcName -in $TamperProtected) {
        "Not attempted — this service is tamper-protected (security/EDR service)"
    } elseif ($restartError) {
        "Command failed: $restartError"
    } else {
        "Service did not start within $RestartWaitSec seconds"
    }

    if ($hasOpenTicket) {
        Write-Output "[$svcName] Open ticket #$existingTicketId found — adding re-check note."
        $recheckNote = @"
<h4>Service Health Re-Check — Still Stopped</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Service</b></td><td>$svcName</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Restart Attempted</b></td><td>$restartAttempted</td></tr>
<tr><td><b>Restart Result</b></td><td>$restartResultText</td></tr>
</table>
<p>Automated re-check ran. Service is still not running. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $existingTicketId -Note $recheckNote

    } else {
        Write-Output "[$svcName] No open ticket — creating new service ticket."

        $tamperNote = if ($svcName -in $TamperProtected) {
            "<li><b>Note:</b> This is a protected security/EDR service. The restart failure may be due to tamper protection — do not attempt a forced restart. Check the vendor management console instead.</li>"
        } else { "" }
        $neverRestartNote = if ($svcName -in $NeverRestart) {
            "<li><b>Note:</b> This service is in the never-restart safety list — no automated restart was attempted. Review current system state carefully before taking action.</li>"
        } else { "" }
        $headline    = if ($svcName -in $NeverRestart -or $svcName -in $TamperProtected) { "Service Stopped — Manual Action Required" } else { "Service Stopped — Restart Failed — Manual Action Required" }
        $summaryText = if ($svcName -in $NeverRestart -or $svcName -in $TamperProtected) { "Stopped, no restart attempted" } else { "Stopped, restart failed" }

        $serviceBody = @"
<h3>$headline</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Service</b></td><td>$svcName</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Restart Attempted</b></td><td>$restartAttempted</td></tr>
<tr><td><b>Restart Result</b></td><td>$restartResultText</td></tr>
</table>
<h4>Next Steps</h4>
<ul>
$neverRestartNote
$tamperNote
<li>Check Windows Event Log (System / Application) for errors around the time of failure.</li>
<li>Verify service dependencies are running: <code>sc qc "$svcName"</code></li>
<li>Attempt manual restart: <code>Start-Service "$svcName"</code></li>
<li>If the service runs under a specific account, verify the credentials are valid and the account is not locked.</li>
<li>Review the service executable path and config files for corruption or misconfiguration.</li>
</ul>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

        $newTicketId = New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -AssetId    $clientSite.AssetId `
            -Summary    "SERVICE DOWN | $env:COMPUTERNAME | $svcName — $summaryText" `
            -Details    $serviceBody `
            -TicketType $HaloServiceType `
            -Priority   2 `
            -Status     1 `
            -Urgency    1

        if ($newTicketId) {
            $ticketMap[$svcName] = $newTicketId
        }
    }
}

# -----------------------------------------------------------------------
# WRITE TICKET MAP BACK TO NINJA
# -----------------------------------------------------------------------
$newMapStr = ConvertTo-TicketMapString -Map $ticketMap
try {
    Ninja-Property-Set servicemonitortickets $newMapStr
    Write-Output ""
    Write-Output "Ticket map saved: $newMapStr"
} catch {
    Write-Output "WARNING: Could not write servicemonitortickets field — ticket state not persisted"
}

Write-Output ""
Write-Output "====================================================="
Write-Output "=== Service Health Monitor Complete ==="
Write-Output "Completed : $timestamp"
Complete-Monitor
