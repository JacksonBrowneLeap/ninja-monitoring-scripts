#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - NTP Drift Monitor
    Runs daily. Queries an NTP server directly, calculates local time drift,
    attempts resync if drifted, and creates/resolves Halo PSA tickets.

.DESCRIPTION
    - Queries pool.ntp.org (or field override) via UDP port 123
    - Compares NTP time to local UTC time
    - If drift exceeds threshold: attempts w32tm /resync /force, rechecks
    - Resolved ticket auto-closes when drift returns to normal
    - On domain machines: if DC's own time is wrong, all members will show drift
      against external NTP — ticket notes this to avoid chasing the wrong machine

.NOTES
    Version           : 1.1.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)

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
        ntpdriftticketid  - Text    - managed by script; do not edit manually
        ntpdriftthreshold - Integer - alert threshold in seconds (default: 30)
        ntpserver         - Text    - NTP server to query (default: pool.ntp.org)
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
$HaloServiceType  = 1
$HaloAlertType    = 21
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2
$FallbackClientId = [int](Get-NinjaConfig "halopsafallbackclientid" 0)
$FallbackSiteId   = [int](Get-NinjaConfig "halopsafallbacksiteid" 0)

# -----------------------------------------------------------------------
# CONFIG DEFAULTS
# -----------------------------------------------------------------------
$DefaultNTPServer        = "pool.ntp.org"
$DefaultThresholdSeconds = 30     # alert well before Kerberos breaks at 300s
$ResyncWaitSec           = 20     # seconds to wait after w32tm /resync before rechecking

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
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/tickets" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) {
            $created = $r.Content | ConvertFrom-Json
            Write-Host "Halo ticket created: #$($created[0].id)"
            return $created[0].id
        }
        Write-Host "WARNING: Ticket creation failed - $($r.Content)"
        return $null
    } catch {
        Write-Host "WARNING: Ticket creation failed - $($_.Exception.Message)"
        return $null
    }
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
# NTP QUERY
# -----------------------------------------------------------------------
function Get-NTPTime {
    param([string]$Server)
    try {
        $ntpData = New-Object byte[] 48
        $ntpData[0] = 0x1B   # LI=0, VN=3, Mode=3 (client)

        $socket = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Dgram,
            [System.Net.Sockets.ProtocolType]::Udp
        )
        $socket.ReceiveTimeout = 5000
        $endpoint = New-Object System.Net.IPEndPoint(
            [System.Net.Dns]::GetHostAddresses($Server)[0], 123
        )
        $socket.SendTo($ntpData, $endpoint) | Out-Null
        $socket.Receive($ntpData) | Out-Null
        $socket.Close()

        # Transmit timestamp: bytes 40-47, big-endian
        $intPart  = ([uint32]$ntpData[40] -shl 24) -bor ([uint32]$ntpData[41] -shl 16) -bor ([uint32]$ntpData[42] -shl 8) -bor [uint32]$ntpData[43]
        $fracPart = ([uint32]$ntpData[44] -shl 24) -bor ([uint32]$ntpData[45] -shl 16) -bor ([uint32]$ntpData[46] -shl 8) -bor [uint32]$ntpData[47]

        $ntpEpoch = [DateTime]::new(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        return $ntpEpoch.AddSeconds($intPart + $fracPart / [Math]::Pow(2, 32))
    } catch {
        Write-Host "WARNING: NTP query failed - $($_.Exception.Message)"
        return $null
    }
}

function Measure-NTPDrift {
    param([string]$Server)
    $ntpTime = Get-NTPTime -Server $Server
    if (-not $ntpTime) { return $null }
    $localUtc  = [DateTime]::UtcNow
    $driftSec  = [math]::Round(($localUtc - $ntpTime).TotalSeconds, 1)
    return @{
        NTPTime   = $ntpTime
        LocalUTC  = $localUtc
        DriftSec  = $driftSec
        AbsDrift  = [math]::Abs($driftSec)
        Direction = if ($driftSec -gt 0) { "fast" } else { "slow" }
    }
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== NTP Drift Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $lastTicketId = Ninja-Property-Get ntpdriftticketid  } catch { $lastTicketId = "" }
try { $thresholdRaw = Ninja-Property-Get ntpdriftthreshold } catch { $thresholdRaw = "" }
try { $ntpServerRaw = Ninja-Property-Get ntpserver         } catch { $ntpServerRaw = "" }

$thresholdSec = if ($thresholdRaw -match '^\d+$') { [int]$thresholdRaw } else { $DefaultThresholdSeconds }
$ntpServer    = if ($ntpServerRaw -and $ntpServerRaw.Trim() -ne "") { $ntpServerRaw.Trim() } else { $DefaultNTPServer }

Write-Output "NTP Server : $ntpServer"
Write-Output "Threshold  : $thresholdSec seconds"

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken  = Get-HaloToken
$clientSite = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client."
} else { "" }

Write-Output "Halo       : $($clientSite.Source)"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# GET W32TM STATUS (informational)
# -----------------------------------------------------------------------
$w32tmStatus = try {
    (& w32tm /query /status 2>$null) -join " | "
} catch { "unavailable" }

# Detect domain membership for DC warning
$isDomainJoined = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain

# -----------------------------------------------------------------------
# MEASURE DRIFT
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "Querying $ntpServer..."
$drift = Measure-NTPDrift -Server $ntpServer

if (-not $drift) {
    Write-Output "WARNING: Could not reach NTP server — skipping drift check."
    Write-Output "=== NTP Drift Monitor Complete ==="
    Write-Output "Completed : $timestamp"
    exit 0
}

Write-Output "NTP Time  : $($drift.NTPTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Output "Local UTC : $($drift.LocalUTC.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Output "Drift     : $($drift.DriftSec)s ($($drift.Direction))"

$existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }
$hasOpenTicket  = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

# -----------------------------------------------------------------------
# WITHIN THRESHOLD
# -----------------------------------------------------------------------
if ($drift.AbsDrift -le $thresholdSec) {
    Write-Output "Drift is within threshold ($thresholdSec s) — OK."
    if ($hasOpenTicket) {
        Write-Output "Closing ticket #$lastTicketId (drift resolved)."
        $resolvedNote = @"
<h4>NTP Drift — Resolved</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>NTP Server</b></td><td>$ntpServer</td></tr>
<tr><td><b>Drift</b></td><td>$($drift.DriftSec)s ($($drift.Direction)) — within threshold ($thresholdSec s)</td></tr>
</table>
<p>Time drift is now within acceptable limits. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
        try { Ninja-Property-Set ntpdriftticketid "none" } catch { Write-Output "WARNING: Could not clear ntpdriftticketid" }
    }

# -----------------------------------------------------------------------
# EXCEEDS THRESHOLD — attempt resync
# -----------------------------------------------------------------------
} else {
    Write-Output "Drift of $($drift.DriftSec)s exceeds threshold ($thresholdSec s) — attempting resync..."

    $w32timeSvc = Get-Service -Name w32time -ErrorAction SilentlyContinue
    if ($w32timeSvc -and $w32timeSvc.Status -ne "Running") {
        Write-Output "W32Time service is $($w32timeSvc.Status) — attempting to start..."
        try {
            Start-Service -Name w32time -ErrorAction Stop
            Start-Sleep -Seconds 5
            Write-Output "W32Time service started."
        } catch {
            Write-Output "WARNING: Could not start W32Time service - $($_.Exception.Message)"
        }
    }

    $resyncOutput = try { (& w32tm /resync /force 2>&1) -join " " } catch { "resync command failed" }
    Write-Output "Resync result: $resyncOutput"
    Start-Sleep -Seconds $ResyncWaitSec

    $driftAfter = Measure-NTPDrift -Server $ntpServer
    if ($driftAfter) {
        Write-Output "Post-resync drift: $($driftAfter.DriftSec)s ($($driftAfter.Direction))"
    } else {
        Write-Output "WARNING: Post-resync NTP query failed — using pre-resync drift for ticket."
        $driftAfter = $drift
    }

    # DC warning note — if domain-joined, the DC may be the root cause
    $dcWarning = if ($isDomainJoined) {
        "<p><b>Domain-joined device note:</b> If multiple devices at this client are showing drift, the domain controller is likely the root cause — it may be syncing incorrectly or not at all. Check time sync on the DC first before investigating this machine.</p>"
    } else { "" }

    # ── Resync fixed it ─────────────────────────────────────────────────
    if ($driftAfter.AbsDrift -le $thresholdSec) {
        Write-Output "Resync resolved the drift."
        if ($hasOpenTicket) {
            Write-Output "Closing ticket #$lastTicketId."
            $restartNote = @"
<h4>NTP Drift — Resolved by Resync</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>NTP Server</b></td><td>$ntpServer</td></tr>
<tr><td><b>Drift Before</b></td><td>$($drift.DriftSec)s ($($drift.Direction))</td></tr>
<tr><td><b>Drift After</b></td><td>$($driftAfter.DriftSec)s — within threshold</td></tr>
</table>
<p>w32tm /resync resolved the drift. No further action required, but investigate root cause if this recurs.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $restartNote
            Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
            try { Ninja-Property-Set ntpdriftticketid "none" } catch { Write-Output "WARNING: Could not clear ntpdriftticketid" }

        } else {
            Write-Output "Creating closed alert ticket for visibility."
            $alertBody = @"
<h3>NTP Drift Detected — Resolved by Resync</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>NTP Server</b></td><td>$ntpServer</td></tr>
<tr><td><b>Drift Detected</b></td><td>$($drift.DriftSec)s ($($drift.Direction))</td></tr>
<tr><td><b>Drift After Resync</b></td><td>$($driftAfter.DriftSec)s — within threshold ($thresholdSec s)</td></tr>
<tr><td><b>W32TM Status</b></td><td>$w32tmStatus</td></tr>
</table>
$dcWarning
<p>Time drift was detected and resolved automatically via w32tm /resync. No immediate action required. Investigate root cause if this recurs.</p>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. No billable time was spent - safe to close.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            New-HaloTicket `
                -Token      $haloToken `
                -ClientId   $clientSite.ClientId `
                -SiteId     $clientSite.SiteId `
                -Summary    "NTP ALERT | $env:COMPUTERNAME — Drift $($drift.DriftSec)s, auto-resolved" `
                -Details    $alertBody `
                -TicketType $HaloAlertType `
                -Priority   4 `
                -Status     9 `
                -Urgency    3
        }

    # ── Still drifted after resync ───────────────────────────────────────
    } else {
        Write-Output "Still drifted ($($driftAfter.DriftSec)s) after resync — escalating."

        # Priority escalates as drift approaches Kerberos limit
        $priority = if ($driftAfter.AbsDrift -gt 240) { 1 } elseif ($driftAfter.AbsDrift -gt 120) { 2 } else { 3 }

        if ($hasOpenTicket) {
            Write-Output "Open ticket #$lastTicketId found — adding re-check note."
            $recheckNote = @"
<h4>NTP Drift Re-Check — Still Drifted</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>NTP Server</b></td><td>$ntpServer</td></tr>
<tr><td><b>Drift</b></td><td>$($driftAfter.DriftSec)s ($($driftAfter.Direction)) — threshold: $thresholdSec s</td></tr>
<tr><td><b>Resync Attempted</b></td><td>Yes — $resyncOutput</td></tr>
<tr><td><b>Kerberos Limit</b></td><td>300s — $(300 - [int]$driftAfter.AbsDrift)s remaining before auth breaks</td></tr>
</table>
$dcWarning
<p>Automated resync re-ran. Drift is still outside threshold. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $recheckNote

        } else {
            Write-Output "No open ticket — creating new service ticket."
            $serviceBody = @"
<h3>NTP Drift — Manual Action Required</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>NTP Server</b></td><td>$ntpServer</td></tr>
<tr><td><b>Drift</b></td><td><b>$($driftAfter.DriftSec)s ($($driftAfter.Direction))</b> — threshold: $thresholdSec s</td></tr>
<tr><td><b>Kerberos Limit</b></td><td>300s — $(300 - [int]$driftAfter.AbsDrift)s remaining before auth breaks</td></tr>
<tr><td><b>Resync Attempted</b></td><td>Yes — $resyncOutput</td></tr>
<tr><td><b>W32TM Status</b></td><td>$w32tmStatus</td></tr>
</table>
$dcWarning
<h4>Next Steps</h4>
<ul>
<li>Check W32TM sync source: <code>w32tm /query /source</code></li>
<li>Check W32TM peers: <code>w32tm /query /peers</code></li>
<li>Force resync manually: <code>w32tm /resync /force</code></li>
<li>If domain-joined, check the domain controller time first — it is the authoritative source for all domain members.</li>
<li>On the DC: verify it is syncing to an external NTP source via <code>w32tm /query /configuration</code></li>
<li>Check for VM snapshot restores — reverting a snapshot resets the clock to snapshot time and can cause large drift.</li>
<li>If drift exceeds 300s, Kerberos authentication will fail — users will see login errors and mapped drive failures.</li>
</ul>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

            $newId = New-HaloTicket `
                -Token      $haloToken `
                -ClientId   $clientSite.ClientId `
                -SiteId     $clientSite.SiteId `
                -Summary    "NTP DRIFT | $env:COMPUTERNAME — $($driftAfter.DriftSec)s drift, resync failed" `
                -Details    $serviceBody `
                -TicketType $HaloServiceType `
                -Priority   $priority `
                -Status     1 `
                -Urgency    1

            if ($newId) {
                try { Ninja-Property-Set ntpdriftticketid "$newId" } catch { Write-Output "WARNING: Could not write ntpdriftticketid" }
            }
        }
    }
}

Write-Output ""
Write-Output "====================================================="
Write-Output "=== NTP Drift Monitor Complete ==="
Write-Output "Completed : $timestamp"
exit 0
