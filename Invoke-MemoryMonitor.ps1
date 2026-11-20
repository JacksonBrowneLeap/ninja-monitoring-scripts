#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - Memory Usage Monitor
    Scheduled via Ninja policy. Reports high memory utilisation, creates/resolves
    Halo PSA tickets. No remediation — reporting only.

.DESCRIPTION
    - Reads alert threshold from Ninja custom field 'memorythreshold' (default: 90%)
    - Reads open ticket ID from Ninja custom field 'memorymonitorticket' (managed by script)
    - Samples current memory utilisation and top processes by working set
    - State transitions:
        * Above threshold + no open ticket  → create new Type 21 alert ticket
        * Above threshold + open ticket     → add re-check note with updated process list
        * Below threshold + open ticket     → add resolved note + close ticket
        * Below threshold + no ticket       → silent OK
    - Flags any single process consuming > 20% of total RAM in the ticket body

.NOTES
    Version           : 1.0.0

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Every 15 minutes (align to Ninja memory condition interval)
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        memorythreshold        - Integer - alert threshold % (default 90 if blank; 0 = disabled)
        memorymonitorticket    - Text    - managed by script; do not edit manually
        memoryprocesscount     - Integer - top N processes to report (default 10 if blank)
        memoryexcludeprocesses - Text    - comma-separated process names to exclude from HIGH flag
                                           (e.g. "sqlservr,sqlserver,mysqld"). Still shown in table.
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
$HaloAlertType    = 21    # Alerts board
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2     # Multiple Users
$FallbackClientId = [int](Get-NinjaConfig "halopsafallbackclientid" 0)
$FallbackSiteId   = [int](Get-NinjaConfig "halopsafallbacksiteid" 0)

# -----------------------------------------------------------------------
# MONITOR CONFIG
# -----------------------------------------------------------------------
$DefaultThreshold    = 90    # % used before alerting
$DefaultProcessCount = 10    # top N processes to report
$HighProcessPct      = 20    # flag any single process consuming this % or more of total RAM

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
        [string]$Token,
        [int]$ClientId,
        [int]$SiteId,
        [string]$Summary,
        [string]$Details,
        [int]$TicketType,
        [int]$Priority = 3,
        [int]$Status   = 1,
        [int]$Urgency  = 2
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
        customfields  = @(
            @{ id = 218; value = 1 }   # CFRMMSelectionForAutomation = NinjaOne
        )
    }
    $body = "[" + ($ticket | ConvertTo-Json -Depth 5) + "]"

    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/tickets" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body `
            -ErrorAction SilentlyContinue

        if ($r.StatusCode -in 200, 201) {
            $created = $r.Content | ConvertFrom-Json
            Write-Host "Halo ticket created: #$($created[0].id) - $($created[0].summary)"
            return $created[0].id
        } else {
            Write-Host "WARNING: Halo ticket creation failed - $($r.Content)"
            return $null
        }
    } catch {
        Write-Host "WARNING: Halo ticket creation failed - $($_.Exception.Message)"
        return $null
    }
}

function Get-HaloTicketStatus {
    param([string]$Token, [string]$TicketId)
    if (-not $Token -or -not $TicketId) { return $null }
    try {
        $r = Invoke-RestMethod `
            -Uri     "$HaloBaseUrl/api/tickets/$TicketId" `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -ErrorAction Stop
        return $r.status_id
    } catch {
        Write-Host "WARNING: Could not query ticket #$TicketId - $($_.Exception.Message)"
        return $null
    }
}

function Close-HaloTicket {
    param([string]$Token, [string]$TicketId)
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping ticket close."; return }
    $body = "[" + (@{ id = [int]$TicketId; status_id = 9 } | ConvertTo-Json -Depth 3) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/tickets" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body `
            -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) {
            Write-Host "Halo ticket #$TicketId closed."
        } else {
            Write-Host "WARNING: Could not close ticket #$TicketId - $($r.Content)"
        }
    } catch {
        Write-Host "WARNING: Could not close ticket #$TicketId - $($_.Exception.Message)"
    }
}

function Add-HaloTicketNote {
    param([string]$Token, [string]$TicketId, [string]$Note)
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping note."; return }
    $action = @{
        ticket_id        = [int]$TicketId
        note             = $Note
        hiddenfromclient = $true
        outcome          = "none"
    }
    $body = "[" + ($action | ConvertTo-Json -Depth 5) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/actions" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body `
            -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) {
            Write-Host "Note added to Halo ticket #$TicketId"
        } else {
            Write-Host "WARNING: Could not add note to ticket #$TicketId - $($r.Content)"
        }
    } catch {
        Write-Host "WARNING: Could not add note to ticket #$TicketId - $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------
# MEMORY HELPERS
# -----------------------------------------------------------------------
function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "$([math]::Round($Bytes / 1GB, 2)) GB" }
    if ($Bytes -ge 1MB) { return "$([math]::Round($Bytes / 1MB, 1)) MB" }
    return "$([math]::Round($Bytes / 1KB, 0)) KB"
}

function Get-TopProcesses {
    param([int]$Count, [long]$TotalRamBytes)
    Get-Process -ErrorAction SilentlyContinue |
        Sort-Object WorkingSet64 -Descending |
        Select-Object -First $Count |
        ForEach-Object {
            $pct = if ($TotalRamBytes -gt 0) { [math]::Round(($_.WorkingSet64 / $TotalRamBytes) * 100, 1) } else { 0 }
            [PSCustomObject]@{
                Name        = $_.ProcessName
                PID         = $_.Id
                WorkingSet  = $_.WorkingSet64
                DisplaySize = Format-Bytes $_.WorkingSet64
                PctOfRam    = $pct
            }
        }
}

function Build-ProcessTableHtml {
    param($Processes, [long]$TotalRamBytes, [string[]]$ExcludedNames)
    $rows = $Processes | ForEach-Object {
        $isExcluded = $_.Name.ToLower() -in $ExcludedNames
        $flag = if ($isExcluded) {
            " <span style='color:#888'>(excluded)</span>"
        } elseif ($_.PctOfRam -ge $HighProcessPct) {
            " <b style='color:#c00'>&uarr; HIGH</b>"
        } else { "" }
        "<tr><td>$($_.Name)</td><td>$($_.PID)</td><td>$($_.DisplaySize)</td><td>$($_.PctOfRam)%$flag</td></tr>"
    }
    return @"
<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>
<tr><th>Process</th><th>PID</th><th>Working Set</th><th>% of Total RAM</th></tr>
$($rows -join "`n")
</table>
"@
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== Memory Usage Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $thresholdRaw    = Ninja-Property-Get memorythreshold        } catch { $thresholdRaw = "" }
try { $openTicketRaw   = Ninja-Property-Get memorymonitorticket   } catch { $openTicketRaw = "" }
try { $processCountRaw = Ninja-Property-Get memoryprocesscount     } catch { $processCountRaw = "" }
try { $excludeRaw      = Ninja-Property-Get memoryexcludeprocesses } catch { $excludeRaw = "" }

$threshold = $DefaultThreshold
if ($thresholdRaw -match '^\d+$') {
    $val = [int]$thresholdRaw
    if ($val -ge 0 -and $val -le 100) { $threshold = $val }
}

if ($threshold -eq 0) {
    Write-Output "Threshold set to 0 — monitoring disabled on this device. Exiting."
    exit 0
}

$processCount = $DefaultProcessCount
if ($processCountRaw -match '^\d+$') {
    $val = [int]$processCountRaw
    if ($val -gt 0 -and $val -le 50) { $processCount = $val }
}

$openTicketId = if ($openTicketRaw) { $openTicketRaw.Trim() } else { "" }
if ($openTicketId -eq "none" -or $openTicketId -notmatch '^\d+$') { $openTicketId = "" }

$excludedProcesses = @(
    $excludeRaw -split "," |
    ForEach-Object { $_.Trim().ToLower() } |
    Where-Object { $_ -ne "" }
)

Write-Output "Threshold     : $threshold%"
Write-Output "Process count : $processCount"
Write-Output "Excluded procs: $(if ($excludedProcesses.Count -gt 0) { $excludedProcesses -join ', ' } else { "none" })"
Write-Output "Open ticket   : $(if ($openTicketId) { "#$openTicketId" } else { "none" })"
Write-Output ""

# -----------------------------------------------------------------------
# SAMPLE MEMORY
# -----------------------------------------------------------------------
$totalKB    = $osInfo.TotalVisibleMemorySize    # Win32_OS gives KB
$freeKB     = $osInfo.FreePhysicalMemory
$usedKB     = $totalKB - $freeKB
$totalBytes = $totalKB * 1KB
$usedPct    = if ($totalKB -gt 0) { [math]::Round(($usedKB / $totalKB) * 100, 1) } else { 0 }

$totalDisplay = Format-Bytes ($totalKB * 1KB)
$usedDisplay  = Format-Bytes ($usedKB  * 1KB)
$freeDisplay  = Format-Bytes ($freeKB  * 1KB)

$lowRamWarning = if ($totalKB -lt (8 * 1MB)) {
    " <b style='color:#c00'>(Low RAM device — $totalDisplay total)</b>"
} else { "" }

Write-Output "Total RAM : $totalDisplay"
Write-Output "Used      : $usedDisplay ($usedPct%)"
Write-Output "Free      : $freeDisplay"
Write-Output ""

$processes = Get-TopProcesses -Count $processCount -TotalRamBytes $totalBytes

Write-Output "Top $processCount processes by working set:"
$processes | ForEach-Object {
    Write-Output ("  {0,-30} PID {1,-6} {2,10}   ({3}%)" -f $_.Name, $_.PID, $_.DisplaySize, $_.PctOfRam)
}
Write-Output ""

$isAboveThreshold = $usedPct -ge $threshold

Write-Output "Status        : $usedPct% used — $(if ($isAboveThreshold) { "ABOVE threshold ($threshold%)" } else { "OK (below threshold of $threshold%)" })"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken  = Get-HaloToken
$clientSite = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client. Verify correct client before actioning."
} else { "" }

Write-Output "Halo          : $($clientSite.Source)"
Write-Output ""

# -----------------------------------------------------------------------
# CHECK EXISTING TICKET STATE
# -----------------------------------------------------------------------
$existingStatus = if ($openTicketId) { Get-HaloTicketStatus -Token $haloToken -TicketId $openTicketId } else { $null }
$hasOpenTicket  = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

if ($openTicketId -and -not $hasOpenTicket) {
    Write-Output "Stored ticket #$openTicketId is already closed — clearing."
    $openTicketId = ""
}

# -----------------------------------------------------------------------
# BUILD SHARED HTML FRAGMENTS
# -----------------------------------------------------------------------
$processTableHtml = Build-ProcessTableHtml -Processes $processes -TotalRamBytes $totalBytes -ExcludedNames $excludedProcesses

$highProcesses = $processes | Where-Object { $_.PctOfRam -ge $HighProcessPct -and $_.Name.ToLower() -notin $excludedProcesses }
$highProcessNote = if ($highProcesses) {
    $names = ($highProcesses | ForEach-Object { "$($_.Name) ($($_.PctOfRam)%)" }) -join ", "
    "<p><b>Notable:</b> The following process(es) each account for $HighProcessPct% or more of total RAM: <b>$names</b>. Investigate whether this is expected behaviour.</p>"
} else { "" }

$memorySummaryHtml = @"
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Total RAM</b></td><td>$totalDisplay$lowRamWarning</td></tr>
<tr><td><b>Used</b></td><td>$usedDisplay ($usedPct%)</td></tr>
<tr><td><b>Free</b></td><td>$freeDisplay</td></tr>
<tr><td><b>Threshold</b></td><td>$threshold%</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
"@

# -----------------------------------------------------------------------
# STATE MACHINE
# -----------------------------------------------------------------------

# ── CASE 1: Above threshold ─────────────────────────────────────────────
if ($isAboveThreshold) {

    if ($hasOpenTicket) {
        Write-Output "Memory above threshold — open ticket #$openTicketId exists. Adding re-check note."

        $recheckNote = (@"
<h4>Memory Monitor Re-Check — Still High</h4>
$memorySummaryHtml
$highProcessNote
<h4>Top $processCount Processes (current)</h4>
$processTableHtml
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@) -replace ">[ \t\r\n]+<", "><"

        Add-HaloTicketNote -Token $haloToken -TicketId $openTicketId -Note $recheckNote

    } else {
        Write-Output "Memory above threshold — no open ticket. Creating alert ticket."

        $priority = if ($usedPct -ge 95) { 2 } else { 3 }   # High if >=95%, Medium otherwise
        $urgency  = if ($usedPct -ge 95) { 1 } else { 2 }

        $ticketBody = (@"
<h3>High Memory Utilisation Detected</h3>
$memorySummaryHtml
$highProcessNote
<h4>Top $processCount Processes</h4>
$processTableHtml
<h4>Next Steps</h4>
<ul>
<li>Review the process list above. Identify any unexpected high-memory processes.</li>
<li>Check if the high usage is sustained or transient (script re-checks every 15 minutes).</li>
<li>If a specific process is abnormally high, check its logs or consider a service restart if safe.</li>
<li>Consider whether the device has sufficient RAM for its workload — an upgrade may be warranted if this is a recurring issue.</li>
<li>Use Task Manager or <code>Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20</code> for a live snapshot.</li>
</ul>
<hr><p><i>This ticket was created automatically by a NinjaRMM automation. No billable time was spent.</i></p>
"@) -replace ">[ \t\r\n]+<", "><"

        $newTicketId = New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -Summary    "MEMORY ALERT | $env:COMPUTERNAME | $usedPct% used (threshold $threshold%)" `
            -Details    $ticketBody `
            -TicketType $HaloAlertType `
            -Priority   $priority `
            -Status     1 `
            -Urgency    $urgency

        if ($newTicketId) { $openTicketId = "$newTicketId" }
    }
}

# ── CASE 2: Below threshold ─────────────────────────────────────────────
else {

    if ($hasOpenTicket) {
        Write-Output "Memory below threshold — resolving open ticket #$openTicketId."

        $resolvedNote = (@"
<h4>Memory Monitor — Utilisation Normalised</h4>
$memorySummaryHtml
<p>Memory utilisation has dropped below the $threshold% threshold. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@) -replace ">[ \t\r\n]+<", "><"

        Add-HaloTicketNote -Token $haloToken -TicketId $openTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $openTicketId
        $openTicketId = ""

    } else {
        Write-Output "Memory within normal range — no action required."
    }
}

# -----------------------------------------------------------------------
# WRITE TICKET ID BACK TO NINJA
# -----------------------------------------------------------------------
$saveValue = if ($openTicketId) { $openTicketId } else { "none" }
try {
    Ninja-Property-Set memorymonitorticket $saveValue
    Write-Output ""
    Write-Output "Ticket field saved: $saveValue"
} catch {
    Write-Output "WARNING: Could not write memorymonitorticket field — ticket state not persisted"
}

Write-Output ""
Write-Output "====================================================="
Write-Output "=== Memory Usage Monitor Complete ==="
Write-Output "Completed : $timestamp"
exit 0
