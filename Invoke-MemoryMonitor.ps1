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
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        monitorhealth           - Text    - Device - Managed by the script: one OK/FAIL line per monitor. Alert on "|FAIL|" (multi-line text)
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
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
$MonitorName = 'Memory'
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
$HaloAlertType    = 21    # Alerts board
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2     # Multiple Users

# -----------------------------------------------------------------------
# MONITOR CONFIG
# -----------------------------------------------------------------------
$DefaultThreshold    = 90    # % used before alerting
$DefaultProcessCount = 10    # top N processes to report
$HighProcessPct      = 20    # flag any single process consuming this % or more of total RAM

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
    Complete-Monitor
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
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
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
            -AssetId    $clientSite.AssetId `
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
Complete-Monitor
