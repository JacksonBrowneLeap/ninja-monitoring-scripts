#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - Print Queue Monitor
    Detects stuck print jobs, clears the queue, restarts the Spooler, and
    creates/resolves Halo PSA tickets based on outcome.

.DESCRIPTION
    - Checks all print queues for jobs older than the stuck threshold
    - If stuck jobs found: stops Spooler, clears spool files, restarts Spooler
    - Spooler restart resolves: closed Type 21 alert (FYI)
    - Spooler won't restart: open Type 1 service ticket
    - No stuck jobs: silent OK, resolves any open ticket

.NOTES
    Version           : 1.1.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Every 30 minutes
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        monitorhealth           - Text    - Device - Managed by the script: one OK/FAIL line per monitor. Alert on "|FAIL|" (multi-line text)
        printqueueticketid  - Text    - managed by script; do not edit manually
        printqueuethreshold - Integer - minutes before a job is considered stuck (default: 15)
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------------------------------------
# HALO CONFIG
# -----------------------------------------------------------------------
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
$MonitorName = 'PrintQueue'
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
$HaloServiceType  = 1
$HaloAlertType    = 21
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2

# -----------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------
$DefaultStuckThresholdMin = 15
$SpoolPath                = "$env:windir\System32\spool\PRINTERS"
$SpoolerStopTimeoutSec    = 30

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== Print Queue Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $lastTicketId    = Ninja-Property-Get printqueueticketid  } catch { $lastTicketId = "" }
try { $thresholdRaw    = Ninja-Property-Get printqueuethreshold } catch { $thresholdRaw = "" }

$stuckThresholdMin = if ($thresholdRaw -match '^\d+$') { [int]$thresholdRaw } else { $DefaultStuckThresholdMin }

Write-Output "Stuck threshold : $stuckThresholdMin minutes"

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken  = Get-HaloToken
$clientSite = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client."
} else { "" }

Write-Output "Halo            : $($clientSite.Source)"
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# CHECK FOR STUCK JOBS
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "Checking print queues..."

$allJobs = Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue

$stuckJobs = @()
if ($allJobs) {
    $stuckJobs = @($allJobs | Where-Object {
        try {
            $submitted = [Management.ManagementDateTimeConverter]::ToDateTime($_.TimeSubmitted)
            ((Get-Date) - $submitted).TotalMinutes -gt $stuckThresholdMin
        } catch { $false }
    })
}

Write-Output "Total jobs in queue : $($allJobs.Count)"
Write-Output "Stuck (>$stuckThresholdMin min)  : $($stuckJobs.Count)"

$existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }
$hasOpenTicket  = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

# -----------------------------------------------------------------------
# NO STUCK JOBS
# -----------------------------------------------------------------------
if ($stuckJobs.Count -eq 0) {
    Write-Output "No stuck jobs — queue healthy."
    if ($hasOpenTicket) {
        Write-Output "Closing ticket #$lastTicketId (queue cleared)."
        $resolvedNote = @"
<h4>Print Queue — Healthy</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Jobs in Queue</b></td><td>$($allJobs.Count)</td></tr>
</table>
<p>No stuck print jobs detected. Queue is healthy. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
        try { Ninja-Property-Set printqueueticketid "none" } catch { Write-Output "WARNING: Could not clear printqueueticketid" }
    }
    Write-Output ""
    Write-Output "=== Print Queue Monitor Complete ==="
    Write-Output "Completed : $timestamp"
    Complete-Monitor
}

# -----------------------------------------------------------------------
# STUCK JOBS FOUND — build job summary for ticket
# -----------------------------------------------------------------------
$jobRows = ($stuckJobs | ForEach-Object {
    $submitted = try { [Management.ManagementDateTimeConverter]::ToDateTime($_.TimeSubmitted) } catch { $null }
    $ageMin    = if ($submitted) { [math]::Round(((Get-Date) - $submitted).TotalMinutes, 0) } else { "?" }
    "<tr><td>$($_.Document)</td><td>$($_.Name -replace ',.*','')</td><td>$($_.JobStatus)</td><td>$ageMin min</td></tr>"
}) -join ""

Write-Output ""
$stuckJobs | ForEach-Object {
    $submitted = try { [Management.ManagementDateTimeConverter]::ToDateTime($_.TimeSubmitted) } catch { $null }
    $ageMin    = if ($submitted) { [math]::Round(((Get-Date) - $submitted).TotalMinutes, 0) } else { "?" }
    Write-Output "  Stuck: $($_.Document) on $($_.Name -replace ',.*','') — $($_.JobStatus) for $ageMin min"
}

# -----------------------------------------------------------------------
# CLEAR THE QUEUE
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "Clearing print queue..."

# Stop Spooler
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    try {
        Stop-Service -Name Spooler -Force -ErrorAction Stop
        $waited = 0
        while ((Get-Service -Name Spooler).Status -ne "Stopped" -and $waited -lt $SpoolerStopTimeoutSec) {
            Start-Sleep -Seconds 2
            $waited += 2
        }
        Write-Output "Spooler stopped."
    } catch {
        Write-Output "WARNING: Could not stop Spooler - $($_.Exception.Message)"
    }
}

# Delete spool files
$spoolFiles = Get-ChildItem -Path $SpoolPath -ErrorAction SilentlyContinue
$fileCount  = $spoolFiles.Count
if ($fileCount -gt 0) {
    $spoolFiles | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Output "Deleted $fileCount spool file(s) from $SpoolPath"
} else {
    Write-Output "No spool files found in $SpoolPath"
}

# Restart Spooler
$restartError = $null
try {
    Start-Service -Name Spooler -ErrorAction Stop
    Start-Sleep -Seconds 5
    Write-Output "Spooler restarted."
} catch {
    $restartError = $_.Exception.Message
    Write-Output "WARNING: Could not restart Spooler - $restartError"
}

$spoolerStatus = (Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status

# -----------------------------------------------------------------------
# OUTCOME: RESOLVED
# -----------------------------------------------------------------------
if ($spoolerStatus -eq "Running") {
    Write-Output "Queue cleared and Spooler running."

    if ($hasOpenTicket) {
        Write-Output "Closing ticket #$lastTicketId."
        $resolvedNote = @"
<h4>Print Queue — Cleared Successfully</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Jobs Cleared</b></td><td>$($stuckJobs.Count) stuck job(s)</td></tr>
<tr><td><b>Spool Files Deleted</b></td><td>$fileCount</td></tr>
<tr><td><b>Spooler Status</b></td><td>Running</td></tr>
</table>
<p>Print queue cleared and Spooler restarted successfully. Users can print again. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
        try { Ninja-Property-Set printqueueticketid "none" } catch { Write-Output "WARNING: Could not clear printqueueticketid" }

    } else {
        Write-Output "Creating closed alert ticket for visibility."
        $alertBody = @"
<h3>Print Queue Stuck — Cleared Automatically</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Stuck Jobs Found</b></td><td>$($stuckJobs.Count) (older than $stuckThresholdMin minutes)</td></tr>
<tr><td><b>Spool Files Deleted</b></td><td>$fileCount</td></tr>
<tr><td><b>Spooler Status</b></td><td>Running</td></tr>
</table>
<h4>Stuck Jobs</h4>
<table>
<tr><th>Document</th><th>Printer</th><th>Status</th><th>Age</th></tr>
$jobRows
</table>
<p>The print queue was cleared and the Spooler restarted automatically. Users should be able to print again. No immediate action required, but investigate the root cause if this recurs frequently on this device.</p>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. No billable time was spent - safe to close.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -AssetId    $clientSite.AssetId `
            -Summary    "PRINT QUEUE | $env:COMPUTERNAME — $($stuckJobs.Count) stuck job(s) cleared automatically" `
            -Details    $alertBody `
            -TicketType $HaloAlertType `
            -Priority   4 `
            -Status     9 `
            -Urgency    3
    }

# -----------------------------------------------------------------------
# OUTCOME: SPOOLER WON'T START
# -----------------------------------------------------------------------
} else {
    Write-Output "Spooler failed to restart — escalating."

    if ($hasOpenTicket) {
        Write-Output "Open ticket #$lastTicketId found — adding re-check note."
        $recheckNote = @"
<h4>Print Queue Re-Check — Spooler Still Not Running</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Spooler Status</b></td><td>$spoolerStatus</td></tr>
<tr><td><b>Restart Error</b></td><td>$restartError</td></tr>
</table>
<p>Queue clear re-ran. Spooler is still not running. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $recheckNote

    } else {
        Write-Output "No open ticket — creating new service ticket."
        $serviceBody = @"
<h3>Print Spooler Down — Manual Action Required</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Stuck Jobs Found</b></td><td>$($stuckJobs.Count)</td></tr>
<tr><td><b>Spool Files Deleted</b></td><td>$fileCount</td></tr>
<tr><td><b>Spooler Status</b></td><td>$spoolerStatus</td></tr>
<tr><td><b>Restart Error</b></td><td>$restartError</td></tr>
</table>
<h4>Stuck Jobs (at time of detection)</h4>
<table>
<tr><th>Document</th><th>Printer</th><th>Status</th><th>Age</th></tr>
$jobRows
</table>
<h4>Next Steps</h4>
<ul>
<li>Check Windows Event Log (System) for Spooler errors around the time of failure.</li>
<li>Attempt manual restart: <code>Start-Service Spooler</code></li>
<li>Check for corrupt or incompatible printer drivers — a bad driver DLL is the most common cause of Spooler crashes.</li>
<li>List installed printer drivers: <code>Get-PrinterDriver</code></li>
<li>Remove suspect driver: <code>Remove-PrinterDriver -Name "DriverName"</code></li>
<li>If Spooler crashes immediately on start, run: <code>sfc /scannow</code> to check for system file corruption.</li>
</ul>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

        $newId = New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -AssetId    $clientSite.AssetId `
            -Summary    "PRINT SPOOLER DOWN | $env:COMPUTERNAME — Queue cleared but Spooler will not restart" `
            -Details    $serviceBody `
            -TicketType $HaloServiceType `
            -Priority   2 `
            -Status     1 `
            -Urgency    1

        if ($newId) {
            try { Ninja-Property-Set printqueueticketid "$newId" } catch { Write-Output "WARNING: Could not write printqueueticketid" }
        }
    }
}

Write-Output ""
Write-Output "====================================================="
Write-Output "=== Print Queue Monitor Complete ==="
Write-Output "Completed : $timestamp"
Complete-Monitor
