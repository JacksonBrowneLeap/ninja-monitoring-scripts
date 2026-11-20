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
        printqueueticketid  - Text    - managed by script; do not edit manually
        printqueuethreshold - Integer - minutes before a job is considered stuck (default: 15)
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
# CONFIG
# -----------------------------------------------------------------------
$DefaultStuckThresholdMin = 15
$SpoolPath                = "$env:windir\System32\spool\PRINTERS"
$SpoolerStopTimeoutSec    = 30

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
    exit 0
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
exit 0
