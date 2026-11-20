#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - Event Log Error Monitor
    Scheduled hourly. Queries System, Application, and Security event logs for
    known critical events and creates/resolves Halo PSA tickets based on findings.

.DESCRIPTION
    Watches for known-critical Windows events in the lookback window (default: 1h):
      - Unexpected shutdowns / reboots        (System Event 41, 6008)
      - BSOD / system crashes                 (System Event 1001 BugCheck)
      - Disk hardware errors                  (System Event 7, 11, 157)
      - NTFS filesystem corruption            (System Event 55)
      - VSS / Shadow Copy failures            (Application Event 8193)
      - NetBIOS name conflicts                (System Event 4319, 4320 / NetBT)
      - IP address conflicts                  (System Event 4199 / Tcpip)
      - TCP connection attempt limit          (System Event 4226 / Tcpip)
      - Audit log cleared                     (Security Event 1102)

    Open ticket → add re-check note on subsequent runs; auto-close on clean run.
    No ticket    → create service/alert ticket if events found; silent if clean.
.NOTES
    Version           : 1.2.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)
        1.2.0 - Changed default lookback to 1h for hourly schedule; added NetBT
                4319/4320, Tcpip 4199/4226, Security 1102 (audit log cleared)

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Hourly
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        eventlogticketid      - Text     - managed by script; do not edit manually
        eventloglookbackhours - Integer  - lookback window in hours (default: 1)
        eventlogexcluded      - Checkbox - tick to exclude this device from monitoring
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------------------------------------
# HALO CONFIG
# -----------------------------------------------------------------------
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
if (-not $HaloLibUrl) { $HaloLibUrl = "https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/lib/HaloCommon.ps1" }
try { Invoke-Expression (Invoke-RestMethod -Uri $HaloLibUrl -UseBasicParsing -ErrorAction Stop) }
catch { Write-Output "ERROR: could not load shared library from $HaloLibUrl - $($_.Exception.Message)"; exit 1 }
$HaloServiceType  = 1
$HaloAlertType    = 21
$HaloCategoryId   = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId     = 2

# -----------------------------------------------------------------------
# EVENT CONFIG
# -----------------------------------------------------------------------
$DefaultLookbackHours = 1

# Source = $null matches any provider (used when the event ID is unique enough).
# Priority: 1=Critical, 2=High, 3=Medium
# TicketType: $HaloServiceType = Service/Incident board, $HaloAlertType = Alerts board
$WatchedEvents = @(
    # ── Unexpected shutdowns ─────────────────────────────────────────────────────
    @{ Log="System";   Id=41;   Source="Microsoft-Windows-Kernel-Power"; Label="Unexpected Shutdown/Reboot";     Priority=2; TicketType=$HaloServiceType }
    @{ Log="System";   Id=6008; Source=$null;                            Label="Unexpected Shutdown/Reboot";     Priority=2; TicketType=$HaloServiceType }
    # ── BSOD ─────────────────────────────────────────────────────────────────────
    @{ Log="System";   Id=1001; Source="BugCheck";                       Label="BSOD / System Crash";            Priority=1; TicketType=$HaloServiceType }
    # ── Disk hardware ────────────────────────────────────────────────────────────
    @{ Log="System";   Id=7;    Source="disk";                           Label="Disk Controller Error";          Priority=2; TicketType=$HaloServiceType }
    @{ Log="System";   Id=11;   Source="disk";                           Label="Disk Read/Write Error";          Priority=2; TicketType=$HaloServiceType }
    @{ Log="System";   Id=55;   Source="Ntfs";                           Label="NTFS Filesystem Corruption";     Priority=1; TicketType=$HaloServiceType }
    @{ Log="System";   Id=157;  Source=$null;                            Label="Disk Surprise Removal/Offline";  Priority=1; TicketType=$HaloServiceType }
    # ── Backup health ────────────────────────────────────────────────────────────
    @{ Log="Application"; Id=8193; Source="VSS";                         Label="VSS / Shadow Copy Failure";      Priority=3; TicketType=$HaloAlertType   }
    # ── Network ──────────────────────────────────────────────────────────────────
    @{ Log="System";   Id=4319; Source="NetBT";                          Label="NetBIOS Name Conflict";          Priority=2; TicketType=$HaloAlertType   }
    @{ Log="System";   Id=4320; Source="NetBT";                          Label="NetBIOS Name Conflict";          Priority=2; TicketType=$HaloAlertType   }
    @{ Log="System";   Id=4199; Source="Tcpip";                          Label="IP Address Conflict";            Priority=2; TicketType=$HaloAlertType   }
    @{ Log="System";   Id=4226; Source="Tcpip";                          Label="TCP Connection Attempt Limit";   Priority=3; TicketType=$HaloAlertType   }
    # ── Security ─────────────────────────────────────────────────────────────────
    @{ Log="Security"; Id=1102; Source="Microsoft-Windows-Eventlog";     Label="Audit Log Cleared";              Priority=1; TicketType=$HaloServiceType }
)

# -----------------------------------------------------------------------
# EVENT QUERY
# -----------------------------------------------------------------------
function Get-WatchedEventFindings {
    param([int]$LookbackHours)

    $cutoff   = (Get-Date).AddHours(-$LookbackHours)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $byLog    = $WatchedEvents | Group-Object { $_.Log }

    foreach ($logGroup in $byLog) {
        $logName   = $logGroup.Name
        $ids       = @($logGroup.Group | ForEach-Object { $_.Id } | Where-Object { $null -ne $_ } | Select-Object -Unique)
        $rawEvents = $null

        if ($ids.Count -eq 0) {
            Write-Host "WARNING: No valid event IDs resolved for log '$logName' — check WatchedEvents definitions."
            continue
        }

        try {
            $rawEvents = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Id        = $ids
                StartTime = $cutoff
            } -ErrorAction SilentlyContinue
        } catch {
            Write-Host "WARNING: Could not query $logName event log (IDs: $($ids -join ',')) — $($_.Exception.Message)"
            continue
        }

        if (-not $rawEvents) { continue }

        foreach ($entry in $logGroup.Group) {
            $matched = @($rawEvents | Where-Object {
                $_.Id -eq $entry.Id -and
                ($null -eq $entry.Source -or $_.ProviderName -eq $entry.Source)
            })
            if ($matched.Count -eq 0) { continue }

            $latest  = $matched | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msgRaw  = ($latest.Message -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 3) -join " "
            $msgRaw  = [regex]::Replace($msgRaw, '[​-‏‪-‮﻿]', '')
            $message = if ($msgRaw.Length -gt 350) { $msgRaw.Substring(0, 350) + "..." } else { $msgRaw }

            $findings.Add([PSCustomObject]@{
                Log        = $logName
                Id         = $entry.Id
                Source     = $entry.Source
                Label      = $entry.Label
                Count      = $matched.Count
                LastSeen   = $latest.TimeCreated
                Message    = $message
                Priority   = $entry.Priority
                TicketType = $entry.TicketType
            })
        }
    }

    # Merge findings that share the same Label into one row (e.g. Event 41 + 6008 → single Unexpected Shutdown entry)
    $mergedFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $labelGroups    = $findings | Group-Object { $_.Label }
    foreach ($g in $labelGroups) {
        $items = @($g.Group)
        if ($items.Count -eq 1) {
            $mergedFindings.Add($items[0])
        } else {
            $totalCount  = 0;                  foreach ($item in $items) { $totalCount  += $item.Count }
            $minPriority = $items[0].Priority; foreach ($item in $items) { if ($item.Priority -lt $minPriority) { $minPriority = $item.Priority } }
            $latest      = ($items | Where-Object { $_.LastSeen } | Sort-Object LastSeen -Descending | Select-Object -First 1)
            if (-not $latest) { $latest = $items[0] }
            $mergedFindings.Add([PSCustomObject]@{
                Log        = $items[0].Log
                Id         = ($items | ForEach-Object { "$($_.Id)" } | Sort-Object -Unique) -join '/'
                Source     = $null
                Label      = $items[0].Label
                Count      = $totalCount
                LastSeen   = $latest.LastSeen
                Message    = $items[0].Message
                Priority   = $minPriority
                TicketType = $items[0].TicketType
            })
        }
    }
    return $mergedFindings
}

function Build-FindingsHtmlTable {
    param([object[]]$Findings)

    $rows = ($Findings | ForEach-Object {
        $f = $_
        $countCell = if ($f.Count -gt 1) { "<b>$($f.Count)x</b>" } else { "1x" }
        $badge = switch ($f.Priority) {
            1 { "<b style='color:darkred'>CRITICAL</b>" }
            2 { "<b style='color:darkorange'>HIGH</b>" }
            3 { "<span style='color:goldenrod'>MEDIUM</span>" }
        }
        $lastSeenStr = if ($f.LastSeen) { $f.LastSeen.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
        "<tr><td>$($f.Label)</td><td>Event $($f.Id) / $($f.Log)</td><td>$badge</td><td>$countCell</td><td>$lastSeenStr</td><td><small>$($f.Message)</small></td></tr>"
    }) -join ""

    return "<table><tr><th>Event Type</th><th>ID / Log</th><th>Severity</th><th>Count</th><th>Last Seen</th><th>Message Preview</th></tr>$rows</table>"
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== Event Log Error Monitor ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# READ NINJA FIELDS
# -----------------------------------------------------------------------
try { $lastTicketId = Ninja-Property-Get eventlogticketid       } catch { $lastTicketId = "" }
try { $lookbackRaw  = Ninja-Property-Get eventloglookbackhours  } catch { $lookbackRaw  = "" }
try { $excludedRaw  = Ninja-Property-Get eventlogexcluded       } catch { $excludedRaw  = "" }

$lookbackHours = if ($lookbackRaw -match '^\d+$' -and [int]$lookbackRaw -gt 0) { [int]$lookbackRaw } else { $DefaultLookbackHours }

Write-Output "Lookback  : $lookbackHours hours"

if ($excludedRaw -eq "1") {
    Write-Output "eventlogexcluded is set — skipping event log monitoring on this device."
    exit 0
}

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken  = Get-HaloToken
$clientSite = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to Halo asset, defaulting to the fallback client. Verify correct client before actioning."
} else { "" }

Write-Output "Halo      : $($clientSite.Source)"
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# QUERY EVENTS
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "Querying event logs (last $lookbackHours hours)..."

$findings = @(Get-WatchedEventFindings -LookbackHours $lookbackHours)

if ($findings.Count -gt 0) {
    Write-Output "Found $($findings.Count) event type(s) with occurrences:"
    foreach ($f in $findings) {
        $lastSeenStr = if ($f.LastSeen) { $f.LastSeen.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
        Write-Output "  [$($f.Label)] $($f.Count)x — last at $lastSeenStr"
    }
} else {
    Write-Output "No watched events found in the last $lookbackHours hours."
}

# -----------------------------------------------------------------------
# TICKET STATE
# -----------------------------------------------------------------------
$existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }
$hasOpenTicket  = ($null -ne $existingStatus -and $existingStatus -notin @(9, 20))

# -----------------------------------------------------------------------
# CASE 1: CLEAN RUN — NO EVENTS
# -----------------------------------------------------------------------
if ($findings.Count -eq 0) {

    if ($hasOpenTicket) {
        Write-Output "No events found — resolving open ticket #$lastTicketId."
        $resolvedNote = @"
<h4>Event Log Monitor — Clean Run</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Lookback Window</b></td><td>$lookbackHours hours</td></tr>
</table>
<p>No watched critical events were found in the lookback window. Condition appears resolved. No further automated action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
        Close-HaloTicket   -Token $haloToken -TicketId $lastTicketId
        try { Ninja-Property-Set eventlogticketid "none" } catch { Write-Output "WARNING: Could not clear eventlogticketid" }

    } else {
        Write-Output "No events found — no action required."
    }

# -----------------------------------------------------------------------
# CASE 2+: EVENTS FOUND
# -----------------------------------------------------------------------
} else {

    # Determine overall priority — take the most severe finding
    $overallPriority = ($findings | Measure-Object -Property Priority -Minimum).Minimum

    # Escalate to P1 if unexpected shutdowns recurred 3+ times in the window
    $shutdownEntry  = $findings | Where-Object { $_.Label -eq "Unexpected Shutdown/Reboot" }
    $shutdownCount  = 0; if ($shutdownEntry) { foreach ($se in @($shutdownEntry)) { $shutdownCount += $se.Count } }
    if ($shutdownCount -ge 3) { $overallPriority = 1 }

    $urgency        = switch ($overallPriority) { 1 { 1 } 2 { 2 } default { 3 } }
    $summaryTag     = switch ($overallPriority) { 1 { "CRITICAL" } 2 { "WARNING" } default { "ALERT" } }
    $ticketType     = if ($findings | Where-Object { $_.TicketType -eq $HaloServiceType }) { $HaloServiceType } else { $HaloAlertType }
    $ticketTypeName = if ($ticketType -eq $HaloServiceType) { "service" } else { "alert" }
    $topLabel       = ($findings | Sort-Object Priority | Select-Object -First 1).Label
    $totalCount     = ($findings | Measure-Object -Property Count -Sum).Sum
    $findingsTable  = Build-FindingsHtmlTable -Findings $findings

    # ── CASE 2: Open ticket exists — add re-check note ───────────────────
    if ($hasOpenTicket) {
        Write-Output "Events found and open ticket #$lastTicketId exists — adding re-check note."
        $recheckNote = @"
<h4>Event Log Re-Check — Issues Still Present</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Lookback Window</b></td><td>$lookbackHours hours</td></tr>
<tr><td><b>Event Types Found</b></td><td>$($findings.Count)</td></tr>
<tr><td><b>Total Occurrences</b></td><td>$totalCount</td></tr>
</table>
$findingsTable
<p>Automated re-check ran. Watched events are still being detected within the lookback window. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
        Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $recheckNote

    # ── CASE 3: No open ticket — create new ticket ───────────────────────
    } else {
        Write-Output "Events found — creating new $ticketTypeName ticket."

        # Check for graceful shutdowns (Event 1074) for technician context — not an alert on its own
        $gracefulEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Id        = 1074
            StartTime = (Get-Date).AddHours(-$lookbackHours)
        } -ErrorAction SilentlyContinue
        $gracefulNote = if ($gracefulEvents) {
            $gracefulCount = @($gracefulEvents).Count
            "<p><b>Note:</b> $gracefulCount graceful/planned shutdown(s) were also logged in this window (Event 1074). These are expected restarts and are listed for context only.</p>"
        } else { "" }

        # Build applicable next steps sections
        $hasShutdownEvents = ($findings | Where-Object { $_.Label -in @("Unexpected Shutdown/Reboot", "BSOD / System Crash") }).Count -gt 0
        $hasDiskEvents     = ($findings | Where-Object { $_.Label -in @("Disk Controller Error", "Disk Read/Write Error", "NTFS Filesystem Corruption", "Disk Surprise Removal/Offline") }).Count -gt 0
        $hasVSSEvents      = ($findings | Where-Object { $_.Label -eq "VSS / Shadow Copy Failure" }).Count -gt 0
        $hasNetworkEvents  = ($findings | Where-Object { $_.Label -in @("NetBIOS Name Conflict", "IP Address Conflict", "TCP Connection Attempt Limit") }).Count -gt 0
        $hasSecurityEvents = ($findings | Where-Object { $_.Label -eq "Audit Log Cleared" }).Count -gt 0

        $shutdownBullets = if ($hasShutdownEvents) { @"
<li>Review System event log around the time of each event — look for Kernel-Power (Event 41), BugCheck (1001), or driver errors in the same window.</li>
<li>Check <code>C:\Windows\Minidump</code> for BSOD dump files. Analyse with WinDbg or upload to <a href="https://www.osronline.com/page.cfm?name=analyze">OSR Online</a>.</li>
<li>On physical servers: verify UPS health and check for power events or hardware logs (ILO/iDRAC/BMC).</li>
<li>On VMs: check the hypervisor host event log for unexpected VM power-off events.</li>
<li>If recurring: investigate RAM stability (MemTest86), overheating, or recently updated drivers/firmware.</li>
"@ } else { "" }

        $diskBullets = if ($hasDiskEvents) { @"
<li>Run SMART health check on all disks: <code>Get-PhysicalDisk | Get-StorageReliabilityCounter</code></li>
<li>If behind a RAID controller: use vendor storage tools (HP Smart Array SSA, Dell OMSA, LSI StorCLI) to check array health.</li>
<li>Scan the filesystem without a reboot: <code>chkdsk /scan C:</code></li>
<li>If NTFS corruption detected (Event 55): schedule a full repair on next reboot: <code>chkdsk /f /r C:</code></li>
<li>Consider proactive disk replacement if SMART data shows reallocated sectors, pending sectors, or uncorrectable errors.</li>
"@ } else { "" }

        $vssBullets = if ($hasVSSEvents) { @"
<li>Check VSS writer status: <code>vssadmin list writers</code> — look for writers in a Failed or Waiting for completion state.</li>
<li>If writers are stuck: <code>net stop vss; net start vss</code> (and restart the affected application service if needed).</li>
<li>Verify backup jobs completed successfully in the backup agent console (Veeam, Datto, etc.).</li>
<li>Check Application event log for additional VSS detail around the same timestamp.</li>
"@ } else { "" }

        $networkBullets = if ($hasNetworkEvents) { @"
<li>For IP/NetBIOS conflicts: run <code>arp -a</code> and <code>nbtstat -n</code> to identify the conflicting device — check for duplicate static IPs or a rogue DHCP server.</li>
<li>Review DHCP server lease table and confirm this device's IP is not assigned to another machine.</li>
<li>If conflict is with a known device: update its static IP or reservation and flush ARP/NetBIOS caches (<code>arp -d *</code>, <code>nbtstat -R</code>).</li>
<li>For TCP connection attempt limit (Event 4226): check for unusual outbound connection volume — may indicate malware, a misconfigured application, or a port scan originating from this host.</li>
"@ } else { "" }

        $securityBullets = if ($hasSecurityEvents) { @"
<li><b>Audit log cleared (Event 1102) requires immediate investigation</b> — this can indicate an attempt to conceal malicious activity.</li>
<li>The event itself contains the account that performed the clear — confirm it was an authorised administrator action.</li>
<li>Correlate with login events (4624/4625) and privilege use events (4672) in the window leading up to the clear.</li>
<li>If the clear was not authorised: treat as a security incident — isolate the device, preserve memory/disk, and escalate.</li>
"@ } else { "" }

        $nextSteps = if ($shutdownBullets -or $diskBullets -or $vssBullets -or $networkBullets -or $securityBullets) { @"
<h4>Next Steps</h4>
<ul>
$shutdownBullets
$diskBullets
$vssBullets
$networkBullets
$securityBullets
</ul>
"@ } else { "" }

        $ticketBody = @"
<h3>EVENT LOG $summaryTag | $env:COMPUTERNAME</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Lookback Window</b></td><td>$lookbackHours hours</td></tr>
<tr><td><b>Event Types Found</b></td><td>$($findings.Count)</td></tr>
<tr><td><b>Total Occurrences</b></td><td>$totalCount</td></tr>
</table>
<h4>Findings</h4>
$findingsTable
$gracefulNote
$nextSteps
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

        $newId = New-HaloTicket `
            -Token      $haloToken `
            -ClientId   $clientSite.ClientId `
            -SiteId     $clientSite.SiteId `
            -AssetId    $clientSite.AssetId `
            -Summary    "EVENT LOG $summaryTag | $env:COMPUTERNAME | $topLabel ($totalCount occurrence(s))" `
            -Details    $ticketBody `
            -TicketType $ticketType `
            -Priority   $overallPriority `
            -Status     1 `
            -Urgency    $urgency

        if ($newId) {
            try { Ninja-Property-Set eventlogticketid "$newId" } catch { Write-Output "WARNING: Could not write eventlogticketid" }
        }
    }
}

Write-Output ""
Write-Output "====================================================="
Write-Output "=== Event Log Error Monitor Complete ==="
Write-Output "Completed : $timestamp"
exit 0
