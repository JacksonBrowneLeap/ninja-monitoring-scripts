#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Managed - Disk Maintenance Script
    Scheduled via Ninja policy. Checks all configured drives against per-drive thresholds,
    runs cleanup if needed, and creates Halo PSA tickets based on outcome.

.DESCRIPTION
    - Reads per-drive thresholds from Ninja custom fields (DiskThreshold_C, DiskThreshold_D, etc)
    - Checks DiskCleanupExcluded flag - exits if ticked
    - For each drive below threshold: runs cleanup, creates Halo ticket
    - Cleanup resolved: if open ticket exists add resolved note + clear field; else closed Alert ticket (Type 21)
    - Cleanup failed: if open ticket exists add re-check note; else new Service ticket (Type 1) + write ID to DiskLastTicketId
    - All drives healthy: silent log only, no ticket
    - New tickets are linked to the matching Halo asset (looked up by hostname)

.NOTES
    Version           : 1.5.0
    Changelog         :
        1.0.0 - Initial release
        1.1.0 - Added DiskLastTicketId field tracking; ticket deduplication across runs
        1.2.0 - Added healthy/excluded path ticket resolve + close; fixed Write-Output capture bug
        1.3.0 - Junction-safe folder size scan; cleanmgr 5-min timeout; Halo token refresh;
                fixed anyDriveExcluded final message; HTML whitespace fix for Halo notes
        1.4.0 - Halo client secret moved to Ninja secure custom field (halopsasecret)
        1.4.1 - Exclude CD/DVD and USB/removable drives via Win32_LogicalDisk DriveType check
        1.4.2 - Fix threshold comparison (-gt → -ge) so drives exactly at threshold aren't escalated
              - Fix cross-drive ticket contamination: disklastticketid now stores a per-drive JSON map
        1.4.3 - Skip USB license dongles (Sentinel/HASP/SafeNet) that present as DriveType=3 (fixed)
                by walking the WMI association chain to check the physical disk InterfaceType
        1.4.4 - Fix Int32 overflow in cleanmgr recovered-space calc ([math]::Max(0, <large>) picked the
                Int32 overload and threw, leaving a stale $freed value that was double-counted).
                Free-space values are now cast to [long]; [math]::Max uses [double]/[long] zeros.
              - Guard Measure-Object -Sum returning $null when no cleanup tasks ran (non-C drives).
        1.6.0 - Asset matching: prefer Ninja device ID (ninjarmm_id) when available, else exact hostname.
                Duplicate guard: ambiguous hostname/ID matches, or a hostname match owned by a different
                Ninja device, fall back to the fallback client with no asset link (reason shown in ticket).
                Search page size raised 10 -> 50 and a warning logged if Halo has more matches than returned.
                Optional Ninja custom field: NinjaDeviceId (Integer, Scripts = Read).
        1.5.1 - Temporary debug logging ($DebugLogging flag): asset lookup candidates, ticket request body,
                response/error body, and a post-create GET to verify the asset link. New-HaloTicket now uses
                -ErrorAction Stop so Halo's error body can be logged.
        1.5.0 - Link the matching Halo asset to newly created tickets (assets array on POST /api/tickets).
                Get-HaloClientSite now returns AssetId; New-HaloTicket takes optional -AssetId.
                Fallback (unmatched device) creates the ticket with no asset.

    Execution Context : System (run as SYSTEM / Local Admin)
    Ninja Usage       : Policy > Scheduled Automation > Run As: System
    Schedule          : Every 6 hours
    Safe to re-run    : Yes

    Ninja Custom Fields required:
        halopsaurl              - Text    - Global - Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         - Text    - Global - Halo API application (client credentials) ID
        halopsasecret           - Secure  - Global - Halo API client secret
        halopsafallbackclientid - Integer - Global - Halo client ID used when no asset match is found
        halopsafallbacksiteid   - Integer - Global - Halo site ID used when no asset match is found
        halopsarmmcustomfieldid - Integer - Global - Optional. Halo custom field ID set to 1 on created tickets (blank = omitted)
        monitorhealth           - Text    - Device - Managed by the script: one OK/FAIL line per monitor. Alert on "|FAIL|" (multi-line text)
        DiskCleanupExcluded  - Checkbox  - tick to exclude device
        DiskThreshold_C      - Integer   - default 15 if not set
        DiskThreshold_D      - Integer   - default 15 if not set
        DiskThreshold_E      - Integer   - default 15 if not set
        DiskThreshold_F      - Integer   - default 15 if not set
        DiskThreshold_G      - Integer   - default 15 if not set
        DiskThreshold_Z      - Integer   - default 15 if not set
        DiskLastTicketId     - Text      - last open Halo ticket ID (managed by script, do not edit)
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------------------------------------------------
# HALO CONFIG
# -----------------------------------------------------------------------
# Shared Halo/Ninja helpers live in lib/HaloCommon.ps1 and are loaded at runtime.
# Set $HaloLibUrl before this point to use a fork or a pinned tag instead of main.
$MonitorName = 'Disk'
if (-not $HaloLibUrl) { $HaloLibUrl = "https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/lib/HaloCommon.ps1" }
try { Invoke-Expression (Invoke-RestMethod -Uri $HaloLibUrl -UseBasicParsing -ErrorAction Stop) }
catch {
    $loadErr = ($_.Exception.Message -replace '[\r\n"]', ' ')
    Write-Output "ERROR: could not load shared library from $HaloLibUrl - $loadErr"
    # Library not available, so report through the Windows event log (Ninja Windows Event condition: source NinjaMonitor, ID 905)
    & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D "${MonitorName} on ${env:COMPUTERNAME}: could not load shared library - $loadErr" 2>&1 | Out-Null
    exit 1
}
$HaloAlertType      = 21    # Alerts board
$HaloServiceType    = 1     # Service/Incident board
$HaloCategoryId     = "Monitoring & RMM>Monitoring Alert"
$HaloImpactId       = 2     # Multiple Users

# -----------------------------------------------------------------------
# DRIVE CONFIG
# -----------------------------------------------------------------------
$DrivesToCheck      = @("C","D","E","F","G","Z")
$DefaultThreshold   = 15    # % free - used if custom field not set

# -----------------------------------------------------------------------
# DISK FUNCTIONS
# -----------------------------------------------------------------------
function Get-DriveStats {
    param([string]$Drive)
    # DriveType 3 = Fixed disk; skip removable (2), CD/DVD (5), network (4), etc.
    $wmi = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${Drive}:'" -ErrorAction SilentlyContinue
    if (-not $wmi -or $wmi.DriveType -ne 3) { return $null }
    # Some USB license dongles (Sentinel, HASP, SafeNet) report DriveType=3 but are USB-backed.
    # Walk LogicalDisk → DiskPartition → DiskDrive to check the physical interface type.
    try {
        $partition = Get-CimInstance -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='${Drive}:'} WHERE AssocClass=Win32_LogicalDiskToPartition" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($partition) {
            $physDisk = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($physDisk -and $physDisk.InterfaceType -eq 'USB') {
                Write-Host "[$Drive] USB-backed drive (license dongle) - skipping."
                return $null
            }
        }
    } catch {}
    $disk = Get-PSDrive -Name $Drive -ErrorAction SilentlyContinue
    if (-not $disk) { return $null }
    $totalBytes = $disk.Used + $disk.Free
    if ($null -eq $totalBytes -or $totalBytes -eq 0) { return $null }
    return @{
        Drive    = $Drive
        FreeGB   = [math]::Round($disk.Free / 1GB, 2)
        UsedGB   = [math]::Round($disk.Used / 1GB, 2)
        TotalGB  = [math]::Round($totalBytes / 1GB, 2)
        FreePct  = [math]::Round(($disk.Free / $totalBytes) * 100, 1)
    }
}

function Get-DriveThreshold {
    param([string]$Drive)
    $fieldName = "diskthreshold$($Drive.ToLower())"
    try { $val = Ninja-Property-Get $fieldName } catch { $val = "" }
    if ($val -and $val -match '^\d+$') {
        if ([int]$val -eq 0) { return -1 }  # 0 = exclude this drive
        return [int]$val
    }
    return $DefaultThreshold
}

function Get-FolderSizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $files = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer }
        if (-not $files) { return 0 }
        return [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
    } catch { return 0 }
}

function Get-FolderSizeGB {
    param([string]$Path)
    $totalBytes = [long]0
    $stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut   = $false
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Path)
    while ($queue.Count -gt 0) {
        if ($stopwatch.Elapsed.TotalSeconds -gt 300) {
            $timedOut = $true
            break
        }
        $dir = $queue.Dequeue()
        try {
            $dirInfo = [System.IO.DirectoryInfo]::new($dir)
            foreach ($file in $dirInfo.GetFiles()) {
                try { $totalBytes += $file.Length } catch {}
            }
            foreach ($subDir in $dirInfo.GetDirectories()) {
                if (-not ($subDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    $queue.Enqueue($subDir.FullName)
                }
            }
        } catch {}
    }
    if ($timedOut) { Write-Host "WARNING: Folder size scan timed out after 5 min for $Path — result is partial." }
    return [math]::Round($totalBytes / 1GB, 2)
}

function Get-TopFoldersBySize {
    param([string]$Drive, [int]$Top = 10)
    $path = "$($Drive):\"
    try {
        $folders = Get-ChildItem $path -Directory -Force -ErrorAction SilentlyContinue |
                   Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) }
        $results = foreach ($folder in $folders) {
            [PSCustomObject]@{ Folder = $folder.FullName; SizeGB = Get-FolderSizeGB -Path $folder.FullName }
        }
        return $results | Sort-Object SizeGB -Descending | Select-Object -First $Top
    } catch { return $null }
}

function Invoke-DiskCleanup {
    param([string]$Drive)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Windows Temp (C only)
    if ($Drive -eq "C") {
        $path = "$env:windir\Temp"
        if (Test-Path $path) {
            $before = Get-FolderSizeMB $path
            Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $freed = [math]::Max([double]0, $before - (Get-FolderSizeMB $path))
            $results.Add([PSCustomObject]@{ Task="Windows Temp"; RecoveredMB=$freed; Status="OK" })
        }

        # User temp folders
        $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }
        $userTotal = [double]0
        foreach ($p in $profiles) {
            $tempPath = Join-Path $p.FullName "AppData\Local\Temp"
            if (Test-Path $tempPath) {
                $before = Get-FolderSizeMB $tempPath
                Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                $userTotal += [math]::Max([double]0, $before - (Get-FolderSizeMB $tempPath))
            }
        }
        $results.Add([PSCustomObject]@{ Task="User Temp Folders"; RecoveredMB=$userTotal; Status="OK" })

        # Windows Update cache
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $wuWasRunning = $wuService.Status -eq "Running"
        if ($wuWasRunning) {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            $stopWait = 0
            while ((Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and $stopWait -lt 30) {
                Start-Sleep -Seconds 2
                $stopWait += 2
            }
        }
        $wuPath = "$env:windir\SoftwareDistribution\Download"
        if (Test-Path $wuPath) {
            $before = Get-FolderSizeMB $wuPath
            Get-ChildItem $wuPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $freed = [math]::Max([double]0, $before - (Get-FolderSizeMB $wuPath))
            $results.Add([PSCustomObject]@{ Task="Windows Update Cache"; RecoveredMB=$freed; Status="OK" })
        }
        if ($wuWasRunning) { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }

        # Recycle Bin
        $rbBefore = 0
        foreach ($rb in @("C:\`$Recycle.Bin","C:\RECYCLER")) {
            if (Test-Path $rb) { $rbBefore += Get-FolderSizeMB $rb }
        }
        try {
            $shell = New-Object -ComObject Shell.Application
            $shell.Namespace(0xA).Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }
            Get-ChildItem "C:\`$Recycle.Bin" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{ Task="Recycle Bin"; RecoveredMB=$rbBefore; Status="OK" })
        } catch {
            $results.Add([PSCustomObject]@{ Task="Recycle Bin"; RecoveredMB=0; Status="Error" })
        }

        # Cleanmgr
        $cleanupKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $categories = @(
            "Active Setup Temp Folders","BranchCache","Content Indexer Cleaner",
            "Downloaded Program Files","Internet Cache Files","Memory Dump Files",
            "Offline Pages Files","Old ChkDsk Files","Previous Installations","Recycle Bin",
            "Setup Log Files","System error memory dump files","System error minidump files",
            "Temporary Files","Temporary Setup Files","Thumbnail Cache","Update Cleanup",
            "Windows Defender","Windows Error Reporting Files","Windows Upgrade Log Files"
        )
        foreach ($cat in $categories) {
            $regPath = Join-Path $cleanupKey $cat
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "StateFlags0001" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        $cleanmgrExe = "$env:windir\System32\cleanmgr.exe"
        if (Test-Path $cleanmgrExe) {
            # Free-space values are UInt64/Int64; cast to [long] so [math]::Max doesn't pick the Int32 overload
            $beforeFree      = [long](Get-PSDrive -Name $Drive).Free
            $cleanmgrTimedOut = $false
            $cleanmgrProcess = Start-Process -FilePath $cleanmgrExe -ArgumentList "/sagerun:1" -PassThru -ErrorAction SilentlyContinue
            if ($cleanmgrProcess) {
                $cleanmgrProcess | Wait-Process -Timeout 300 -ErrorAction SilentlyContinue
                if (-not $cleanmgrProcess.HasExited) {
                    $cleanmgrProcess | Stop-Process -Force -ErrorAction SilentlyContinue
                    $cleanmgrTimedOut = $true
                    Write-Host "WARNING: cleanmgr.exe did not complete within 5 minutes — terminated."
                }
            }
            Start-Sleep -Seconds 5
            $afterFree     = [long](Get-PSDrive -Name $Drive).Free
            $cleanmgrFreed = [math]::Round([math]::Max([long]0, $afterFree - $beforeFree) / 1MB, 1)
            $results.Add([PSCustomObject]@{ Task="Disk Cleanup (cleanmgr)"; RecoveredMB=$cleanmgrFreed; Status=$(if ($cleanmgrTimedOut) { "Timeout" } else { "OK" }) })
        } else {
            $results.Add([PSCustomObject]@{ Task="Disk Cleanup (cleanmgr)"; RecoveredMB=0; Status="Skipped" })
        }
    }

    return $results
}

# -----------------------------------------------------------------------
# TICKET MAP HELPERS  (JSON map stored in disklastticketid Ninja field)
# -----------------------------------------------------------------------
function Get-TicketMap {
    try { $raw = Ninja-Property-Get disklastticketid } catch { $raw = "" }
    if ($raw -and $raw -ne "none" -and $raw.Trim().StartsWith("{")) {
        try {
            $obj = $raw | ConvertFrom-Json
            $map = @{}
            $obj.PSObject.Properties | ForEach-Object { $map[$_.Name] = $_.Value }
            return $map
        } catch {}
    }
    return @{}
}

function Save-TicketMap {
    param([hashtable]$Map)
    $json = if ($Map.Count -eq 0) { "{}" } else { $Map | ConvertTo-Json -Compress }
    try { Ninja-Property-Set disklastticketid $json } catch { Write-Output "WARNING: Could not write disklastticketid" }
}

# -----------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------
$tzName    = [System.TimeZoneInfo]::Local.DisplayName
$timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($tzName)"
$osInfo    = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

Write-Output "=== Disk Maintenance ==="
Write-Output "Computer  : $env:COMPUTERNAME"
Write-Output "OS        : $($osInfo.Caption)"
Write-Output "Timestamp : $timestamp"
Write-Output ""

# -----------------------------------------------------------------------
# EXCLUSION CHECK
# -----------------------------------------------------------------------
try { $excluded = Ninja-Property-Get diskcleanupexcluded } catch { $excluded = "" }

if ($excluded -eq "1") {
    Write-Output "DiskCleanupExcluded is set on this device - skipping all disk maintenance."
    Complete-Monitor
}

# -----------------------------------------------------------------------
# HALO AUTH + CLIENT LOOKUP
# -----------------------------------------------------------------------
$haloToken     = Get-HaloToken
$haloTokenTime = Get-Date
$clientSite    = Get-HaloClientSite -Token $haloToken
$clientWarning = if ($clientSite.IsFallback) {
    " - <b>WARNING:</b> Could not match device to a Halo asset ($($clientSite.FallbackReason)), defaulting to the fallback client. Verify correct client before actioning."
} else { "" }

Write-Output "Halo      : $($clientSite.Source)"
Write-Output "Halo Asset: $(if ($clientSite.AssetId) { "#$($clientSite.AssetId)" } else { 'none (ticket will not be linked to an asset)' })"
Write-DebugLog "Halo token acquired: $([bool]$haloToken); secret present: $([bool]$HaloClientSecret); fallback used: $($clientSite.IsFallback)"
Write-DebugLog "ClientSite: ClientId=$($clientSite.ClientId) SiteId=$($clientSite.SiteId) AssetId=$($clientSite.AssetId)"
Write-Output "====================================================="

# -----------------------------------------------------------------------
# DRIVE LOOP
# -----------------------------------------------------------------------
$anyDriveActioned = $false
$anyDriveExcluded = $false

foreach ($drive in $DrivesToCheck) {
    if (((Get-Date) - $haloTokenTime).TotalMinutes -gt 50) {
        Write-Host "Refreshing Halo token (approaching expiry)..."
        $refreshed = Get-HaloToken
        if ($refreshed) { $haloToken = $refreshed; $haloTokenTime = Get-Date }
    }

    $stats = Get-DriveStats -Drive $drive
    if (-not $stats) {
        Write-Output "[$drive] Not present - skipping."
        continue
    }

    $threshold = Get-DriveThreshold -Drive $drive

    if ($threshold -eq -1) {
        $anyDriveExcluded = $true
        $ticketMap = Get-TicketMap; $lastTicketId = $ticketMap[$drive]
        if ($lastTicketId -match '^\d+$') {
            $existingStatus = Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId
            if ($null -ne $existingStatus -and $existingStatus -notin @(9, 20)) {
                Write-Output "[$drive] Excluded - resolving open ticket #$lastTicketId."
                $excludedNote = @"
<h4>Drive Excluded from Monitoring</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
</table>
<p>DiskThreshold for this drive has been set to 0 (excluded). No further automated monitoring will occur. Verify manually if action is still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
                Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $excludedNote
                Close-HaloTicket -Token $haloToken -TicketId $lastTicketId
                $ticketMap = Get-TicketMap; $ticketMap.Remove($drive); Save-TicketMap -Map $ticketMap
            } else {
                Write-Output "[$drive] Excluded from monitoring — DiskThreshold_$drive = 0. Set to 1–100 to re-enable."
            }
        } else {
            Write-Output "[$drive] Excluded from monitoring — DiskThreshold_$drive = 0. Set to 1–100 to re-enable."
        }
        continue
    }

    Write-Output ""
    Write-Output "--- [$drive] ------------------------------------------------"
    Write-Output "[$drive] $($stats.FreeGB) GB free of $($stats.TotalGB) GB ($($stats.FreePct)%) - threshold: $threshold%"

    if ($stats.FreePct -ge $threshold) {
        $ticketMap = Get-TicketMap; $lastTicketId = $ticketMap[$drive]
        if ($lastTicketId -match '^\d+$') {
            $existingStatus = Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId
            if ($null -ne $existingStatus -and $existingStatus -notin @(9, 20)) {
                Write-Output "[$drive] Healthy - resolving open ticket #$lastTicketId."
                $resolvedNote = @"
<h4>Disk Space — Now Healthy</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Free</b></td><td>$($stats.FreeGB) GB ($($stats.FreePct)%) — above threshold ($threshold%)</td></tr>
</table>
<p>Drive is now above the alert threshold. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
                Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
                Close-HaloTicket -Token $haloToken -TicketId $lastTicketId
                $ticketMap = Get-TicketMap; $ticketMap.Remove($drive); Save-TicketMap -Map $ticketMap
            } else {
                Write-Output "[$drive] Healthy - no action required."
            }
        } else {
            Write-Output "[$drive] Healthy - no action required."
        }
        continue
    }

    # Drive is below threshold
    $anyDriveActioned = $true
    Write-Output "[$drive] Below threshold - running cleanup..."

    # Run cleanup
    $cleanupResults = Invoke-DiskCleanup -Drive $drive
    $freedSum       = ($cleanupResults | Measure-Object -Property RecoveredMB -Sum).Sum
    $totalFreedMB   = [math]::Round([double]$freedSum, 1)   # $null (no tasks ran) -> 0

    $statsAfter = Get-DriveStats -Drive $drive
    Write-Output "[$drive] Cleanup complete - recovered $totalFreedMB MB - now $($statsAfter.FreeGB) GB free ($($statsAfter.FreePct)%)"

    $taskRows = ($cleanupResults | ForEach-Object {
        "<tr><td>$($_.Task)</td><td>$($_.RecoveredMB) MB</td><td>$($_.Status)</td></tr>"
    }) -join ""
    $cleanupSection = if ($cleanupResults.Count -gt 0) {
        "<h4>Cleanup Attempted</h4><table><tr><th>Task</th><th>Recovered</th><th>Status</th></tr>$taskRows</table>"
    } else {
        "<p><i>No automated cleanup available for $($drive):\ — only C: is supported by this script.</i></p>"
    }

    # -----------------------------------------------------------------------
    # OUTCOME: RESOLVED
    # -----------------------------------------------------------------------
    if ($statsAfter.FreePct -ge $threshold) {

        $ticketMap = Get-TicketMap; $lastTicketId = $ticketMap[$drive]
        $existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }

        if ($null -ne $existingStatus -and $existingStatus -notin @(9, 20)) {
            Write-Output "[$drive] Resolved - adding note to existing open ticket #$lastTicketId."

            $resolvedNote = @"
<h4>Disk Space Alert - Resolved Automatically</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Free Before</b></td><td>$($stats.FreeGB) GB ($($stats.FreePct)%)</td></tr>
<tr><td><b>Free After</b></td><td>$($statsAfter.FreeGB) GB ($($statsAfter.FreePct)%)</td></tr>
<tr><td><b>Recovered</b></td><td>$totalFreedMB MB</td></tr>
</table>
<p>Automated cleanup resolved the disk space issue. No further action required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $resolvedNote
            Close-HaloTicket -Token $haloToken -TicketId $lastTicketId
            $ticketMap = Get-TicketMap; $ticketMap.Remove($drive); Save-TicketMap -Map $ticketMap

        } else {
            Write-Output "[$drive] Resolved - creating closed Halo alert ticket."

            $recoveryWarning = if ($totalFreedMB -gt 10240) {
                "<p><b>Note:</b> Recovery figure ($totalFreedMB MB) is unusually high and may include non-temp files. Review in Ninja activity log if unexpected.</p>"
            } else { "" }

            $alertBody = @"
<h3>Disk Space Alert - Resolved Automatically</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Free Before</b></td><td>$($stats.FreeGB) GB ($($stats.FreePct)%)</td></tr>
<tr><td><b>Free After</b></td><td>$($statsAfter.FreeGB) GB ($($statsAfter.FreePct)%)</td></tr>
<tr><td><b>Recovered</b></td><td>$totalFreedMB MB</td></tr>
</table>
$recoveryWarning
$cleanupSection
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. No billable time was spent - safe to close.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

            New-HaloTicket `
                -Token      $haloToken `
                -ClientId   $clientSite.ClientId `
                -SiteId     $clientSite.SiteId `
                -AssetId    $clientSite.AssetId `
                -Summary    "DISK ALERT | $env:COMPUTERNAME | $($drive): Cleanup recovered $totalFreedMB MB ($($statsAfter.FreeGB) GB free)" `
                -Details    $alertBody `
                -TicketType $HaloAlertType `
                -Priority   4 `
                -Status     9 `
                -Urgency    2
        }

    # -----------------------------------------------------------------------
    # OUTCOME: NOT RESOLVED
    # -----------------------------------------------------------------------
    } else {
        Write-Output "[$drive] Still below threshold after cleanup - escalating to service board."

        $topFolders = Get-TopFoldersBySize -Drive $drive -Top 10
        $folderRows = if ($topFolders) {
            ($topFolders | ForEach-Object { "<tr><td>$("{0:N2}" -f $_.SizeGB) GB</td><td>$($_.Folder)</td></tr>" }) -join ""
        } else { "<tr><td colspan='2'>Unable to generate folder report.</td></tr>" }

        $priority = if ($statsAfter.FreeGB -lt 5) { 1 } elseif ($statsAfter.FreeGB -lt 10) { 2 } else { 3 }

        $ticketMap = Get-TicketMap; $lastTicketId = $ticketMap[$drive]
        $existingStatus = if ($lastTicketId -match '^\d+$') { Get-HaloTicketStatus -Token $haloToken -TicketId $lastTicketId } else { $null }

        if ($null -ne $existingStatus -and $existingStatus -notin @(9, 20)) {
            Write-Output "[$drive] Open ticket #$lastTicketId found - adding re-check note."

            $recheckNote = @"
<h4>Disk Space Re-Check — Still Below Threshold</h4>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Free</b></td><td>$($statsAfter.FreeGB) GB ($($statsAfter.FreePct)%) — threshold: $threshold%</td></tr>
<tr><td><b>Cleanup Recovered</b></td><td>$totalFreedMB MB (insufficient to resolve)</td></tr>
</table>
<h4>Top Folders ($($drive):\)</h4>
<table>
<tr><th>Size</th><th>Folder</th></tr>
$folderRows
</table>
<p>Automated maintenance re-ran. Drive is still below threshold. Manual investigation still required.</p>
<hr><p><i>Updated automatically by NinjaRMM automation.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"
            Add-HaloTicketNote -Token $haloToken -TicketId $lastTicketId -Note $recheckNote

        } else {

            $serviceBody = @"
<h3>Disk Space Escalation - Manual Action Required</h3>
<table>
<tr><td><b>Device</b></td><td>$env:COMPUTERNAME</td></tr>
<tr><td><b>Drive</b></td><td>$($drive):\</td></tr>
<tr><td><b>OS</b></td><td>$($osInfo.Caption)</td></tr>
<tr><td><b>Client</b></td><td>$($clientSite.Source)$clientWarning</td></tr>
<tr><td><b>Time</b></td><td>$timestamp</td></tr>
<tr><td><b>Total</b></td><td>$($statsAfter.TotalGB) GB</td></tr>
<tr><td><b>Used</b></td><td>$($statsAfter.UsedGB) GB</td></tr>
<tr><td><b>Free</b></td><td><b>$($statsAfter.FreeGB) GB ($($statsAfter.FreePct)%)</b></td></tr>
</table>
<h4>Background</h4>
<p>The automated disk cleanup script ran on this device and was unable to recover sufficient space to bring $($drive): above the $threshold% threshold. This ticket has been escalated for manual investigation.</p>
$cleanupSection
<h4>Next Steps</h4>
<ul>
<li>Review folder size report below - identify largest disk consumers.</li>
<li>Check for oversized log files: C:\Windows\Logs, C:\inetpub\logs, application-specific log paths.</li>
<li>Check for backup agent local staging data (Veeam, Datto, etc).</li>
<li>Run DISM component store cleanup: <code>DISM /Online /Cleanup-Image /StartComponentCleanup</code></li>
<li>If SQL instance present, check database and transaction log file sizes.</li>
<li>For a full visual breakdown, install WinDirStat (<code>winget install WinDirStat.WinDirStat</code>) or use TreeSize Free to identify large files and folders interactively.</li>
<li>If still unresolved, escalate for capacity review/disk expansion.</li>
</ul>
<h4>Top 10 Folders by Size ($($drive):\)</h4>
<table>
<tr><th>Size</th><th>Folder</th></tr>
$folderRows
</table>
<hr>
<p><i>This ticket was created automatically by a NinjaRMM automation. Manual investigation required before closing.</i></p>
"@ -replace ">[ \t\r\n]+<", "><"

            $newTicketId = New-HaloTicket `
                -Token      $haloToken `
                -ClientId   $clientSite.ClientId `
                -SiteId     $clientSite.SiteId `
                -AssetId    $clientSite.AssetId `
                -Summary    "DISK ESCALATION | $env:COMPUTERNAME | $($drive): Automated cleanup insufficient - $($statsAfter.FreeGB) GB free ($($statsAfter.FreePct)%)" `
                -Details    $serviceBody `
                -TicketType $HaloServiceType `
                -Priority   $priority `
                -Status     1 `
                -Urgency    1

            if ($newTicketId) {
                $ticketMap = Get-TicketMap; $ticketMap[$drive] = "$newTicketId"; Save-TicketMap -Map $ticketMap
            }
        }
    }

}

# -----------------------------------------------------------------------
# FINAL STATUS
# -----------------------------------------------------------------------
Write-Output ""
Write-Output "====================================================="
if (-not $anyDriveActioned) {
    if ($anyDriveExcluded) {
        Write-Output "All monitored drives healthy — some drives excluded from monitoring (DiskThreshold = 0)."
    } else {
        Write-Output "All drives healthy - no action required."
    }
}
Write-Output "=== Disk Maintenance Complete ==="
Write-Output "Completed : $timestamp"
Complete-Monitor
