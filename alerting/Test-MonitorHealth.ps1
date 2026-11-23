<#
.SYNOPSIS
    Safety net for the monitors: exits 1 if any monitor reports FAIL, or has stopped reporting.

.DESCRIPTION
    Reads the 'monitorhealth' Ninja field, which each Invoke-*.ps1 monitor updates when it
    finishes (one line per monitor: Name|STATUS|UTC time|message).

    A monitor is flagged when:
      - its line says FAIL (skipped when NM_STALE_ONLY=1), or
      - it has not reported for longer than max(3 x its schedule, 1 hour), or
      - it is listed as required for this device and has no line at all.

    The canary (alerting/Test-MonitorCanary.bat) runs this every cycle with NM_STALE_ONLY=1 and raises
    event 908, so "a monitor stopped reporting" is alerted without any extra Ninja setup. It can also be
    used on its own as the script of a NinjaOne "Script Result" condition (alert when exit code is not 0),
    or run manually. The FAIL case is separately covered, with no script, by a "Custom fields"
    condition on monitorhealth containing "|FAIL|".

    Environment / variables (all optional):
        NM_STALE_ONLY=1        Report only stale/missing monitors, not FAIL lines (the canary already
                               has the Custom fields condition for those).
        NM_REQUIRED=Service,Memory   Monitors that must have a line on this device. A missing line is
                               flagged. Leave empty to only check monitors that have reported before.
                               (A $RequiredMonitors array set before running does the same.)

    A monitor you remove from a device leaves its line behind and will go stale; delete that
    line from the monitorhealth field.
#>

# Schedule of each monitor, in hours (keys match $MonitorName in each script).
$Intervals     = @{ Disk = 6; EventLog = 0.5; KMS = 24; Memory = 0.25; NTP = 24; PrintQueue = 0.5; Service = 0.25 }
$StaleFactor   = 3
$MinStaleHours = 1      # was 12: a dead 15-minute monitor should not take half a day to flag
$UnknownLimitH = 24     # for a monitor name that is not in $Intervals

# When launched from the batch canary there is no Ninja PowerShell module in this session: fall back to the agent CLI.
if (-not (Get-Command Ninja-Property-Get -ErrorAction SilentlyContinue)) {
    function Ninja-Property-Get {
        param([string]$Name)
        $cli = Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) { & $cli get $Name }
    }
}

function ConvertFrom-MonitorHealth {
    # Parses the monitorhealth field into entries (Name, Status, Time, Message). Deliberately does NOT rely on
    # line breaks: Ninja has been seen handing the value back with the newlines turned into spaces, which made a
    # line-based parser treat the whole field as one line. Entries are found by their Name|OK/FAIL|UTC time| shape.
    # Keep this copy identical in alerting/Test-MonitorHealth.ps1 and tests/Simulate-Faults.ps1 (they run standalone).
    param([string]$Raw)
    if (-not $Raw) { return }
    $pattern = '(?<name>[A-Za-z0-9_.-]+)\|(?<status>OK|FAIL)\|(?<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\|(?<msg>.*?)(?=\s*[A-Za-z0-9_.-]+\|(?:OK|FAIL)\|\d{4}-\d{2}-\d{2}T|\s*$)'
    foreach ($m in [regex]::Matches($Raw, $pattern, 'Singleline')) {
        [pscustomobject]@{ Name = $m.Groups['name'].Value; Status = $m.Groups['status'].Value; Time = $m.Groups['time'].Value; Message = $m.Groups['msg'].Value.Trim() }
    }
}

$staleOnly = ($env:NM_STALE_ONLY -eq '1')
$required  = @()
if ($RequiredMonitors) { $required += $RequiredMonitors }
if ($env:NM_REQUIRED)  { $required += ($env:NM_REQUIRED -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

$raw = Ninja-Property-Get monitorhealth 2>$null
$problems = @()
$seen = @{}

if (-not $raw) {
    if ($required.Count -eq 0) { Write-Output "No monitorhealth data yet."; exit 0 }
} else {
    $entries = @(ConvertFrom-MonitorHealth "$raw")
    if ($entries.Count -eq 0) { $problems += "monitorhealth has data but no readable entries: ${raw}" }
    foreach ($entry in $entries) {
        $name   = $entry.Name
        $status = $entry.Status
        $msg    = $entry.Message
        $seen[$name] = $true

        if ($status -eq 'FAIL' -and -not $staleOnly) { $problems += "${name}: FAIL - $msg" }

        $when  = [datetime]::MinValue
        $style = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
        if ([datetime]::TryParse($entry.Time, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$when)) {
            $ageH  = ((Get-Date).ToUniversalTime() - $when).TotalHours
            $every = if ($Intervals.ContainsKey($name)) { $Intervals[$name] } else { $null }
            $limit = if ($every) { [math]::Max($every * $StaleFactor, $MinStaleHours) } else { $UnknownLimitH }
            if ($ageH -gt $limit) {
                $problems += ("{0}: no report for {1:N1}h (limit {2:N1}h)" -f $name, $ageH, $limit)
            }
        } else {
            $problems += "${name}: unreadable timestamp '$($entry.Time)'"
        }
    }
}

foreach ($r in $required) {
    if (-not $seen.ContainsKey($r)) { $problems += "${r}: required monitor has never reported" }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Output $_ }
    exit 1
}
Write-Output "All monitors reporting OK."
exit 0
