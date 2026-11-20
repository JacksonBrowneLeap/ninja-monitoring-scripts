<#
.SYNOPSIS
    Safety net for the monitors: exits 1 if any monitor reports FAIL, or has stopped reporting.

.DESCRIPTION
    Reads the 'monitorhealth' Ninja field, which each Invoke-*.ps1 monitor updates when it
    finishes (one line per monitor: Name|STATUS|UTC time|message).

    A monitor is flagged when:
      - its line says FAIL, or
      - it has not reported for longer than max(3 x its schedule, 12 hours).

    Use as the script of a NinjaOne "Script Result" condition (alert when exit code is not 0),
    or run manually. The FAIL case is also covered, with no script, by a "Custom fields"
    condition on monitorhealth containing "|FAIL|". This script adds the "stopped reporting" case.

    A monitor you remove from a device leaves its line behind and will go stale; delete that
    line from the monitorhealth field.
#>

# Schedule of each monitor, in hours (keys match $MonitorName in each script).
$Intervals     = @{ Disk = 6; EventLog = 1; KMS = 24; Memory = 0.25; NTP = 24; PrintQueue = 0.5; Service = 0.25 }
$StaleFactor   = 3
$MinStaleHours = 12

$raw = Ninja-Property-Get monitorhealth 2>$null
if (-not $raw) { Write-Output "No monitorhealth data yet."; exit 0 }

$problems = @()
foreach ($line in ("$raw" -split "\r?\n" | Where-Object { $_.Trim() })) {
    $p = $line -split '\|', 4
    if ($p.Count -lt 3) { continue }
    $name   = $p[0]
    $status = $p[1]
    $msg    = if ($p.Count -ge 4) { $p[3] } else { '' }

    if ($status -eq 'FAIL') { $problems += "${name}: FAIL - $msg" }

    $when  = [datetime]::MinValue
    $style = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($p[2], [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$when)) {
        $ageH  = ((Get-Date).ToUniversalTime() - $when).TotalHours
        $every = if ($Intervals.ContainsKey($name)) { $Intervals[$name] } else { $null }
        $limit = if ($every) { [math]::Max($every * $StaleFactor, $MinStaleHours) } else { $MinStaleHours * 2 }
        if ($ageH -gt $limit) {
            $problems += ("{0}: no report for {1:N0}h (limit {2:N0}h)" -f $name, $ageH, $limit)
        }
    }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Output $_ }
    exit 1
}
Write-Output "All monitors reporting OK."
exit 0
