<#
.SYNOPSIS
    Downloads the monitors and shared library from GitHub and checks that each one parses.

.DESCRIPTION
    A syntax error pushed to the repo breaks a monitor on every device at once, and the monitor can
    never report it because it never starts. This check runs from the canary (alerting/Test-MonitorCanary.bat,
    event ID 906) so that case is caught within one canary cycle. It exits 1 and lists the problems.

    Parsing uses the PowerShell on the device, i.e. the real target (5.1), not a newer one.

    Environment:
        NM_SCRIPT_BASE  Optional. Base raw URL, e.g. a fork or branch. Defaults to this repo's main.
#>

$Base = $env:NM_SCRIPT_BASE
if (-not $Base) { $Base = 'https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main' }
$Base = $Base.TrimEnd('/')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Keep in step with the Invoke-*.ps1 files in the repo (CI checks that this list is complete).
$Files = @(
    'lib/HaloCommon.ps1',
    'Invoke-DiskMaintenance.ps1', 'Invoke-EventLogErrors.ps1', 'Invoke-KMSMonitor.ps1', 'Invoke-MemoryMonitor.ps1',
    'Invoke-NTPMonitor.ps1', 'Invoke-PrintQueueMonitor.ps1', 'Invoke-ServiceMonitor.ps1',
    'alerting/Test-MonitorHealth.ps1'
)

$problems = @()
foreach ($f in $Files) {
    try {
        $text = Invoke-RestMethod -Uri "$Base/$f" -UseBasicParsing -ErrorAction Stop
    } catch {
        $problems += "${f}: could not download - $($_.Exception.Message)"
        continue
    }
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput([string]$text, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        $first = $errs[0]
        $problems += "${f}: $($errs.Count) parse error(s), first at line $($first.Extent.StartLineNumber): $($first.Message)"
    }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Output $_ }
    exit 1
}
Write-Output "All $($Files.Count) monitor files download and parse."
exit 0
