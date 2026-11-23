# Launchers for the NinjaOne automations

Each automation (PowerShell, Windows, Run As System) contains a short launcher that downloads the monitor from this repo and runs it. Use the launchers below, not a bare `irm ... | iex`.

## Why the launcher looks like this

- **TLS 1.2 is set first.** Windows PowerShell 5.1 on Windows Server 2012 R2 and 2016 defaults to `Ssl3, Tls`, and GitHub only accepts TLS 1.2. A bare `irm https://raw.githubusercontent.com/... | iex` then fails with `The underlying connection was closed: An unexpected error occurred on a send`. The monitors set TLS 1.2 themselves, but only after they have been downloaded, which is too late.
- **A failed download is visible.** With a bare `irm | iex` the download error is not fatal, so Ninja shows the run as SUCCESS, nothing is written to `monitorhealth` and no alert fires. This launcher writes event **905** (source `NinjaMonitor`, which your Windows Event condition already covers) with the reason, and exits 1 so the run shows as a failure in Ninja.

To replace a launcher: open the automation in the Ninja library, replace the script body with the block for that monitor, save, and make sure the policy picks up the change.

## Invoke-LeapDiskMaintenance

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-DiskMaintenance.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("Disk on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapEventLogErrors

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-EventLogErrors.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("EventLog on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapKMSMonitor

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-KMSMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("KMS on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapMemoryMonitor

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-MemoryMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("Memory on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapNTPMonitor

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-NTPMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("NTP on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapPrintQueueMonitor

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-PrintQueueMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("PrintQueue on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Invoke-LeapServiceMonitor

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-ServiceMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("Service on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Other one-liners

The test helpers and the stale check are also downloaded, so put the TLS line in front of them on older servers:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/alerting/Test-MonitorHealth.ps1 | iex
```

`alerting/Test-MonitorCanary.bat` is a batch file and does not use `irm` for the monitors, but its PowerShell checks (event 906 and 908) now set TLS 1.2 before downloading.
