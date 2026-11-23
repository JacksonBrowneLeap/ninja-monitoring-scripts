# Invoke-EventLogErrors

Scans Windows event logs for known critical events and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Hourly |
| **Run as** | System |
| **Remediation** | None (detection only) |

## Events watched
Within the lookback window (default 1 hour):

| Problem | Source and event ID |
|---|---|
| Unexpected shutdown or reboot | System 41, 6008 |
| BSOD / system crash | System 1001 (BugCheck) |
| Disk hardware errors | System 7, 11, 157 |
| NTFS corruption | System 55 |
| VSS / shadow copy failure | Application 8193 |
| NetBIOS name conflict | System 4319, 4320 (NetBT) |
| IP address conflict | System 4199 (Tcpip) |
| TCP connection attempt limit | System 4226 (Tcpip) |
| Audit log cleared | Security 1102 |

## What it does
- **Events found, no open ticket:** creates a ticket. **Events found, ticket open:** adds a re-check note.
- **Clean run, ticket open:** closes the ticket. **Clean run, no ticket:** silent.

Keep the schedule and `eventloglookbackhours` aligned. Hourly runs with a 1-hour lookback cover every event once.

## Run it
Use this launcher (TLS 1.2 first, and a failed download is reported); see [Launchers](Launchers.md).
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-EventLogErrors.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("EventLog on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `eventlogticketid` | Text | Managed by the script. Do not edit. |
| `eventloglookbackhours` | Integer | Lookback window in hours (default 1). |
| `eventlogexcluded` | Checkbox | Tick to exclude the device. |
