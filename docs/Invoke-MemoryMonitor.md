# Invoke-MemoryMonitor

Reports high memory use with the top processes, and opens or closes a Halo ticket. Reporting only, nothing is changed on the device.

| | |
|---|---|
| **Schedule** | Every 15 minutes (match your Ninja memory condition interval) |
| **Run as** | System |
| **Remediation** | None |

## What it does
- **Above threshold, no open ticket:** creates an alert ticket.
- **Above threshold, ticket open:** adds a re-check note with an updated process list.
- **Below threshold, ticket open:** adds a resolved note and closes the ticket.
- **Below threshold, no ticket:** silent.

The ticket body lists the top processes by working set and flags any single process using more than 20% of total RAM.

## Run it
Use this launcher (TLS 1.2 first, and a failed download is reported); see [Launchers](Launchers.md).
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/Invoke-MemoryMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("Memory on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `memorythreshold` | Integer | Alert threshold in percent (default 90, 0 disables). |
| `memorymonitorticket` | Text | Managed by the script. Do not edit. |
| `memoryprocesscount` | Integer | How many top processes to report (default 10). |
| `memoryexcludeprocesses` | Text | Comma-separated process names not to flag as HIGH, e.g. `sqlservr,mysqld`. They still appear in the table. |
