# Invoke-PrintQueueMonitor

Finds stuck print jobs, clears the queue, restarts the Print Spooler, and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Every 30 minutes |
| **Run as** | System |
| **Remediation** | Stops the Spooler, clears spool files, restarts the Spooler |

## What it does
1. Checks all print queues for jobs older than the stuck threshold.
2. If any are stuck, stops the Spooler, clears the spool files, and restarts it.
3. Spooler restarts fine: logs a closed alert ticket for information.
4. Spooler does not restart: opens a service ticket.
5. No stuck jobs: silent, and any open ticket is resolved.

Clearing the queue deletes the stuck jobs, so users may need to print again.

## Run it
Use this launcher (TLS 1.2 first, and a failed download is reported); see [Launchers](Launchers.md).
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-PrintQueueMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("PrintQueue on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `printqueueticketid` | Text | Managed by the script. Do not edit. |
| `printqueuethreshold` | Integer | Minutes before a job counts as stuck (default 15). |
