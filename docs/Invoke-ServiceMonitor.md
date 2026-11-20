# Invoke-ServiceMonitor

Checks a list of Windows services, restarts any that are stopped, and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Every 15 minutes |
| **Run as** | System |
| **Remediation** | Restarts stopped services, waits 30 seconds, rechecks |

## What it does
For each monitored service:
- **Running, ticket open:** adds a resolved note and closes the ticket.
- **Running, no ticket:** silent.
- **Stopped:** tries a restart, then rechecks.
  - Now running, ticket open: adds a note and closes it.
  - Now running, no ticket: logs a closed alert for information.
  - Still stopped, ticket open: adds a re-check note.
  - Still stopped, no ticket: opens a service ticket.

## Safety behaviour
- Core services (NTDS, EventLog, RpcSs) are never restarted. The script escalates them directly.
- Tamper-protected services such as SentinelOne are not restarted either. They escalate directly, and the ticket carries a note about tamper protection.
- Disabled services are skipped, and a service in a transitional state is not treated as stopped.
- A service that restarts successfully gets an open ticket that closes on the next clean run, so a flapping service shows up instead of being hidden.

## Run it
```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/Invoke-ServiceMonitor.ps1 | iex
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `monitoredservices` | Text | Comma-separated service names to monitor. Blank uses the built-in list. |
| `servicemonitorexclude` | Text | Comma-separated service names to skip on this device (case-insensitive). |
| `servicemonitortickets` | Text | Managed by the script. Do not edit. |
