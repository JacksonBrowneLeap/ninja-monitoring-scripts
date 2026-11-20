# ninja-monitoring-scripts

PowerShell monitoring scripts for NinjaOne that create and resolve tickets in Halo PSA.
Each script is run on a schedule from a NinjaOne policy as SYSTEM.

| Script | Purpose |
|---|---|
| `Invoke-DiskMaintenance.ps1` | Per-drive free-space check, cleanup, ticketing |
| `Invoke-EventLogErrors.ps1` | Event log error monitor |
| `Invoke-KMSMonitor.ps1` | KMS activation monitor |
| `Invoke-MemoryMonitor.ps1` | Memory usage monitor |
| `Invoke-NTPMonitor.ps1` | NTP drift monitor with resync attempt |
| `Invoke-PrintQueueMonitor.ps1` | Stuck print queue monitor |
| `Invoke-ServiceMonitor.ps1` | Service health monitor |

## Required NinjaOne custom fields (System scope, Automation = Read)

| Field | Type | Holds |
|---|---|---|
| `halopsaurl` | Text | Halo base URL, e.g. `https://yourtenant.halopsa.com` |
| `halopsaclientid` | Text | Halo API application (client credentials) ID |
| `halopsasecret` | Secure | Halo API client secret |
| `halopsafallbackclientid` | Integer | Halo client ID used when no asset match is found |
| `halopsafallbacksiteid` | Integer | Halo site ID used when no asset match is found |

Each script's header lists any extra per-script fields.

## Running from NinjaOne

Create an automation (PowerShell, Windows, Run As: System) containing:

```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/Invoke-NTPMonitor.ps1 | iex
```

Your endpoint controls (application control, network filtering) must allow PowerShell to reach `raw.githubusercontent.com`.

## Security

No credentials are stored in these scripts. Anything instance-specific is read from NinjaOne custom fields at runtime.
Review a script before running it in your environment.
