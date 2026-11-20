# ninja-monitoring-scripts

PowerShell monitoring scripts for NinjaOne that create and resolve tickets in Halo PSA.
Each script is run on a schedule from a NinjaOne policy as SYSTEM.

| Script | Schedule | Purpose |
|---|---|---|
| [Invoke-DiskMaintenance](docs/Invoke-DiskMaintenance.md) | Every 6 hours | Checks free space per drive, runs cleanup, raises tickets |
| [Invoke-EventLogErrors](docs/Invoke-EventLogErrors.md) | Hourly | Flags crashes, disk errors, conflicts and cleared audit logs |
| [Invoke-KMSMonitor](docs/Invoke-KMSMonitor.md) | Daily | Checks Windows and Office activation, retries Windows activation |
| [Invoke-MemoryMonitor](docs/Invoke-MemoryMonitor.md) | Every 15 minutes | Reports high memory use with the top processes |
| [Invoke-NTPMonitor](docs/Invoke-NTPMonitor.md) | Daily | Checks clock drift and attempts a resync |
| [Invoke-PrintQueueMonitor](docs/Invoke-PrintQueueMonitor.md) | Every 30 minutes | Clears stuck print jobs and restarts the Spooler |
| [Invoke-ServiceMonitor](docs/Invoke-ServiceMonitor.md) | Every 15 minutes | Restarts stopped services and raises tickets if they stay down |

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
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/<ScriptName>.ps1 | iex
```

Replace `<ScriptName>` with one of the script names above, for example `Invoke-NTPMonitor`.

Your endpoint controls (application control, network filtering) must allow PowerShell to reach `raw.githubusercontent.com`.

## Security

No credentials are stored in these scripts. Anything instance-specific is read from NinjaOne custom fields at runtime.
Review a script before running it in your environment.
