# Alerting when the monitors themselves fail

The monitors report problems on the device. This page covers the other case: the monitoring itself breaks (wrong PowerShell version, Halo unreachable, GitHub unreachable, PowerShell blocked). It uses two layers that fail independently.

| Layer | Catches | Works without PowerShell? | Ninja alert type |
|---|---|---|---|
| 1. Script health | Halo auth/API failure, missing Halo config, ticket calls failing, PowerShell older than 5.1 | No | **Custom fields** condition |
| 2. Canary | PowerShell broken or blocked, PowerShell too old, GitHub unreachable, Halo unreachable, a script that could not load the shared library | **Yes** | **Windows Event** condition |

A scripts-stopped-reporting check (`alerting/Test-MonitorHealth.ps1`) is optional on top of both.

## Layer 1: script health

Each monitor writes one line to the device custom field `monitorhealth` when it finishes:

```
NTP|OK|2026-11-20T06:40:53Z|
Service|FAIL|2026-11-20T06:45:02Z|Halo auth failed - Unable to connect to the remote server
```

A failing monitor also exits with code 1, so the run shows as failed in the Ninja activity log.

### Setup in Ninja
1. **Create the field.** Administration, Devices, Role custom fields (or your usual place for device fields). Name `monitorhealth`, type **Multi-line text**, Automation = **Read/Write**.
2. **Add the condition** to your monitoring policy: Add condition, **Custom fields**.
   - Under "Custom field value must meet ANY conditions" click **Add**.
   - Field `monitorhealth`, operator **contains**, value `|FAIL|`.
   - **Settings:** pick a severity and priority. If a reset or auto-resolve option is offered, leave it on so the alert clears when the monitor next reports OK.
   - **Notifications:** choose how it reaches you (for example the same route as your other device alerts).

The alert clears by itself on the next successful run, because each monitor overwrites only its own line.

## Layer 2: the canary

`alerting/Test-MonitorCanary.bat` is a batch script, so it can report a PowerShell failure even when PowerShell is dead. It checks that PowerShell runs and is 5.1 or newer, and with `curl.exe` that GitHub and your Halo URL are reachable. On a failure it writes an Application event, source `NinjaMonitor`:

| ID | Meaning |
|---|---|
| 901 | PowerShell failed to run (missing, broken or blocked) |
| 902 | PowerShell older than 5.1 |
| 903 | GitHub unreachable |
| 904 | Halo unreachable |
| 905 | A monitor could not load the shared library (written by the monitor itself) |

### Setup in Ninja
1. **Create the automation:** Administration, Library, Automation, Add. Language **Batch**, OS Windows, Run As **System**. Paste the contents of `alerting/Test-MonitorCanary.bat`. The canary is deliberately self-contained, so it keeps working when GitHub or PowerShell does not. When the file in the repo changes, paste the new version.
2. **Schedule it** in your policy to run about every 15 minutes.
3. **Add the condition:** Add condition, **Windows Event**. Log **Application**, source `NinjaMonitor`, event IDs **901 to 905**, type Error. If one condition cannot take a range, add one per ID or use a comma list. If a reset-after option is offered, set it to about an hour; the canary writes a fresh event every run while the fault persists.

The canary needs the `halopsaurl` System field (already set) and the Ninja agent CLI at `C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe`. If the CLI is missing it skips the Halo check.

## Optional: scripts that stopped reporting

`alerting/Test-MonitorHealth.ps1` flags any monitor that has not reported within max(3 x its schedule, 12 hours), plus any FAIL line. Use it as a **Script Result** condition (alert when exit code is not 0), run hourly:

```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/alerting/Test-MonitorHealth.ps1 | iex
```

If you remove a monitor from a device, delete its line from `monitorhealth`, or it will go stale.

## Test the alerts without breaking anything

Use a test device. Run from a Ninja automation (PowerShell, Windows, System):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/tests/Simulate-Faults.ps1))) -Mode HealthFail -ThisIsATestDevice
```

- The **Custom fields** alert should fire within the condition's evaluation time. Clear it with the same command plus `-Cleanup`.
- For the **Windows Event** alert, run the canary as a Batch automation with the argument `simulate 903`. A matching event is written and the alert should fire.
- A real end-to-end failure: on a test device, run a monitor whose Halo secret is wrong (for example in a test copy), or block `raw.githubusercontent.com` for that device and watch for ID 903 or 905.

## What this cannot catch

- A device that is off, or whose Ninja agent is offline: use Ninja's own offline alert.
- `cmd.exe` and PowerShell both blocked: the canary cannot run either. Check ThreatLocker audit.
