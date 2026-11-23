# Alerting when the monitors themselves fail

The monitors report problems on the device. This page covers the other case: the monitoring itself breaks (wrong PowerShell version, Halo unreachable, GitHub unreachable, PowerShell blocked). It uses two layers that fail independently.

| Layer | Catches | Works without PowerShell? | Ninja alert type |
|---|---|---|---|
| 1. Script health | Halo auth/API failure, missing Halo config, ticket calls failing, PowerShell older than 5.1 | No | **Custom fields** condition |
| 2. Canary | PowerShell broken or blocked, PowerShell too old, GitHub unreachable, Halo unreachable, a monitor or the shared library with a syntax error, a monitor that stopped reporting, a script that could not load the shared library or write its health line | **Yes** | **Windows Event** condition |

The canary also covers the cases where a monitor never gets as far as writing its health line (see "What counts as a failure" below).

## What counts as a failure

| Situation | Caught by |
|---|---|
| Halo auth/API/config failure, ticket calls failing | Layer 1 (`FAIL` line, exit 1) |
| A monitor crashes part-way (any terminating error) | Layer 1: each monitor has `trap { Invoke-MonitorCrash $_ }`, which records `FAIL` and exits 1 |
| A syntax error pushed to the repo (monitor never starts) | Canary 906, and the CI check blocks it before merge |
| A monitor hangs, is killed, is not scheduled, or its automation was removed | Canary 908 (no report within max(3 x schedule, 1 hour)) |
| The `monitorhealth` field cannot be written (field missing, wrong type, no permission) | Canary 907, raised by the monitor itself; the write is read back to prove it stuck |
| Two monitors finishing at the same time | A machine-wide lock covers the read, the write and a short wait until the write is visible, so a later monitor cannot overwrite a line from a stale read |
| Many monitors starting in the same minute (the Ninja agent then returns "Unable to fill operation type") | Each monitor waits a random 0-40 s before starting, and the library retries that one error. A monitor never writes the field after a failed read (that would wipe the other monitors' lines) |

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
| 906 | A monitor or the shared library on GitHub does not parse (syntax error) |
| 907 | A monitor could not write or verify its `monitorhealth` line (written by the monitor itself) |
| 908 | A monitor has not reported within max(3 x its schedule, 1 hour) |

### Setup in Ninja
1. **Create the automation:** Administration, Library, Automation, Add. Language **Batch**, OS Windows, Run As **System**. Paste the contents of `alerting/Test-MonitorCanary.bat`. The canary is deliberately self-contained, so it keeps working when GitHub or PowerShell does not. When the file in the repo changes, paste the new version.
2. **Schedule it** in your policy to run about every 15 minutes.
3. **Add the condition:** Add condition, **Windows Event**. Log **Application**, source `NinjaMonitor`, event IDs **901 to 908**, type Error. If one condition cannot take a range, add one per ID or use a comma list. If a reset-after option is offered, set it to about an hour; the canary writes a fresh event every run while the fault persists.

906 and 908 run only when PowerShell works and GitHub is reachable (otherwise 901 to 903 already fired), and download `alerting/Test-MonitorScripts.ps1` and `alerting/Test-MonitorHealth.ps1` from GitHub each cycle. To require specific monitors on a device (so a monitor that was never deployed or was removed is flagged), set the `NM_REQUIRED` environment variable in the canary automation, for example `set "NM_REQUIRED=Service,Memory"` near the top.

The canary needs the `halopsaurl` System field (already set) and the Ninja agent CLI at `C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe`. If the CLI is missing it skips the Halo check.

## Scripts that stopped reporting

`alerting/Test-MonitorHealth.ps1` flags any monitor that has not reported within max(3 x its schedule, 1 hour), a line with an unreadable timestamp, and any monitor named in `NM_REQUIRED` that has no line. The canary runs it every cycle (stale/missing only, raising 908), so no extra Ninja setup is needed. The FAIL case is covered by the Custom fields condition from layer 1.

You can still run it on its own as a **Script Result** condition (alert when exit code is not 0), for example hourly, which also reports `FAIL` lines:

```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/alerting/Test-MonitorHealth.ps1 | iex
```

If you remove a monitor from a device, delete its line from `monitorhealth`, or it will go stale. A new monitor must also be added to the `$Intervals` table in that script (CI checks this).

## Test the alerts without breaking anything

Use a test device. Run from a Ninja automation (PowerShell, Windows, System):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/tests/Simulate-Faults.ps1))) -Mode HealthFail -ThisIsATestDevice
```

- The **Custom fields** alert should fire within the condition's evaluation time. Clear it with the same command plus `-Cleanup`.
- For the **Windows Event** alert, run the canary as a Batch automation with the argument `simulate 903`. A matching event is written and the alert should fire.
- A real end-to-end failure: on a test device, run a monitor whose Halo secret is wrong (for example in a test copy), or block `raw.githubusercontent.com` for that device and watch for ID 903 or 905.

## Test with real failures (no fake data)

Every layer-1 failure can be triggered for real on a test device by setting a test override before a monitor runs. The monitor behaves exactly as it would in production: it hits the failure, writes `FAIL` to `monitorhealth` and exits 1. Run these from a PowerShell automation (Run As System). While the `alerting` branch is unmerged, point the monitor and library at the same ref; after the merge use `main` and drop the `$HaloLibUrl` line.

Common start for every layer-1 test:

```powershell
$HaloLibUrl = "https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/alerting/lib/HaloCommon.ps1"
```

Then add ONE override line from the table, and finish with the monitor launcher:

```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/alerting/Invoke-NTPMonitor.ps1 | iex
```

| Failure to test | Line to add before the launcher | Expected |
|---|---|---|
| Halo not reachable | `$HaloBaseUrlOverride = "https://halo-unreachable.invalid"` | `NTP\|FAIL\|...Halo auth failed`, exit 1 |
| API key incorrect | `$HaloClientSecretOverride = "wrong-secret"` | `NTP\|FAIL\|...Halo auth failed` (401), exit 1 |
| Wrong client ID | `$HaloClientIdOverride = "00000000-0000-0000-0000-000000000000"` | `NTP\|FAIL\|...Halo auth failed`, exit 1 |
| PowerShell version too old | `$MinPSVersionOverride = "99.0"` | `NTP\|FAIL\|PowerShell 5.x is older than 99.0`, exit 1 |
| Halo URL/credentials missing | (not an override: test in a copy of the test device with the field blank, or use the API key tests) | `Halo URL, client ID or secret not configured` |
| Library cannot load | change the `$HaloLibUrl` line to `.../lib/DoesNotExist.ps1` | Event 905 from source `NinjaMonitor`, exit 1 |
| Monitor crashes | add `throw "test crash"` as a line after the library has loaded in a test copy of a monitor | `NTP\|FAIL\|...Unhandled error in NTP`, exit 1 |
| `monitorhealth` cannot be written | on a test device, set the field's Automation to Read only (or rename it), then run a monitor | Event 907, exit 1 |

Run the same launcher again without any override. The monitor writes `NTP|OK|...` and the alert clears.

### Real failures for the canary

Layer 2 reads these environment variables, so a test copy of the canary automation only needs one extra line at the very top (then delete the copy):

| Failure to test | Line to add at the top of the test copy | Expected event |
|---|---|---|
| PowerShell blocked or missing | `set "PS_EXE=C:\missing\powershell.exe"` | 901 |
| PowerShell too old | `set "MIN_PS=99.0"` | 902 |
| Syntax error in a monitor | `set "SCRIPT_BASE=<raw URL of a test branch containing a broken monitor>"` | 906 |
| Monitor stopped reporting | `set "NM_REQUIRED=SomeMonitorThatNeverRan"` (or wait out a monitor's limit on a test device) | 908 |
| GitHub unreachable | `set "GITHUB_URL=https://raw.githubusercontent.com/does-not-exist/x/main/y"` | 903 |
| Halo unreachable | `set "HALO_URL_OVERRIDE=https://halo-unreachable.invalid"` | 904 |

`simulate <ID>` writes the event directly if you only want to test the alert, not the check.

## What this cannot catch

- A device that is off, or whose Ninja agent is offline: use Ninja's own offline alert.
- `cmd.exe` and PowerShell both blocked: the canary cannot run either. Check ThreatLocker audit.
