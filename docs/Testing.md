# Testing the monitors

Use a **test device only**. [`tests/Simulate-Faults.ps1`](../tests/Simulate-Faults.ps1) creates reversible faults. It refuses to run without `-ThisIsATestDevice`.

Run it from a Ninja automation (PowerShell, Windows, Run As System). Replace `<args>` with the arguments in the table below.

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/tests/Simulate-Faults.ps1))) <args> -ThisIsATestDevice
```

| Monitor | Simulate with | Expected result | Undo |
|---|---|---|---|
| Invoke-EventLogErrors | `-Mode EventLog` | Ticket listing the simulated events (shutdown, disk, network, VSS, crash). Kernel-Power 41 cannot be faked; Security 1102 only with `-IncludeAuditLogClear`. | `-Mode EventLog -Cleanup`. The events age out of the lookback window (default 1 hour), then the next run closes the ticket. |
| Invoke-ServiceMonitor | `-Mode ServiceDown`, then set `monitoredservices` to `NinjaTestSvc` | Restart fails, ticket opened. | Clear the field, `-Mode ServiceDown -Cleanup`, close the ticket by hand. |
| Invoke-ServiceMonitor (restart works) | `-Mode ServiceDown -Service <name>`, set `monitoredservices` to it | Service restarted, closed alert logged. | `-Mode ServiceDown -Service <name> -Cleanup` |
| Invoke-PrintQueueMonitor | `-Mode PrintQueue`, set `printqueuethreshold` to 1, wait over a minute | Spooler restarted, queue cleared, closed alert. | `-Mode PrintQueue -Cleanup` |
| Invoke-NTPMonitor | `-Mode NtpSkew` (add `-KeepTimeService` to test a successful resync) | Drift detected, ticket opened (or resync fixes it). | `-Mode NtpSkew -Cleanup` |
| Invoke-MemoryMonitor | No script. Set `memorythreshold` to `1` | Alert ticket. Set it above current use (for example `99`) and rerun to close it. | Restore the field. |
| Invoke-DiskMaintenance | No script. Set `DiskThreshold_C` to `99` | Cleanup runs, then a ticket if space is still low. | Restore the field. |
| Invoke-KMSMonitor | No safe simulator. Needs a device with a genuinely unactivated Windows or Office. | n/a | n/a |

After each test, check in Halo that the ticket is linked to the device's asset.
