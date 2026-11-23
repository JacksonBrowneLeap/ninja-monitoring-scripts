# Invoke-DiskMaintenance

Checks free space on each drive against a per-drive threshold, runs cleanup when a drive is low, and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Every 6 hours |
| **Run as** | System |
| **Remediation** | Disk cleanup (`cleanmgr`, with a 5-minute timeout) |

## What it does
1. Exits immediately if `DiskCleanupExcluded` is ticked.
2. Checks drives C, D, E, F, G and Z. CD/DVD, USB and removable drives are skipped, as are USB license dongles that present as fixed disks.
3. A drive below its free-space threshold gets a cleanup, then is checked again.
4. **Cleanup fixed it:** resolves any open ticket, or logs a closed alert for information.
5. **Cleanup did not fix it:** adds a re-check note to the open ticket, or opens a new service ticket.
6. **All drives healthy:** silent.

Tickets are linked to the matching Halo asset. The match prefers the Ninja device ID, then an exact hostname. If the match is ambiguous, the ticket goes to the fallback client with no asset link, and the ticket says why.

## Debug logging
`$DebugLogging` is `$true` by default and prints asset lookup candidates, the ticket request body and the response. Set it to `$false` in your copy once you are happy with asset linking.

## Run it
Use this launcher (TLS 1.2 first, and a failed download is reported); see [Launchers](Launchers.md).
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/leap-consult/ninja-monitoring-scripts/main/Invoke-DiskMaintenance.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("Disk on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `DiskCleanupExcluded` | Checkbox | Tick to exclude the device. |
| `DiskThreshold_C` to `DiskThreshold_G`, `DiskThreshold_Z` | Integer | Minimum percent free per drive (default 15). |
| `DiskLastTicketId` | Text | Managed by the script. Do not edit. |
| `NinjaDeviceId` | Integer | Optional. Scripts = Read. Improves asset matching. |
