# Invoke-NTPMonitor

Checks the device clock against an NTP server, tries a resync if it has drifted, and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Daily |
| **Run as** | System |
| **Remediation** | `w32tm /resync /force` when drift exceeds the threshold |

## What it does
1. Queries the NTP server over UDP 123 and compares it with local UTC time.
2. If drift is above the threshold, attempts a resync and rechecks after 20 seconds.
3. Drift still above threshold: opens a ticket. Drift back to normal: closes the open ticket.
4. On domain machines, ticket notes mention that a wrong domain controller clock makes every member look drifted, so you don't chase the wrong device.

A clean run creates no ticket.

## Run it
```powershell
irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/Invoke-NTPMonitor.ps1 | iex
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `ntpdriftticketid` | Text | Managed by the script. Do not edit. |
| `ntpdriftthreshold` | Integer | Alert threshold in seconds (default 30). |
| `ntpserver` | Text | NTP server to query (default `pool.ntp.org`). |
