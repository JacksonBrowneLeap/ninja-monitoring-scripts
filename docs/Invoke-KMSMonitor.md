# Invoke-KMSMonitor

Checks Windows and Office activation, attempts to activate Windows if needed, and opens or closes a Halo ticket.

| | |
|---|---|
| **Schedule** | Daily |
| **Run as** | System |
| **Remediation** | `slmgr /ato` for an unactivated Windows install |

## What it does
1. Checks Windows activation through WMI (`SoftwareLicensingProduct`).
2. Checks Office activation through the `OfficeSoftwareProtectionPlatform` namespace. Office is reported only, with no automatic fix, because Microsoft 365 licensing is user-based.
3. Flags SQL Server Evaluation editions. SQL Express is not flagged because it is free.
4. Unactivated Windows gets an activation attempt before any ticket is raised.
5. When everything is activated, any open ticket is closed automatically.
6. Ticket creation retries transient failures (HTTP 5xx, 429, network errors) up to 3 times.

## Run it
Use this launcher (TLS 1.2 first, and a failed download is reported); see [Launchers](Launchers.md).
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { $s = irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/Invoke-KMSMonitor.ps1 -ErrorAction Stop }
catch { & eventcreate.exe /T ERROR /ID 905 /L APPLICATION /SO NinjaMonitor /D ("KMS on ${env:COMPUTERNAME}: could not download the monitor script - " + ($_.Exception.Message -replace '[\r\n"]',' ')) | Out-Null; exit 1 }
iex $s
```

## Custom fields
Shared Halo fields are listed in the [main README](../README.md).

| Field | Type | Purpose |
|---|---|---|
| `kmsmonitorticketid` | Text | Managed by the script. Do not edit. |
| `kmsmonitorexclude` | Text | Optional. Comma-separated checks to skip: `Windows`, `Office`, `SQL`. Blank runs all checks. |
