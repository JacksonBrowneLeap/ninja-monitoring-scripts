<#
.SYNOPSIS
    Creates harmless, reversible faults on a TEST device so the monitors in this repo can be exercised.

.DESCRIPTION
    DO NOT RUN ON A PRODUCTION OR CLIENT DEVICE. Requires -ThisIsATestDevice.

    Modes:
      EventLog     Writes fake events to the System/Application logs that Invoke-EventLogErrors watches.
                   Events are labelled "SIMULATED TEST EVENT". Use -EventGroups to pick which.
                   Cannot fake: Kernel-Power 41 (needs a real crash). Security 1102 only with
                   -IncludeAuditLogClear, which really clears the Security log.
      ServiceDown  Creates a dummy service (NinjaTestSvc) that cannot start, or stops an existing
                   service with -Service. Point Invoke-ServiceMonitor at it with the
                   'monitoredservices' Ninja field.
      PrintQueue   Creates a paused printer (NinjaTestPrinter) with one job that never prints.
                   Set the 'printqueuethreshold' field to 1 and wait over a minute.
      NtpSkew      Moves the clock forward (default 2 minutes) and stops the Windows Time service
                   so Invoke-NTPMonitor sees drift it cannot fix. Use -KeepTimeService to let the
                   monitor's resync succeed instead.

      HealthFail   Adds a fake FAIL line to the monitorhealth field, to test the Ninja alert on it.

    Undo any mode with -Cleanup.

    Memory, Disk and KMS need no simulator: temporarily change the Ninja threshold fields
    (memorythreshold, DiskThreshold_C). See docs/Testing.md.

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/tests/Simulate-Faults.ps1))) -Mode EventLog -ThisIsATestDevice
.EXAMPLE
    ... -Mode ServiceDown -ThisIsATestDevice
.EXAMPLE
    ... -Mode ServiceDown -Cleanup -ThisIsATestDevice
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('EventLog','ServiceDown','PrintQueue','NtpSkew','HealthFail')][string]$Mode,
    [Parameter(Mandatory)][switch]$ThisIsATestDevice,
    [switch]$Cleanup,
    [ValidateSet('Shutdown','Crash','Disk','Network','VSS')][string[]]$EventGroups = @('Shutdown','Crash','Disk','Network','VSS'),
    [switch]$IncludeAuditLogClear,
    [string]$Service,
    [int]$SkewMinutes = 2,
    [switch]$KeepTimeService
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: run as Administrator / SYSTEM."; exit 1
}
Write-Output "=== Simulate-Faults | $env:COMPUTERNAME | Mode=$Mode | Cleanup=$([bool]$Cleanup) ==="

# -----------------------------------------------------------------------
switch ($Mode) {

'EventLog' {
    $source = 'NinjaMonitorTest'
    if ($Cleanup) {
        if ([System.Diagnostics.EventLog]::SourceExists($source)) { Remove-EventLog -Source $source; Write-Output "Removed event source $source." }
        Write-Output "Already-written events cannot be deleted; they fall out of the monitor's lookback window (default 1h)."
        break
    }
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) { New-EventLog -LogName System -Source $source }

    # Source = custom for events the monitor matches on ID alone; real classic sources otherwise.
    $catalog = @(
        @{ Group='Shutdown'; Log='System';      Source=$source;   Id=6008 }
        @{ Group='Crash';    Log='System';      Source='BugCheck'; Id=1001 }
        @{ Group='Disk';     Log='System';      Source='disk';    Id=7    }
        @{ Group='Disk';     Log='System';      Source='disk';    Id=11   }
        @{ Group='Disk';     Log='System';      Source='Ntfs';    Id=55   }
        @{ Group='Disk';     Log='System';      Source=$source;   Id=157  }
        @{ Group='Network';  Log='System';      Source='NetBT';   Id=4319 }
        @{ Group='Network';  Log='System';      Source='Tcpip';   Id=4199 }
        @{ Group='Network';  Log='System';      Source='Tcpip';   Id=4226 }
        @{ Group='VSS';      Log='Application'; Source='VSS';     Id=8193 }
    )
    $ok = 0; $skipped = 0
    foreach ($e in $catalog | Where-Object { $_.Group -in $EventGroups }) {
        try {
            Write-EventLog -LogName $e.Log -Source $e.Source -EventId $e.Id -EntryType Error `
                -Message "SIMULATED TEST EVENT (Simulate-Faults.ps1) - not a real fault. Safe to ignore."
            Write-Output ("  wrote   {0,-11} {1,-16} id {2}" -f $e.Log, $e.Source, $e.Id); $ok++
        } catch {
            Write-Output ("  SKIPPED {0,-11} {1,-16} id {2} - {3}" -f $e.Log, $e.Source, $e.Id, $_.Exception.Message); $skipped++
        }
    }
    if ($IncludeAuditLogClear) {
        Write-Output "  clearing the Security log (real audit log clear, on purpose)..."
        wevtutil cl Security
    }
    Write-Output "Done: $ok written, $skipped skipped. Now run Invoke-EventLogErrors on this device."
}

'ServiceDown' {
    $dummy = 'NinjaTestSvc'
    if ($Cleanup) {
        if (Get-Service -Name $dummy -ErrorAction SilentlyContinue) { sc.exe delete $dummy | Out-Null; Write-Output "Deleted $dummy." }
        if ($Service) { Start-Service -Name $Service; Write-Output "Started $Service." }
        break
    }
    if ($Service) {
        Stop-Service -Name $Service -Force
        Write-Output "Stopped $Service. Set 'monitoredservices' = $Service, run Invoke-ServiceMonitor: expect restart succeeded."
    } else {
        if (-not (Get-Service -Name $dummy -ErrorAction SilentlyContinue)) {
            sc.exe create $dummy binPath= "C:\NinjaTest\missing.exe" start= demand DisplayName= "Ninja Monitor Test Service" | Out-Null
        }
        Write-Output "Created $dummy (cannot start). Set 'monitoredservices' = $dummy, run Invoke-ServiceMonitor: expect restart fails, ticket opened."
        Write-Output "To finish: remove the field value and run with -Cleanup, then close the Halo ticket by hand."
    }
}

'PrintQueue' {
    $name = 'NinjaTestPrinter'
    if ($Cleanup) {
        if (Get-Printer -Name $name -ErrorAction SilentlyContinue) {
            Get-PrintJob -PrinterName $name -ErrorAction SilentlyContinue | Remove-PrintJob -ErrorAction SilentlyContinue
            Remove-Printer -Name $name
            Write-Output "Removed $name."
        }
        break
    }
    if (-not (Get-Printer -Name $name -ErrorAction SilentlyContinue)) {
        Add-Printer -Name $name -DriverName 'Microsoft Print to PDF' -PortName 'FILE:'
    }
    Get-CimInstance Win32_Printer -Filter "Name='$name'" | Invoke-CimMethod -MethodName Pause | Out-Null
    "Simulated stuck job" | Out-Printer -Name $name
    Write-Output "Paused printer $name with one queued job."
    Write-Output "Set 'printqueuethreshold' = 1, wait over a minute, then run Invoke-PrintQueueMonitor. Run -Cleanup afterwards."
}

'HealthFail' {
    # Adds (or with -Cleanup removes) a fake FAIL line in the monitorhealth field, to test the Ninja
    # "Custom fields" alert on "|FAIL|" without touching Halo or any real monitor.
    $raw  = Ninja-Property-Get monitorhealth 2>$null
    $keep = @()
    if ($raw) { $keep = @("$raw" -split "\r?\n" | Where-Object { $_ -and ($_ -notlike 'SimulatedTest|*') }) }
    if (-not $Cleanup) {
        $keep += "SimulatedTest|FAIL|$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))|SIMULATED failure for alert testing"
    }
    Ninja-Property-Set monitorhealth (($keep | Sort-Object) -join "`n")
    Write-Output $(if ($Cleanup) { "Removed the SimulatedTest line from monitorhealth." } else { "Added SimulatedTest|FAIL to monitorhealth. The Ninja alert should fire; run -Cleanup to clear it." })
}

'NtpSkew' {
    if ($Cleanup) {
        Start-Service w32time -ErrorAction SilentlyContinue
        w32tm /resync /force | Out-Null
        Write-Output "Time service started and resynced. Clock now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        break
    }
    if (-not $KeepTimeService) { Stop-Service w32time -Force }
    $target = (Get-Date).AddMinutes($SkewMinutes)
    Set-Date -Date $target | Out-Null
    Write-Output "Clock moved forward $SkewMinutes min (now $(Get-Date -Format 'HH:mm:ss')). Time service $(if ($KeepTimeService) { 'left running' } else { 'stopped' })."
    Write-Output "Run Invoke-NTPMonitor now. Then run -Cleanup to restore time."
}

}
