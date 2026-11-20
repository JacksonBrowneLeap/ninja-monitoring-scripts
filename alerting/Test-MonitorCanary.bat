@echo off
setlocal EnableDelayedExpansion
rem ===========================================================================
rem Test-MonitorCanary.bat - PowerShell-independent health check for the monitors.
rem
rem Runs from a NinjaOne automation (Language: Batch, Run As: System) every ~15 minutes.
rem Needs no PowerShell to report a PowerShell problem. On a failure it writes an
rem Application event, source "NinjaMonitor", which a Ninja "Windows Event" condition alerts on.
rem
rem   ID 901  PowerShell failed to run (missing, broken or blocked)
rem   ID 902  PowerShell is older than 5.1
rem   ID 903  GitHub unreachable (shared library cannot be downloaded)
rem   ID 904  Halo unreachable (URL read from the halopsaurl Ninja field)
rem
rem Test the alert path without breaking anything:  Test-MonitorCanary.bat simulate 903
rem Real-failure tests: set any of these before the checks run (see docs/Alerting.md):
rem   GITHUB_URL (bad URL -> 903), HALO_URL_OVERRIDE (bad URL -> 904), MIN_PS=99.0 (-> 902), PS_EXE=missing.exe (-> 901)
rem Exit code: 0 = all checks passed, 1 = at least one failed.
rem ===========================================================================

set "SRC=NinjaMonitor"
if not defined GITHUB_URL set "GITHUB_URL=https://raw.githubusercontent.com/JacksonBrowneLeap/ninja-monitoring-scripts/main/lib/HaloCommon.ps1"
if not defined PS_EXE set "PS_EXE=powershell.exe"
if not defined MIN_PS set "MIN_PS=5.1"
set "CLI=%ProgramData%\NinjaRMMAgent\ninjarmm-cli.exe"
set "FAILS=0"

if /i "%~1"=="simulate" goto :simulate

rem --- 1) PowerShell runs and is 5.1 or newer -------------------------------
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "if ($PSVersionTable.PSVersion -lt [version]'%MIN_PS%') { exit 42 } else { exit 0 }" >nul 2>&1
set "PSRC=!errorlevel!"
if "!PSRC!"=="0" goto :ps_ok
if "!PSRC!"=="42" goto :ps_old
call :fail 901 "PowerShell failed to run (exit code !PSRC!) - missing, broken or blocked"
goto :ps_done
:ps_old
call :fail 902 "PowerShell is older than %MIN_PS%"
goto :ps_done
:ps_ok
echo OK: PowerShell 5.1 or newer runs.
:ps_done

rem --- 2) Network checks need curl.exe (Windows 10 1803 and later) ----------
where curl.exe >nul 2>&1
if errorlevel 1 goto :no_curl

call :http "%GITHUB_URL%"
if "!HTTP!"=="200" goto :gh_ok
call :fail 903 "Cannot reach GitHub for the shared library (HTTP !HTTP!)"
goto :gh_done
:gh_ok
echo OK: GitHub reachable.
:gh_done

set "HALO_URL="
if exist "%CLI%" for /f "usebackq delims=" %%u in (`"%CLI%" get halopsaurl 2^>nul`) do set "HALO_URL=%%u"
if defined HALO_URL_OVERRIDE set "HALO_URL=%HALO_URL_OVERRIDE%"
if not defined HALO_URL goto :halo_skip
if "!HALO_URL:~-1!"=="/" set "HALO_URL=!HALO_URL:~0,-1!"
call :http "!HALO_URL!/auth/token"
if "!HTTP!"=="000" goto :halo_bad
if !HTTP! GEQ 500 goto :halo_bad
echo OK: Halo reachable (HTTP !HTTP!).
goto :finish
:halo_bad
call :fail 904 "Cannot reach Halo at !HALO_URL! (HTTP !HTTP!)"
goto :finish
:halo_skip
echo SKIP: halopsaurl not readable from the Ninja CLI - Halo check skipped.
goto :finish

:no_curl
echo SKIP: curl.exe not found - network checks skipped.

:finish
if !FAILS! GTR 0 exit /b 1
echo OK: all canary checks passed.
exit /b 0

:simulate
set "SIMID=%~2"
if "%SIMID%"=="" set "SIMID=903"
call :fail %SIMID% "SIMULATED canary event for alert testing"
exit /b 1

rem --- helpers --------------------------------------------------------------
:http
set "HTTP=000"
for /f %%c in ('curl.exe -s -o NUL -w "%%{http_code}" --max-time 20 "%~1" 2^>NUL') do set "HTTP=%%c"
exit /b 0

:fail
echo FAIL [%~1]: %~2
set /a FAILS+=1
eventcreate /T ERROR /ID %~1 /L APPLICATION /SO %SRC% /D "%COMPUTERNAME%: %~2" >nul 2>&1
exit /b 0
