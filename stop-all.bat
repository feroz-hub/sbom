@echo off
setlocal EnableDelayedExpansion
rem ============================================================================
rem  Stop the local SBOM Analyzer stack started by start-all.bat.
rem
rem  Kills whatever is LISTENING on the API and frontend ports, then the console
rem  windows those servers run in. Port-based rather than name-based on purpose:
rem  "python.exe" and "node.exe" are far too broad to kill blindly on a machine
rem  that also runs other projects.
rem
rem  Deliberately left alone, because they are shared infrastructure rather than
rem  part of this stack:
rem    * PostgreSQL
rem    * any Next.js dev server belonging to another project
rem
rem  Usage:  stop-all.bat            stop API + frontend
rem          stop-all.bat api        stop the API only
rem          stop-all.bat frontend   stop the frontend only
rem ============================================================================

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=all"

set "API_PORT=8000"
set "FE_PORT=3000"

echo.
echo  SBOM Analyzer - stopping local stack
echo.

if /i "%WHAT%"=="frontend" goto :stop_frontend
call :kill_port %API_PORT% "API"
if /i "%WHAT%"=="api" goto :windows

:stop_frontend
call :kill_port %FE_PORT% "Frontend"

:windows
rem The cmd /k host windows survive their child, so close them by title. These
rem titles are the ones start-all.bat sets; a window titled otherwise is left.
call :kill_window "SBOM API"
call :kill_window "SBOM Frontend"

echo.
echo  Done. PostgreSQL was not touched.
echo.
exit /b 0

rem ---------------------------------------------------------------------------
rem  kill_port <port> <label> - terminate whatever is LISTENING on that port.
rem ---------------------------------------------------------------------------
:kill_port
set "PORT=%~1"
set "LABEL=%~2"
set "FOUND=0"
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /c:":%PORT% " ^| findstr /c:"LISTENING"') do (
    if not "%%P"=="0" (
        set "FOUND=1"
        taskkill /pid %%P /t /f >nul 2>&1
        if errorlevel 1 (
            echo  [WARN]  %LABEL% - could not kill PID %%P ^(already gone, or needs admin^)
        ) else (
            echo  [STOP]  %LABEL% - port %PORT%, PID %%P
        )
    )
)
if "%FOUND%"=="0" echo  [SKIP]  %LABEL% - nothing listening on %PORT%
exit /b 0

rem ---------------------------------------------------------------------------
rem  kill_window <title> - close a console window started by start-all.bat.
rem ---------------------------------------------------------------------------
:kill_window
taskkill /fi "WINDOWTITLE eq %~1*" /f >nul 2>&1
exit /b 0
