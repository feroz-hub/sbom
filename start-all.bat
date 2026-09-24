@echo off
setlocal EnableDelayedExpansion
rem ============================================================================
rem  Start the local SBOM Analyzer stack: FastAPI backend + Next.js frontend.
rem
rem  Deliberately simpler than scripts\windows\Start-SbomAll.ps1, which refuses
rem  to run without .windows\sbom.env.ps1 from Initialize-SbomLocal.ps1 and is
rem  geared to the HCL.CS / OIDC path. This reads .env and frontend\.env.local
rem  directly, which is how the stack is actually run here.
rem
rem  PostgreSQL is NOT started or stopped: it is shared infrastructure running
rem  as a Windows service, not part of this stack.
rem
rem  Usage:  start-all.bat            start API + frontend
rem          start-all.bat api        start the API only
rem          start-all.bat frontend   start the frontend only
rem ============================================================================

set "REPO=%~dp0"
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=all"

set "API_PORT=8000"
set "FE_PORT=3000"
set "VENV_PY=%REPO%\.venv\Scripts\python.exe"

echo.
echo  SBOM Analyzer - starting local stack
echo  repo: %REPO%
echo.

rem --- preflight -------------------------------------------------------------
if not exist "%VENV_PY%" (
    echo  [ERROR] No virtualenv at .venv
    echo          Create it first:  py -m venv .venv ^&^& .venv\Scripts\python -m pip install -r requirements.txt
    exit /b 1
)
if not exist "%REPO%\.env" (
    echo  [ERROR] No .env in the repo root. Copy .env.example and set DATABASE_URL.
    exit /b 1
)
if not exist "%REPO%\frontend\node_modules" (
    echo  [ERROR] frontend\node_modules is missing. Run:  cd frontend ^&^& npm install
    exit /b 1
)

rem PostgreSQL must already be listening; the app cannot start without it.
netstat -ano -p tcp | findstr /r /c:"LISTENING" | findstr /c:":5432 " >nul 2>&1
if errorlevel 1 (
    echo  [WARN]  Nothing is listening on 5432 - is the PostgreSQL service running?
    echo          The API will start but fail its database checks.
    echo.
)

rem --- backend ---------------------------------------------------------------
if /i "%WHAT%"=="frontend" goto :frontend

call :is_listening %API_PORT%
if "%PORT_BUSY%"=="1" (
    echo  [SKIP]  API          - port %API_PORT% already in use
) else (
    start "SBOM API" /d "%REPO%" cmd /k ""%VENV_PY%" run.py"
    echo  [START] API          - http://localhost:%API_PORT%
)
if /i "%WHAT%"=="api" goto :done

rem --- frontend --------------------------------------------------------------
:frontend
call :is_listening %FE_PORT%
if "%PORT_BUSY%"=="1" (
    echo  [SKIP]  Frontend     - port %FE_PORT% already in use
) else (
    start "SBOM Frontend" /d "%REPO%\frontend" cmd /k "npm run dev"
    echo  [START] Frontend     - http://localhost:%FE_PORT%
)

:done
echo.
echo  Each component runs in its own window. Close them, or run stop-all.bat.
echo.
exit /b 0

rem ---------------------------------------------------------------------------
rem  Sets PORT_BUSY=1 when something is LISTENING on the given port.
rem  Matches ":<port> " so 3000 does not match 30000.
rem ---------------------------------------------------------------------------
:is_listening
set "PORT_BUSY=0"
for /f "tokens=*" %%L in ('netstat -ano -p tcp ^| findstr /c:":%~1 " ^| findstr /c:"LISTENING"') do set "PORT_BUSY=1"
exit /b 0
