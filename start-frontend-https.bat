@echo off
setlocal EnableDelayedExpansion
rem ============================================================================
rem  Start the Next.js frontend over HTTPS, creating and trusting the localhost
rem  certificate first if one is missing or about to expire.
rem
rem  HTTPS is required whenever IAM is on: the registered OIDC redirect URI is
rem  https://localhost:3000/auth/callback, so a plain-HTTP dev server never
rem  completes the sign-in round trip.
rem
rem  start-all.bat runs the plain-HTTP `npm run dev` instead. Use this one when
rem  NEXT_PUBLIC_AUTH_ENABLED=true.
rem
rem  Usage:  start-frontend-https.bat              start (generate cert if needed)
rem          start-frontend-https.bat --force-cert regenerate the cert first
rem          start-frontend-https.bat --cert-only  set the cert up, do not start
rem ============================================================================

set "REPO=%~dp0"
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"
set "FE_PORT=3000"
set "CERT_ARGS="
set "CERT_ONLY=0"

set "SKIP_API_CHECK=0"

if /i "%~1"=="--force-cert"   set "CERT_ARGS=-Force"
if /i "%~1"=="--cert-only"    set "CERT_ONLY=1"
rem start-all.bat launches the API moments before calling this, and uvicorn
rem takes a few seconds to bind. Checking the port then would always warn.
if /i "%~1"=="--no-api-check" set "SKIP_API_CHECK=1"

echo.
echo  SBOM Analyzer - frontend (HTTPS)
echo.

rem --- preflight -------------------------------------------------------------
if not exist "%REPO%\frontend\node_modules" (
    echo  [ERROR] frontend\node_modules is missing. Run:  cd frontend ^&^& npm install
    exit /b 1
)
if not exist "%REPO%\frontend\.env.local" (
    echo  [ERROR] frontend\.env.local is missing. Copy .env.local.example and set
    echo          NEXT_PUBLIC_AUTH_ENABLED and the HCL_IAM values.
    exit /b 1
)

rem Warn, do not block: the page loads without the API, it just cannot sign in.
if "%SKIP_API_CHECK%"=="0" (
    netstat -ano -p tcp | findstr /c:":8000 " | findstr /c:"LISTENING" >nul 2>&1
    if errorlevel 1 (
        echo  [WARN]  The API is not listening on 8000 - start it with start-all.bat api
        echo.
    )
)

rem --- certificate -----------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%REPO%\scripts\windows\Ensure-DevHttpsCert.ps1" %CERT_ARGS%
if errorlevel 1 (
    echo.
    echo  [ERROR] Could not prepare the HTTPS certificate. See the message above.
    exit /b 1
)

if "%CERT_ONLY%"=="1" (
    echo.
    echo  Certificate ready. Not starting the dev server ^(--cert-only^).
    exit /b 0
)

rem --- start -----------------------------------------------------------------
echo.
call :is_listening %FE_PORT%
if "%PORT_BUSY%"=="1" (
    echo  [SKIP]  Frontend - port %FE_PORT% already in use. Run stop-all.bat first
    echo          if the server there is running plain HTTP.
    exit /b 0
)

start "SBOM Frontend" /d "%REPO%\frontend" cmd /k "npm run dev:https"
echo  [START] Frontend - https://localhost:%FE_PORT%
echo.
echo  Sign-in redirects to HCL.CS; stop-all.bat shuts this down.
echo.
exit /b 0

rem ---------------------------------------------------------------------------
rem  Sets PORT_BUSY=1 when something is LISTENING on the given port.
rem  Matches ":<port> " so 3000 does not also match 30000.
rem ---------------------------------------------------------------------------
:is_listening
set "PORT_BUSY=0"
for /f "tokens=*" %%L in ('netstat -ano -p tcp ^| findstr /c:":%~1 " ^| findstr /c:"LISTENING"') do set "PORT_BUSY=1"
exit /b 0
