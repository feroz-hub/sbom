<# Starts the whole local SBOM stack, one PowerShell window per component.
   Skips anything already running (ports for API/frontend, command line for Celery). #>
[CmdletBinding()]
param([switch]$NoAuth)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not (Test-Path (Join-Path $RepoRoot ".windows\sbom.env.ps1"))) { throw "Run Initialize-SbomLocal.ps1 first." }

function Test-Port([int]$Port) {
    [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Test-CeleryRunning([string]$Pattern) {
    [bool](Get-CimInstance Win32_Process -Filter "Name like 'python%' or Name like 'celery%'" |
        Where-Object { $_.CommandLine -match [regex]::Escape('app.workers.celery_app') -and $_.CommandLine -match $Pattern })
}

function Start-Component([string]$Title, [string]$Script, [string[]]$ScriptArgs = @()) {
    $file = Join-Path $PSScriptRoot $Script
    $args = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command',
        "`$Host.UI.RawUI.WindowTitle = '$Title'; & '$file' $ScriptArgs")
    Start-Process powershell -ArgumentList $args -WorkingDirectory $RepoRoot | Out-Null
    Write-Host ("started  {0}" -f $Title) -ForegroundColor Green
}

$apiArgs = @(); $feArgs = @()
if ($NoAuth) { $apiArgs = @('-NoAuth'); $feArgs = @('-NoAuth') }

if (Test-Port 8000) { Write-Host "skipped  SBOM API (port 8000 already listening)" -ForegroundColor Yellow }
else { Start-Component 'SBOM API (8000)' 'Start-SbomApi.ps1' $apiArgs }

if (Test-Port 3000) { Write-Host "skipped  SBOM frontend (port 3000 already listening)" -ForegroundColor Yellow }
else { Start-Component 'SBOM frontend (3000)' 'Start-SbomFrontend.ps1' $feArgs }

if (Test-CeleryRunning 'hostname=default@') { Write-Host "skipped  Celery default worker (already running)" -ForegroundColor Yellow }
else { Start-Component 'Celery worker (default)' 'Start-SbomWorker.ps1' }

if (Test-CeleryRunning 'hostname=reports@') { Write-Host "skipped  Celery reports worker (already running)" -ForegroundColor Yellow }
else { Start-Component 'Celery worker (reports)' 'Start-SbomReportsWorker.ps1' }

if (Test-CeleryRunning ' beat ') { Write-Host "skipped  Celery Beat (already running - only ONE beat may run)" -ForegroundColor Yellow }
else { Start-Component 'Celery Beat' 'Start-SbomBeat.ps1' }

Write-Host ""
Write-Host "Reminder: the HCL.CS auth server (5001) is separate:" -ForegroundColor Cyan
Write-Host '  dotnet run --project "C:\SF_Main\SF.8.CRS_PL_AG_24\Cybersecurity-Demo\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp" --launch-profile HCL.CS.SF.DemoServerApp'
Write-Host "Status check: .\scripts\windows\Check-SbomStatus.ps1"
