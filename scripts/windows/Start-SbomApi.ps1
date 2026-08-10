[CmdletBinding()]
param([switch]$NoAuth)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
. $config
if ($NoAuth) {
    $env:AUTH_ENABLED = "false"
    $env:DEV_DEFAULT_TENANT = "true"
}
Push-Location $RepoRoot
try { & .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload }
finally { Pop-Location }
