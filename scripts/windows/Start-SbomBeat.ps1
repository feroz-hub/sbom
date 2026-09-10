<# Starts Celery Beat (the scheduler). Run exactly ONE beat instance per deployment. #>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
. $config
Push-Location $RepoRoot
try { & .\.venv\Scripts\celery.exe -A app.workers.celery_app beat --loglevel=info }
finally { Pop-Location }
