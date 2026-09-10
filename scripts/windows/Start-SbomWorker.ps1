<# Starts the default Celery worker (analysis, KEV sync, cache sweeps). #>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
. $config
Push-Location $RepoRoot
try { & .\.venv\Scripts\celery.exe -A app.workers.celery_app worker --pool=solo --loglevel=info --hostname=default@%h }
finally { Pop-Location }
