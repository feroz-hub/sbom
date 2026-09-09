<# Starts the reports Celery worker (scheduled security report notifications, queue "reports"). #>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
. $config
Push-Location $RepoRoot
try { & .\.venv\Scripts\celery.exe -A app.workers.celery_app worker -Q reports --pool=solo --loglevel=info --hostname=reports@%h }
finally { Pop-Location }
