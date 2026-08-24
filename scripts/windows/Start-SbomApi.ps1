[CmdletBinding()]
# Internal implementation script — normally invoked through setup/windows/Start.ps1.
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
$port = 8000
if (-not [string]::IsNullOrWhiteSpace($env:PORT)) {
    if (-not [int]::TryParse($env:PORT, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "PORT must be a valid TCP port."
    }
}
Push-Location $RepoRoot
try { & .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port $port --reload }
finally { Pop-Location }
