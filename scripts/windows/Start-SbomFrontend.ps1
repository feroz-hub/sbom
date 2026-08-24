[CmdletBinding()]
# Internal implementation script — normally invoked through setup/windows/Start.ps1.
param([switch]$NoAuth)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
$configuredApiUrl = $env:NEXT_PUBLIC_API_URL
$configuredSbomApiUrl = $env:SBOM_API_URL
. $config
if (-not [string]::IsNullOrWhiteSpace($configuredApiUrl)) { $env:NEXT_PUBLIC_API_URL = $configuredApiUrl }
if (-not [string]::IsNullOrWhiteSpace($configuredSbomApiUrl)) { $env:SBOM_API_URL = $configuredSbomApiUrl }
if ($NoAuth) { $env:NEXT_PUBLIC_AUTH_ENABLED = "false"; $frontendCommand = "dev" }
else { $frontendCommand = "dev:https" }
Push-Location (Join-Path $RepoRoot "frontend")
try { & npm.cmd run $frontendCommand }
finally { Pop-Location }
