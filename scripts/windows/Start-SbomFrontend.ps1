[CmdletBinding()]
param([switch]$NoAuth)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$config = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if (-not (Test-Path $config)) { throw "Run Initialize-SbomLocal.ps1 first." }
. $config
if ($NoAuth) { $env:NEXT_PUBLIC_AUTH_ENABLED = "false" }
Push-Location (Join-Path $RepoRoot "frontend")
try { & npm.cmd run dev:https }
finally { Pop-Location }
