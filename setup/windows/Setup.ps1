<#
.SYNOPSIS
    Canonical first-time/local setup for SBOM Analyser on Windows.

.DESCRIPTION
    Developer-facing wrapper around the repository's existing bootstrap,
    database, and HTTPS setup scripts. It preserves existing environment files
    and does not grant platform-admin authority unless explicitly requested.

    Internal implementation scripts remain under scripts/ and are normally
    invoked through this setup/... entry point.
#>
[CmdletBinding()]
param(
    [switch]$UseNativeWindowsPostgres,
    [string]$HclCsRoot = "",
    [switch]$BootstrapPlatformAdmin,
    [string]$PlatformAdminSubject = "",
    [string]$PlatformAdminIssuer = "",
    [string]$PlatformAdminChangeReference = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$EnvFile = Join-Path $RepoRoot ".env"
$EnvExample = Join-Path $RepoRoot ".env.example"
$FrontendRoot = Join-Path $RepoRoot "frontend"
$FrontendEnv = Join-Path $FrontendRoot ".env.local"
$FrontendEnvExample = Join-Path $FrontendRoot ".env.local.example"

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "PASS $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "WARN $Message" -ForegroundColor Yellow }
function Fail([string]$Message) { throw $Message }

function Require-Command([string[]]$Names, [string]$Purpose) {
    foreach ($name in $Names) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            return $name
        }
    }
    Fail "$Purpose is missing. Install it and open a new PowerShell window before rerunning setup. Tried: $($Names -join ', ')."
}

function Import-DotEnv([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or $trimmed -notmatch "^[A-Za-z_][A-Za-z0-9_]*\s*=") { continue }
        $pair = $trimmed -split "=", 2
        $key = $pair[0].Trim()
        $value = $pair[1].Trim()
        if (($value.StartsWith([char]34) -and $value.EndsWith([char]34)) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
}

function Get-EnvValue([string]$Name, [string]$Default = "") {
    $value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Get-DotEnvFileValue([string]$Path, [string]$Name, [string]$Default = "") {
    if (-not (Test-Path -LiteralPath $Path)) { return $Default }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or $trimmed -notmatch "^[A-Za-z_][A-Za-z0-9_]*\s*=") { continue }
        $pair = $trimmed -split "=", 2
        if ($pair[0].Trim() -ne $Name) { continue }
        $value = $pair[1].Trim()
        if (($value.StartsWith([char]34) -and $value.EndsWith([char]34)) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        return $value
    }
    return $Default
}

function Set-SetupMode([string]$Mode) {
    $modeFile = Join-Path $RepoRoot ".windows\setup-mode.json"
    New-Item -ItemType Directory -Force -Path (Split-Path $modeFile -Parent) | Out-Null
    @{ version = 1; mode = $Mode; updatedAt = [DateTime]::UtcNow.ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath $modeFile -Encoding UTF8
}

function Test-ComposeDatabase([string]$DatabaseUrl) {
    $expectedPort = Get-EnvValue "POSTGRES_PORT" "55439"
    $env:DATABASE_URL = $DatabaseUrl
    $env:EXPECTED_POSTGRES_PORT = $expectedPort
    $result = & $VenvPython -c "import os; from sqlalchemy.engine import make_url; u=make_url(os.environ['DATABASE_URL']); print('true' if u.get_backend_name().startswith('postgresql') and (u.host or 'localhost') in {'localhost','127.0.0.1','::1'} and (u.port or 5432) == int(os.environ['EXPECTED_POSTGRES_PORT']) and (u.database or '') == 'sbom_analyser' and (u.username or '') == 'sbom' and (u.password or '') == 'sbom' else 'false')" 2>$null
    return ([string]$result).Trim() -eq "true"
}

function Assert-AuthConsistency {
    $backend = (Get-EnvValue "AUTH_ENABLED" "false").ToLowerInvariant()
    $frontend = (Get-DotEnvFileValue $FrontendEnv "NEXT_PUBLIC_AUTH_ENABLED" "false").ToLowerInvariant()
    if (($backend -ne "true" -and $backend -ne "false") -or ($frontend -ne "true" -and $frontend -ne "false")) {
        Fail "AUTH_ENABLED and NEXT_PUBLIC_AUTH_ENABLED must each be true or false."
    }
    if ($backend -ne $frontend) {
        Fail "Authentication configuration is inconsistent: AUTH_ENABLED=$backend, NEXT_PUBLIC_AUTH_ENABLED=$frontend. Update both files explicitly."
    }
    return ($backend -eq "true")
}

function Test-PythonVersion([string]$Python) {
    & $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Python 3.11 or newer is required." }
}

Write-Host ""
Write-Host "SBOM Analyser Windows Setup" -ForegroundColor White
Write-Host "===========================" -ForegroundColor White
Write-Host "Repository: $RepoRoot" -ForegroundColor Gray

Write-Step "Checking required tools"
Require-Command @("git.exe", "git") "Git" | Out-Null
$pythonCommand = Require-Command @("py.exe", "python.exe", "python") "Python"
$nodeCommand = Require-Command @("node.exe", "node") "Node.js"
Require-Command @("npm.cmd", "npm") "npm" | Out-Null
$composeAvailable = [bool](Get-Command docker.exe -ErrorAction SilentlyContinue) -and ((& docker.exe compose version 2>$null) -match "Docker Compose")
$psqlAvailable = [bool](Get-Command psql.exe -ErrorAction SilentlyContinue)
if (-not $composeAvailable -and -not $psqlAvailable) {
    Write-Warn "Docker Compose and psql.exe are unavailable. External PostgreSQL can still be checked through the Python driver; install Docker Desktop or PostgreSQL client tooling if the configured database is repository-managed or native."
}
& $pythonCommand --version
& $nodeCommand --version
& $nodeCommand -e "process.exit(Number(process.versions.node.split('.')[0]) >= 20 ? 0 : 1)"
if ($LASTEXITCODE -ne 0) { Fail "Node.js 20 or newer is required." }
& npm.cmd --version
Write-Ok "Git, Python, Node.js, npm, and PostgreSQL access are available."

Write-Step "Preparing environment files without overwriting developer values"
if (-not (Test-Path $EnvFile)) {
    if (-not (Test-Path $EnvExample)) { Fail "Missing .env.example; cannot create the backend environment file." }
    Copy-Item -LiteralPath $EnvExample -Destination $EnvFile
    Write-Ok "Created .env from .env.example. Review it before using authenticated mode."
}
else { Write-Ok "Preserved existing .env." }
if (-not (Test-Path $FrontendEnv)) {
    if (-not (Test-Path $FrontendEnvExample)) { Fail "Missing frontend/.env.local.example; cannot create frontend configuration." }
    Copy-Item -LiteralPath $FrontendEnvExample -Destination $FrontendEnv
    Write-Ok "Created frontend/.env.local from its template."
}
else { Write-Ok "Preserved existing frontend/.env.local." }

$nativeConfig = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if ($UseNativeWindowsPostgres) {
    Write-Step "Reusing native Windows/HCL.CS setup"
    $initializer = Join-Path $RepoRoot "scripts\windows\Initialize-SbomLocal.ps1"
    if (-not (Test-Path $initializer)) { Fail "Missing scripts/windows/Initialize-SbomLocal.ps1." }
    $initializerArgs = @()
    if (-not [string]::IsNullOrWhiteSpace($HclCsRoot)) { $initializerArgs += @("-HclCsRoot", $HclCsRoot) }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $initializer @initializerArgs
    if ($LASTEXITCODE -ne 0) { Fail "Native Windows SBOM setup failed." }
    if (Test-Path $nativeConfig) { . $nativeConfig }
    Set-SetupMode "native"
}
else {
    Import-DotEnv $EnvFile
    [void](Assert-AuthConsistency)
    Set-SetupMode "docker"
    Write-Step "Reusing existing dependency bootstrap"
    $bootstrap = Join-Path $RepoRoot "scripts\bootstrap.ps1"
    if (-not (Test-Path $bootstrap)) { Fail "Missing scripts/bootstrap.ps1." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrap -SkipSystem
    if ($LASTEXITCODE -ne 0) { Fail "Existing Windows dependency bootstrap failed." }
    if (-not (Test-Path $VenvPython)) { Fail "The Python virtual environment was not created at $VenvPython." }
    Test-PythonVersion $VenvPython
}
if (-not (Test-Path $VenvPython)) { Fail "The Python virtual environment was not created at $VenvPython." }
Test-PythonVersion $VenvPython

if ([string]::IsNullOrWhiteSpace((Get-EnvValue "DATABASE_URL"))) {
    Fail "DATABASE_URL is missing from .env. Set it to a reachable PostgreSQL database before rerunning setup."
}
$composeDatabaseConfigured = -not $UseNativeWindowsPostgres -and (Test-ComposeDatabase (Get-EnvValue "DATABASE_URL"))
if ($composeDatabaseConfigured -and -not $composeAvailable) {
    Fail "DATABASE_URL points to the repository Compose database, but Docker Compose is unavailable. Install Docker Desktop or change DATABASE_URL to an intentionally managed PostgreSQL instance."
}
if ($composeDatabaseConfigured -and $composeAvailable) {
    Write-Step "Starting the repository PostgreSQL service"
    Push-Location $RepoRoot
    try {
        & docker.exe compose up -d postgres
        if ($LASTEXITCODE -ne 0) { Fail "Docker Compose could not start the configured repository PostgreSQL service." }
    }
    finally { Pop-Location }
    Write-Ok "PostgreSQL Compose service started."
}
elseif (-not $UseNativeWindowsPostgres) {
    Write-Ok "Docker Compose was not started because DATABASE_URL points to a non-repository database."
}

Write-Step "Checking database connectivity"
$dbConnected = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    Push-Location $RepoRoot
    try { & $VenvPython -c "from app.db import engine; c=engine.connect(); c.close(); engine.dispose()" 2>$null }
    finally { Pop-Location }
    if ($LASTEXITCODE -eq 0) { $dbConnected = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $dbConnected) { Fail "Database connection failed after 30 seconds. Start PostgreSQL or correct DATABASE_URL in .env." }
Write-Ok "Database connection is healthy."

Write-Step "Applying Alembic migrations"
$objectCount = & $VenvPython -c "import os; from sqlalchemy import create_engine; from scripts.bootstrap_fresh_database import existing_application_objects; e=create_engine(os.environ['DATABASE_URL']); c=e.connect(); print(len(existing_application_objects(c))); c.close(); e.dispose()"
if ($LASTEXITCODE -ne 0) { Fail "Unable to inspect PostgreSQL application objects." }
$databaseName = & $VenvPython -c "import os; from sqlalchemy.engine import make_url; print(make_url(os.environ['DATABASE_URL']).database or '')"
if ([int]$objectCount -eq 0 -and (Get-EnvValue "DATABASE_URL").StartsWith("postgresql")) {
    $fresh = Join-Path $RepoRoot "scripts\bootstrap_fresh_database.py"
    & $VenvPython $fresh --confirm-empty-database ([string]$databaseName).Trim()
    if ($LASTEXITCODE -ne 0) { Fail "Fresh PostgreSQL bootstrap failed." }
}
else {
    Push-Location $RepoRoot
    try {
        & $VenvPython -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) { Fail "Alembic migration failed." }
    }
    finally { Pop-Location }
}
Write-Ok "Database schema is at the Alembic head."
$activeAdminCount = & $VenvPython -c "from app.db import SessionLocal; from app.models import PlatformUserRole; db=SessionLocal(); print(db.query(PlatformUserRole).filter(PlatformUserRole.status == 'ACTIVE').count()); db.close()"
if ($LASTEXITCODE -eq 0 -and [int]$activeAdminCount -eq 0) {
    Write-Warn "No active Platform Administrator grant exists. Setup does not grant authority; use scripts/bootstrap_platform_admin.py with an approved change reference if required."
}

$frontendAuthValue = if ($UseNativeWindowsPostgres) { Get-EnvValue "NEXT_PUBLIC_AUTH_ENABLED" "false" } else { Get-DotEnvFileValue $FrontendEnv "NEXT_PUBLIC_AUTH_ENABLED" "false" }
$backendAuthValue = (Get-EnvValue "AUTH_ENABLED" "false").ToLowerInvariant()
$frontendAuthValue = ([string]$frontendAuthValue).ToLowerInvariant()
if (($backendAuthValue -ne "true" -and $backendAuthValue -ne "false") -or ($frontendAuthValue -ne "true" -and $frontendAuthValue -ne "false")) {
    Fail "AUTH_ENABLED and NEXT_PUBLIC_AUTH_ENABLED must each be true or false."
}
if ($backendAuthValue -ne $frontendAuthValue) {
    Fail "Authentication configuration is inconsistent: AUTH_ENABLED=$backendAuthValue, NEXT_PUBLIC_AUTH_ENABLED=$frontendAuthValue. Update both files explicitly."
}
$authEnabled = $backendAuthValue -eq "true"
if ($authEnabled) {
    Write-Step "Checking HCL IAM configuration"
    $issuer = Get-EnvValue "HCL_IAM_ISSUER"
    $discovery = Get-EnvValue "HCL_IAM_DISCOVERY_URL"
    if ([string]::IsNullOrWhiteSpace($discovery)) { $discovery = $issuer.TrimEnd('/') + "/.well-known/openid-configuration" }
    if ([string]::IsNullOrWhiteSpace($issuer)) { Fail "AUTH_ENABLED=true but HCL_IAM_ISSUER is empty." }
    $caBundle = Get-EnvValue "HCL_IAM_CA_BUNDLE"
    if (-not [string]::IsNullOrWhiteSpace($caBundle) -and -not [IO.Path]::IsPathRooted($caBundle)) {
        $caBundle = Join-Path $RepoRoot $caBundle
    }
    if (-not [string]::IsNullOrWhiteSpace($caBundle) -and -not (Test-Path $caBundle)) {
        Fail "HCL_IAM_CA_BUNDLE does not exist: $caBundle"
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $curlArgs = @("--fail", "--silent", "--show-error", "--max-time", "5")
        if (-not [string]::IsNullOrWhiteSpace($caBundle)) { $curlArgs += @("--cacert", $caBundle) }
        & $curl.Source @curlArgs $discovery | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Ok "HCL IAM discovery endpoint is reachable." }
        else { Write-Warn "HCL IAM is external and was not reachable from this machine. Start Security Framework separately and verify $discovery." }
    }
    else {
        try { Invoke-WebRequest -Uri $discovery -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Ok "HCL IAM discovery endpoint is reachable." }
        catch { Write-Warn "HCL IAM is external and was not reachable from this machine. Start Security Framework separately and verify $discovery." }
    }

    $certScript = Join-Path $FrontendRoot "scripts\setup-dev-https.ps1"
    $certFile = Join-Path $FrontendRoot "certificates\localhost.pem"
    $keyFile = Join-Path $FrontendRoot "certificates\localhost-key.pem"
    if (-not (Test-Path $certFile) -or -not (Test-Path $keyFile)) {
        if (-not (Test-Path $certScript)) { Fail "Authenticated mode requires frontend HTTPS, but its certificate setup script is missing." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $certScript
        if ($LASTEXITCODE -ne 0) { Fail "Frontend HTTPS certificate setup failed." }
    }
    if (-not (Test-Path $certFile) -or -not (Test-Path $keyFile)) { Fail "Authenticated frontend HTTPS requires both localhost.pem and localhost-key.pem." }
}
else { Write-Warn "AUTH_ENABLED=false; HCL IAM is disabled for this local setup." }

if ($BootstrapPlatformAdmin) {
    if (-not $authEnabled) { Fail "Platform Administrator bootstrap requires AUTH_ENABLED=true in .env; do not override application auth mode." }
    if ([string]::IsNullOrWhiteSpace($PlatformAdminSubject) -or [string]::IsNullOrWhiteSpace($PlatformAdminChangeReference)) {
        Fail "-BootstrapPlatformAdmin requires -PlatformAdminSubject and -PlatformAdminChangeReference."
    }
    $adminScript = Join-Path $RepoRoot "scripts\bootstrap_platform_admin.py"
    $adminArgs = @("--subject", $PlatformAdminSubject, "--change-reference", $PlatformAdminChangeReference, "--confirm", "BOOTSTRAP_PLATFORM_ADMIN")
    if (-not [string]::IsNullOrWhiteSpace($PlatformAdminIssuer)) { $adminArgs += @("--issuer", $PlatformAdminIssuer) }
    & $VenvPython $adminScript @adminArgs
    if ($LASTEXITCODE -ne 0) { Fail "Platform Administrator bootstrap failed." }
}
else {
    Write-Warn "Platform Administrator grants are explicit and were not changed. Use scripts/bootstrap_platform_admin.py only after an approved operator decision."
}

Write-Host ""
Write-Host "READY" -ForegroundColor Green
Write-Host "Run .\setup\windows\Start.ps1 to start the SBOM API and integrated frontend/admin UI." -ForegroundColor White
Write-Host "HCL Security Framework/IAM is external to this repository and is only detected, not started, by this setup." -ForegroundColor Gray
