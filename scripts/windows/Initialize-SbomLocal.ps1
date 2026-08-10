<# Initializes SBOM Analyser for native Windows development with local PostgreSQL and HCL.CS. #>
[CmdletBinding()]
param(
    [string]$PostgresHost = "localhost",
    [int]$PostgresPort = 5432,
    [string]$PostgresAdminUser = "postgres",
    [string]$DatabaseName = "sbom_analyser",
    [string]$DatabaseUser = "sbom",
    [string]$HclCsRoot = "",
    [switch]$SkipDependencyRestore
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($HclCsRoot)) { $HclCsRoot = Join-Path (Split-Path $RepoRoot -Parent) "SF" }
$HclCsRoot = (Resolve-Path $HclCsRoot).Path

function Get-PlainText([Security.SecureString]$Value) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
function Find-Psql {
    $command = Get-Command psql.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $root = Join-Path $env:ProgramFiles "PostgreSQL"
    if (Test-Path $root) {
        $candidate = Get-ChildItem $root -Filter psql.exe -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw "psql.exe was not found. Install PostgreSQL 16 and open a new PowerShell window."
}
function Assert-Identifier([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "$Name is not a safe PostgreSQL identifier." }
}
function Invoke-Psql([string]$Psql, [string]$User, [string]$Database, [string]$Sql) {
    $Sql | & $Psql -X -v ON_ERROR_STOP=1 -h $PostgresHost -p $PostgresPort -U $User -d $Database
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL command failed." }
}
function Quote-Ps([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }

Assert-Identifier $DatabaseName "DatabaseName"
Assert-Identifier $DatabaseUser "DatabaseUser"
$psql = Find-Psql
if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
    throw "Python 3.11+ and the py launcher are required. Install: winget install Python.Python.3.11"
}
& py.exe -3.11 -c "import sys; assert sys.version_info >= (3, 11)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.11 is not available through py.exe." }
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is required. Install: winget install OpenJS.NodeJS.LTS"
}

$adminPassword = Get-PlainText (Read-Host "PostgreSQL password for $PostgresAdminUser" -AsSecureString)
$databasePassword = Get-PlainText (Read-Host "Choose a local password for database role $DatabaseUser" -AsSecureString)
try {
    $env:PGPASSWORD = $adminPassword
    $roleLookup = & $psql -X -tA -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres `
        -c "SELECT 1 FROM pg_roles WHERE rolname='$($DatabaseUser.Replace("'", "''"))'"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query PostgreSQL roles. Verify that PostgreSQL is running and that the $PostgresAdminUser password is correct."
    }
    $roleExists = ([string]$roleLookup).Trim()
    if ($roleExists -ne "1") {
        Invoke-Psql $psql $PostgresAdminUser postgres `
            "CREATE ROLE `"$DatabaseUser`" LOGIN PASSWORD '$($databasePassword.Replace("'", "''"))';"
    } else {
        Invoke-Psql $psql $PostgresAdminUser postgres `
            "ALTER ROLE `"$DatabaseUser`" WITH LOGIN PASSWORD '$($databasePassword.Replace("'", "''"))';"
    }
    $databaseLookup = & $psql -X -tA -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres `
        -c "SELECT 1 FROM pg_database WHERE datname='$($DatabaseName.Replace("'", "''"))'"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query PostgreSQL databases. Verify that PostgreSQL is running and that the $PostgresAdminUser password is correct."
    }
    $dbExists = ([string]$databaseLookup).Trim()
    if ($dbExists -ne "1") {
        Invoke-Psql $psql $PostgresAdminUser postgres `
            "CREATE DATABASE `"$DatabaseName`" OWNER `"$DatabaseUser`";"
    }
} finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    $adminPassword = $null
}

$hclCertificate = Join-Path $HclCsRoot ".windows\certificates\hcl-cs-local.pem"
if (-not (Test-Path $hclCertificate)) {
    throw "HCL.CS certificate not found at $hclCertificate. Run Initialize-HclCsLocal.ps1 first."
}
$encodedPassword = [Uri]::EscapeDataString($databasePassword)
$databaseUrl = "postgresql+psycopg://$DatabaseUser`:$encodedPassword@$PostgresHost`:$PostgresPort/$DatabaseName"
$windowsDir = Join-Path $RepoRoot ".windows"
New-Item -ItemType Directory -Force $windowsDir | Out-Null
$envScript = @(
    "`$env:DATABASE_URL = $(Quote-Ps $databaseUrl)",
    "`$env:AUTH_ENABLED = 'true'",
    "`$env:DEV_DEFAULT_TENANT = 'false'",
    "`$env:HCL_IAM_ISSUER = 'https://localhost:5180'",
    "`$env:HCL_IAM_AUDIENCE = 'sbom-analyser-api'",
    "`$env:HCL_IAM_CLIENT_ID = 'sbom-analyser-web'",
    "`$env:HCL_IAM_DISCOVERY_URL = 'https://localhost:5180/.well-known/openid-configuration'",
    "`$env:HCL_IAM_ROLE_CLAIM = 'role'",
    "`$env:HCL_IAM_TENANT_CLAIM = 'tenant_id'",
    "`$env:HCL_IAM_ALLOWED_ALGORITHMS = 'RS256'",
    "`$env:HCL_IAM_CA_BUNDLE = $(Quote-Ps $hclCertificate)",
    "`$env:CORS_ORIGINS = 'https://localhost:3000'",
    "`$env:NEXT_PUBLIC_AUTH_ENABLED = 'true'",
    "`$env:NEXT_PUBLIC_API_URL = 'http://localhost:8000'",
    "`$env:NEXT_PUBLIC_APP_URL = 'https://localhost:3000'",
    "`$env:NEXT_PUBLIC_HCL_IAM_ISSUER = 'https://localhost:5180'",
    "`$env:NEXT_PUBLIC_HCL_IAM_CLIENT_ID = 'sbom-analyser-web'",
    "`$env:NEXT_PUBLIC_HCL_IAM_REDIRECT_URI = 'https://localhost:3000/auth/callback'",
    "`$env:NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI = 'https://localhost:3000'",
    "`$env:NEXT_PUBLIC_HCL_IAM_SCOPES = 'openid profile email offline_access sbom-analyser-api'",
    "`$env:SBOM_API_URL = 'http://localhost:8000'"
)
Set-Content -Path (Join-Path $windowsDir "sbom.env.ps1") -Value $envScript -Encoding utf8
$databasePassword = $null

$venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { & py.exe -3.11 -m venv (Join-Path $RepoRoot ".venv") }
if (-not $SkipDependencyRestore) {
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r (Join-Path $RepoRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }
    Push-Location (Join-Path $RepoRoot "frontend")
    try { & npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw "Frontend npm install failed." } }
    finally { Pop-Location }
}
. (Join-Path $windowsDir "sbom.env.ps1")
Push-Location $RepoRoot
try { & $venvPython -m alembic upgrade head; if ($LASTEXITCODE -ne 0) { throw "Alembic migration failed." } }
finally { Pop-Location }
& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "frontend\scripts\setup-dev-https.ps1")
if ($LASTEXITCODE -ne 0) { throw "Frontend HTTPS setup failed." }
Write-Host "SBOM native Windows setup is complete." -ForegroundColor Green
Write-Host "Start API: .\scripts\windows\Start-SbomApi.ps1"
Write-Host "Start UI:  .\scripts\windows\Start-SbomFrontend.ps1"
