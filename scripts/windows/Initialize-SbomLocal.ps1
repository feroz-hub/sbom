<# Initializes SBOM Analyser for native Windows development with local PostgreSQL and HCL.CS. #>
# Internal implementation script — normally invoked through setup/windows/Setup.ps1.
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
if ([string]::IsNullOrWhiteSpace($HclCsRoot)) {
    $HclCsRoot = Join-Path (Split-Path $RepoRoot -Parent) "SF"
}
$HclCsRoot = (Resolve-Path $HclCsRoot).Path
function Get-PlainText([Security.SecureString]$Value) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}
function Find-Psql {
    $command = Get-Command psql.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $postgresRoot = Join-Path $env:ProgramFiles "PostgreSQL"
    if (Test-Path $postgresRoot) {
        $candidate = Get-ChildItem $postgresRoot -Filter psql.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) {
            return $candidate.FullName
        }
    }
    throw "psql.exe was not found. Install PostgreSQL and open a new PowerShell window."
}
function Assert-Identifier([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        throw "$Name is not a safe PostgreSQL identifier."
    }
}
function Invoke-Psql([string]$Psql, [string]$User, [string]$Database, [string]$Sql) {
    $Sql | & $Psql -X -v ON_ERROR_STOP=1 -h $PostgresHost -p $PostgresPort -U $User -d $Database
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL command failed."
    }
}
function Quote-Ps([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}
Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " SBOM Analyser - Native Windows Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repository: $RepoRoot" -ForegroundColor Gray
Write-Host "HCL.CS root: $HclCsRoot" -ForegroundColor Gray
Write-Host ""
Assert-Identifier $DatabaseName "DatabaseName"
Assert-Identifier $DatabaseUser "DatabaseUser"
Write-Host "[1/9] Checking PostgreSQL..." -ForegroundColor Cyan
$psql = Find-Psql
Write-Host "psql: $psql" -ForegroundColor Green
& $psql --version
if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute psql.exe."
}
Write-Host ""
Write-Host "[2/9] Checking Python..." -ForegroundColor Cyan
$pythonLauncher = $null
foreach ($candidate in @("py.exe", "python.exe", "python")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $pythonLauncher = $candidate; break }
}
if (-not $pythonLauncher) {
    throw "Python 3.11 or newer is required. Install it and open a new PowerShell window."
}
& $pythonLauncher --version
if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute $pythonLauncher."
}
& $pythonLauncher -c "import sys; print('Detected Python:', sys.version); raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.11 or newer is required."
}
Write-Host "Python validation passed." -ForegroundColor Green
Write-Host ""
Write-Host "[3/9] Checking Node.js and npm..." -ForegroundColor Cyan
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is required."
}
if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
    throw "Node.js executable was not found."
}
& node.exe --version
if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute Node.js."
}
$nodeMajor = & node.exe -p "process.versions.node.split('.')[0]"
$nodeMajorNumber = 0
if (-not [int]::TryParse(([string]$nodeMajor).Trim(), [ref]$nodeMajorNumber) -or $nodeMajorNumber -lt 20) {
    throw "Node.js 20 or newer is required."
}
& npm.cmd --version
if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute npm."
}
Write-Host "Node.js/npm validation passed." -ForegroundColor Green
Write-Host ""
Write-Host "[4/9] Configuring PostgreSQL..." -ForegroundColor Cyan
$adminPasswordSecure = Read-Host "PostgreSQL password for $PostgresAdminUser" -AsSecureString
$databasePasswordSecure = Read-Host "Choose a local password for database role $DatabaseUser" -AsSecureString
$adminPassword = Get-PlainText $adminPasswordSecure
$databasePassword = Get-PlainText $databasePasswordSecure
if ([string]::IsNullOrWhiteSpace($adminPassword)) {
    throw "PostgreSQL administrator password cannot be empty."
}
if ([string]::IsNullOrWhiteSpace($databasePassword)) {
    throw "SBOM database password cannot be empty."
}
try {
    $env:PGPASSWORD = $adminPassword
    Write-Host "Checking database role '$DatabaseUser'..." -ForegroundColor Gray
    $escapedDatabaseUser = $DatabaseUser.Replace("'", "''")
    $roleLookupSql = "SELECT 1 FROM pg_roles WHERE rolname='$escapedDatabaseUser';"
    $roleLookup = & $psql -X -tA -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -c $roleLookupSql
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query PostgreSQL roles. Verify PostgreSQL is running and the postgres password is correct."
    }
    $roleExists = if ($null -eq $roleLookup) {
        ""
    }
    else {
        ([string]$roleLookup).Trim()
    }
    $escapedDatabasePassword = $databasePassword.Replace("'", "''")
    $quotedDatabaseUser = '"' + $DatabaseUser + '"'
    if ($roleExists -ne "1") {
        Write-Host "Creating PostgreSQL role '$DatabaseUser'..." -ForegroundColor Yellow
        $createRoleSql = "CREATE ROLE $quotedDatabaseUser LOGIN PASSWORD '$escapedDatabasePassword';"
        Invoke-Psql $psql $PostgresAdminUser "postgres" $createRoleSql
        Write-Host "Database role created." -ForegroundColor Green
    }
    else {
        Write-Host "Database role already exists. Updating its local password..." -ForegroundColor Yellow
        $alterRoleSql = "ALTER ROLE $quotedDatabaseUser WITH LOGIN PASSWORD '$escapedDatabasePassword';"
        Invoke-Psql $psql $PostgresAdminUser "postgres" $alterRoleSql
        Write-Host "Database role updated." -ForegroundColor Green
    }
    Write-Host "Checking database '$DatabaseName'..." -ForegroundColor Gray
    $escapedDatabaseName = $DatabaseName.Replace("'", "''")
    $databaseLookupSql = "SELECT 1 FROM pg_database WHERE datname='$escapedDatabaseName';"
    $databaseLookup = & $psql -X -tA -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -c $databaseLookupSql
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query PostgreSQL databases."
    }
    $databaseExists = if ($null -eq $databaseLookup) {
        ""
    }
    else {
        ([string]$databaseLookup).Trim()
    }
    $quotedDatabaseName = '"' + $DatabaseName + '"'
    if ($databaseExists -ne "1") {
        Write-Host "Creating fresh PostgreSQL database '$DatabaseName'..." -ForegroundColor Yellow
        $createDatabaseSql = "CREATE DATABASE $quotedDatabaseName OWNER $quotedDatabaseUser;"
        Invoke-Psql $psql $PostgresAdminUser "postgres" $createDatabaseSql
        Write-Host "Database '$DatabaseName' created." -ForegroundColor Green
    }
    else {
        Write-Host "Database '$DatabaseName' already exists. It will NOT be dropped by this script." -ForegroundColor Yellow
    }
}
finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    $adminPassword = $null
    $adminPasswordSecure = $null
}
Write-Host ""
Write-Host "[5/9] Locating HCL.CS CA certificate..." -ForegroundColor Cyan
$originalHclCertificate = Join-Path $HclCsRoot ".windows\certificates\hcl-cs-local.pem"
$projectsRoot = Split-Path $RepoRoot -Parent
$sharedRootCa = Join-Path $projectsRoot "certificates\rootCA.pem"
if (Test-Path $originalHclCertificate) {
    $hclCertificate = $originalHclCertificate
}
elseif (Test-Path $sharedRootCa) {
    $hclCertificate = $sharedRootCa
}
else {
    throw "HCL.CS CA certificate was not found. Checked '$originalHclCertificate' and '$sharedRootCa'."
}
Write-Host "Using HCL.CS CA: $hclCertificate" -ForegroundColor Green
Write-Host ""
Write-Host "[6/9] Generating Windows SBOM environment configuration..." -ForegroundColor Cyan
$encodedPassword = [Uri]::EscapeDataString($databasePassword)
$databaseUrl = "postgresql+psycopg://$DatabaseUser`:$encodedPassword@$PostgresHost`:$PostgresPort/$DatabaseName"
$windowsDir = Join-Path $RepoRoot ".windows"
New-Item -ItemType Directory -Force -Path $windowsDir | Out-Null
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
    "if ([string]::IsNullOrWhiteSpace(`$env:NEXT_PUBLIC_API_URL)) { `$env:NEXT_PUBLIC_API_URL = 'http://localhost:8000' }",
    "`$env:NEXT_PUBLIC_APP_URL = 'https://localhost:3000'",
    "`$env:NEXT_PUBLIC_HCL_IAM_ISSUER = 'https://localhost:5180'",
    "`$env:NEXT_PUBLIC_HCL_IAM_CLIENT_ID = 'sbom-analyser-web'",
    "`$env:NEXT_PUBLIC_HCL_IAM_REDIRECT_URI = 'https://localhost:3000/auth/callback'",
    "`$env:NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI = 'https://localhost:3000'",
    "`$env:NEXT_PUBLIC_HCL_IAM_SCOPES = 'openid profile email offline_access sbom-analyser-api'",
    "if ([string]::IsNullOrWhiteSpace(`$env:SBOM_API_URL)) { `$env:SBOM_API_URL = 'http://localhost:8000' }"
)
$environmentFile = Join-Path $windowsDir "sbom.env.ps1"
Set-Content -Path $environmentFile -Value $envScript -Encoding UTF8
if (-not (Test-Path $environmentFile)) {
    throw "Failed to create $environmentFile."
}
Write-Host "Environment file created: $environmentFile" -ForegroundColor Green
$databasePassword = $null
$databasePasswordSecure = $null
Write-Host ""
Write-Host "[7/9] Configuring Python virtual environment..." -ForegroundColor Cyan
$venvPath = Join-Path $RepoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating .venv using $pythonLauncher..." -ForegroundColor Yellow
    & $pythonLauncher -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        throw "Python virtual environment creation failed."
    }
}
else {
    Write-Host "Existing .venv detected." -ForegroundColor Yellow
}
if (-not (Test-Path $venvPython)) {
    throw "Virtual environment Python executable was not created."
}
Write-Host "Virtual environment Python version:" -ForegroundColor Gray
& $venvPython --version
if ($LASTEXITCODE -ne 0) {
    throw "Unable to execute Python from .venv."
}
& $venvPython -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "The virtual environment uses Python older than 3.11. Delete .venv and rerun this script."
}
if (-not $SkipDependencyRestore) {
    Write-Host ""
    Write-Host "[8/9] Restoring dependencies..." -ForegroundColor Cyan
    Write-Host "Upgrading pip..." -ForegroundColor Gray
    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "pip upgrade failed."
    }
    Write-Host "Installing Python dependencies..." -ForegroundColor Gray
    $requirementsFile = Join-Path $RepoRoot "requirements.txt"
    if (-not (Test-Path $requirementsFile)) {
        throw "requirements.txt was not found at $requirementsFile."
    }
    & $venvPython -m pip install -r $requirementsFile
    if ($LASTEXITCODE -ne 0) {
        throw "Python dependency installation failed."
    }
    Write-Host "Installing frontend dependencies..." -ForegroundColor Gray
    $frontendDirectory = Join-Path $RepoRoot "frontend"
    if (-not (Test-Path (Join-Path $frontendDirectory "package.json"))) {
        throw "Frontend package.json was not found."
    }
    Push-Location $frontendDirectory
    try {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) {
            throw "Frontend npm install failed."
        }
    }
    finally {
        Pop-Location
    }
    Write-Host "Dependency restore completed." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "[8/9] Dependency restore skipped." -ForegroundColor Yellow
}
. $environmentFile
Write-Host ""
Write-Host "[9/9] Applying Alembic migrations..." -ForegroundColor Cyan
Push-Location $RepoRoot
try {
    Write-Host "[9/9] Preparing PostgreSQL schema..." -ForegroundColor Cyan
    $tableCountOutput = & $venvPython -c "import os; from sqlalchemy import create_engine; from scripts.bootstrap_fresh_database import existing_application_objects; e=create_engine(os.environ['DATABASE_URL']); c=e.connect(); print(len(existing_application_objects(c))); c.close(); e.dispose()"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect SBOM PostgreSQL database."
    }
    $applicationObjectCount = [int](([string]$tableCountOutput).Trim())
    if ($applicationObjectCount -eq 0) {
        Write-Host "Empty PostgreSQL database detected. Running canonical fresh bootstrap..." -ForegroundColor Yellow
        $bootstrapScript = Join-Path $RepoRoot "scripts\bootstrap_fresh_database.py"

        & $venvPython $bootstrapScript "--confirm-empty-database" $DatabaseName

        if ($LASTEXITCODE -ne 0) {
            throw "Fresh PostgreSQL bootstrap failed."
        }
    }
    else {
        Write-Host "Existing PostgreSQL database detected. Applying incremental Alembic migrations..." -ForegroundColor Yellow
        $previousBackfillIssuer = $env:SBOM_IDENTITY_BACKFILL_ISSUER
        try {
            $env:SBOM_IDENTITY_BACKFILL_ISSUER = $env:HCL_IAM_ISSUER
            & $venvPython -m alembic upgrade head
            if ($LASTEXITCODE -ne 0) {
                throw "Alembic migration failed."
            }
        }
        finally {
            if ([string]::IsNullOrWhiteSpace($previousBackfillIssuer)) {
                Remove-Item Env:SBOM_IDENTITY_BACKFILL_ISSUER -ErrorAction SilentlyContinue
            }
            else {
                $env:SBOM_IDENTITY_BACKFILL_ISSUER = $previousBackfillIssuer
            }
        }
    }
    & $venvPython -m alembic current
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify Alembic revision."
    }
}
finally {
    Pop-Location
}
Write-Host "Alembic migrations completed." -ForegroundColor Green
Write-Host ""
Write-Host "Configuring frontend HTTPS..." -ForegroundColor Cyan
$httpsSetupScript = Join-Path $RepoRoot "frontend\scripts\setup-dev-https.ps1"
if (-not (Test-Path $httpsSetupScript)) {
    throw "Frontend HTTPS setup script was not found at $httpsSetupScript."
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $httpsSetupScript
if ($LASTEXITCODE -ne 0) {
    throw "Frontend HTTPS setup failed."
}
Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " SBOM native Windows setup is complete." -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Python:" -ForegroundColor Cyan
& $venvPython --version
Write-Host ""
Write-Host "Database" -ForegroundColor Cyan
Write-Host "  Host : $PostgresHost"
Write-Host "  Port : $PostgresPort"
Write-Host "  DB   : $DatabaseName"
Write-Host "  User : $DatabaseUser"
Write-Host ""
Write-Host "HCL.CS" -ForegroundColor Cyan
Write-Host "  https://localhost:5180"
Write-Host ""
Write-Host "SBOM API" -ForegroundColor Cyan
Write-Host "  http://localhost:8000"
Write-Host ""
Write-Host "SBOM UI" -ForegroundColor Cyan
Write-Host "  https://localhost:3000"
Write-Host ""
Write-Host "Run the canonical daily command:" -ForegroundColor Yellow
Write-Host "  .\setup\windows\Start.ps1"
Write-Host ""
