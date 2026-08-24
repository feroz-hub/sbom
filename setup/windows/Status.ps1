<#
    Canonical Windows status entry point. It reports SBOM services and external
    HCL IAM; it never starts or stops anything.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$FrontendRoot = Join-Path $RepoRoot "frontend"
$ModeFile = Join-Path $RepoRoot ".windows\setup-mode.json"
$FrontendPort = 3000
$statusFailed = $false

function Pass([string]$Message) { Write-Host "PASS $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "WARN $Message" -ForegroundColor Yellow }
function Fail-Line([string]$Message) { $script:statusFailed = $true; Write-Host "FAIL $Message" -ForegroundColor Red }
function Import-DotEnv([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or $trimmed -notmatch "^[A-Za-z_][A-Za-z0-9_]*\s*=") { continue }
        $pair = $trimmed -split "=", 2; $key = $pair[0].Trim(); $value = $pair[1].Trim()
        if (($value.StartsWith([char]34) -and $value.EndsWith([char]34)) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) { $value = $value.Substring(1, $value.Length - 2) }
        [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
}
function Get-DotEnvFileValue([string]$Path, [string]$Name, [string]$Default = "") {
    if (-not (Test-Path -LiteralPath $Path)) { return $Default }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or $trimmed -notmatch "^[A-Za-z_][A-Za-z0-9_]*\s*=") { continue }
        $pair = $trimmed -split "=", 2
        if ($pair[0].Trim() -ne $Name) { continue }
        $value = $pair[1].Trim()
        if (($value.StartsWith([char]34) -and $value.EndsWith([char]34)) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) { $value = $value.Substring(1, $value.Length - 2) }
        return $value
    }
    return $Default
}
function Env-Value([string]$Name, [string]$Default = "") {
    $value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}
function Read-Mode {
    if (-not (Test-Path -LiteralPath $ModeFile)) { return $null }
    try {
        $state = Get-Content -LiteralPath $ModeFile -Raw | ConvertFrom-Json
        if ([int]$state.version -ne 1 -or [string]$state.mode -notin @("docker", "native")) { return $null }
        return [string]$state.mode
    }
    catch { return $null }
}
function Port-Status([int]$Port, [string]$Name) {
    $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($connection) { Pass ("{0,-10} port {1} listening (PID {2})" -f $Name, $Port, $connection.OwningProcess) }
    else { Fail-Line ("{0,-10} port {1} is not listening" -f $Name, $Port) }
}
function Url-Status([string]$Url, [string]$Name, [bool]$Required, [bool]$AllowLocalInsecure, [string]$CaBundle = "") {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    $reachable = $false
    if ($curl) {
        $args = @("--fail", "--silent", "--show-error", "--max-time", "5")
        if ($AllowLocalInsecure) { $args += "--insecure" }
        if (-not [string]::IsNullOrWhiteSpace($CaBundle)) { $args += @("--cacert", $CaBundle) }
        & $curl.Source @args $Url | Out-Null
        $reachable = $LASTEXITCODE -eq 0
    }
    else {
        try { Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 | Out-Null; $reachable = $true } catch { $reachable = $false }
    }
    if ($reachable) { Pass "$Name $Url" }
    elseif ($Required) { Fail-Line "$Name unavailable: $Url" }
    else { Warn "$Name unreachable: $Url" }
}

Write-Host ""
Write-Host "SBOM Analyser Status" -ForegroundColor White
Write-Host "====================" -ForegroundColor White
$envPath = Join-Path $RepoRoot ".env"
$frontendEnvPath = Join-Path $FrontendRoot ".env.local"
if (Test-Path $envPath) { Pass "config     .env present" } else { Fail-Line "config     .env missing" }
if (Test-Path $frontendEnvPath) { Pass "config     frontend/.env.local present" } else { Fail-Line "config     frontend/.env.local missing" }
$mode = Read-Mode
if (-not $mode) { Fail-Line "config     setup mode missing or invalid; run Setup.ps1" }
Import-DotEnv $envPath
if ($mode -eq "native") {
    $nativeConfig = Join-Path $RepoRoot ".windows\sbom.env.ps1"
    if (Test-Path $nativeConfig) { . $nativeConfig } else { Fail-Line "config     native mode selected but .windows\sbom.env.ps1 is missing" }
}
$databaseOk = $false
if (Test-Path $VenvPython) {
    & $VenvPython -c "from app.db import engine; c=engine.connect(); c.close(); engine.dispose()" 2>$null
    $databaseOk = $LASTEXITCODE -eq 0
}
if ($databaseOk) { Pass "Database   PostgreSQL/database reachable" } else { Fail-Line "Database   database unavailable or .venv missing" }

$backendAuth = (Env-Value "AUTH_ENABLED" "false").ToLowerInvariant()
$frontendAuth = if ($mode -eq "native") { (Env-Value "NEXT_PUBLIC_AUTH_ENABLED" "false").ToLowerInvariant() } else { (Get-DotEnvFileValue $frontendEnvPath "NEXT_PUBLIC_AUTH_ENABLED" "false").ToLowerInvariant() }
if ($backendAuth -notin @("true", "false")) { Fail-Line "config     AUTH_ENABLED must be true or false" }
if ($frontendAuth -notin @("true", "false")) { Fail-Line "config     NEXT_PUBLIC_AUTH_ENABLED must be true or false" }
if ($backendAuth -ne $frontendAuth) { Fail-Line "config     authentication modes are inconsistent: AUTH_ENABLED=$backendAuth, NEXT_PUBLIC_AUTH_ENABLED=$frontendAuth" }

$portText = Env-Value "PORT" "8000"
$backendPort = 0
if ([int]::TryParse($portText, [ref]$backendPort) -and $backendPort -ge 1 -and $backendPort -le 65535) {
    Url-Status "http://localhost:$backendPort/health" "Backend" $true $false
    Port-Status $backendPort "Backend"
}
else { Fail-Line "Backend    invalid PORT: $portText" }
$frontendUrl = if ($frontendAuth -eq "true") { "https://localhost:$FrontendPort" } else { "http://localhost:$FrontendPort" }
Url-Status $frontendUrl "Frontend/admin" $true ($frontendAuth -eq "true")
Port-Status $FrontendPort "Frontend"

if ($backendAuth -eq "true") {
    $issuer = Env-Value "HCL_IAM_ISSUER"
    $discovery = Env-Value "HCL_IAM_DISCOVERY_URL"
    if ([string]::IsNullOrWhiteSpace($discovery)) { $discovery = $issuer.TrimEnd('/') + "/.well-known/openid-configuration" }
    $caBundle = Env-Value "HCL_IAM_CA_BUNDLE"
    if (-not [string]::IsNullOrWhiteSpace($caBundle) -and -not [IO.Path]::IsPathRooted($caBundle)) { $caBundle = Join-Path $RepoRoot $caBundle }
    if ([string]::IsNullOrWhiteSpace($issuer)) { Fail-Line "IAM        AUTH_ENABLED=true but HCL_IAM_ISSUER is empty" }
    elseif (-not [string]::IsNullOrWhiteSpace($caBundle) -and -not (Test-Path $caBundle)) { Fail-Line "IAM        HCL_IAM_CA_BUNDLE does not exist: $caBundle" }
    else { Url-Status $discovery "IAM (external)" $false $false $caBundle }
}
else { Warn "IAM        disabled for local development" }
Write-Host "INFO Admin      integrated into the same Next.js frontend; no separate SBOM Admin process" -ForegroundColor Gray
Write-Host "INFO HCL IAM    external to this repository; not started by status/start scripts" -ForegroundColor Gray
if ($statusFailed) { exit 1 } else { exit 0 }
