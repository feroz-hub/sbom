<#
.SYNOPSIS
    Canonical daily startup for the Windows SBOM Analyser services.

    Internal implementation scripts are normally invoked through this
    setup/... entry point. Only processes launched by this run are tracked.
#>
[CmdletBinding()]
param([switch]$NoAuth)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$FrontendRoot = Join-Path $RepoRoot "frontend"
$StateDir = Join-Path $RepoRoot ".windows"
$StateFile = Join-Path $StateDir "sbom-processes.json"
$ModeFile = Join-Path $StateDir "setup-mode.json"
$LogDir = Join-Path $StateDir "logs"
$FrontendPort = 3000

function Fail([string]$Message) { throw $Message }
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
function Read-SetupMode {
    if (-not (Test-Path -LiteralPath $ModeFile)) { Fail "Setup mode is missing. Run .\setup\windows\Setup.ps1 first." }
    try {
        $state = Get-Content -LiteralPath $ModeFile -Raw | ConvertFrom-Json
        $version = [int]$state.version
        $mode = [string]$state.mode
        if ($version -ne 1 -or $mode -notin @("docker", "native")) { throw "invalid mode" }
        return $mode
    }
    catch { Fail "Setup mode is malformed or invalid. Run .\setup\windows\Setup.ps1 again." }
}
function Get-ProcessMetadata([int]$ProcessId) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if (-not $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath) -or [string]::IsNullOrWhiteSpace($process.CommandLine)) { return $null }
    $creationValue = $process.CreationDate
    if ($creationValue -is [DateTime]) {
        $creation = $creationValue.ToUniversalTime().ToString("o")
    }
    elseif ($creationValue -is [string] -and $creationValue -match '^\d{14}\.\d{6}[+-]\d{3}$') {
        $creation = [System.Management.ManagementDateTimeConverter]::ToDateTime($creationValue).ToUniversalTime().ToString("o")
    }
    else { return $null }
    [pscustomobject]@{
        pid = $ProcessId
        startTime = $creation
        executable = $process.ExecutablePath
        commandLine = $process.CommandLine
    }
}
function Test-RecordIdentity($Record) {
    if (-not $Record -or [int]$Record.pid -lt 1) { return $false }
    $actual = Get-ProcessMetadata ([int]$Record.pid)
    if (-not $actual) { return $false }
    if ($actual.startTime -ne [string]$Record.startTime) { return $false }
    if (-not ([string]$actual.executable).Equals([string]$Record.executable, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    return ([string]$actual.commandLine).IndexOf([string]$Record.commandMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0
}
function Get-ChildProcesses([int]$ProcessId) {
    @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue)
}
function Stop-ProcessTree([int]$ProcessId, [switch]$Force) {
    foreach ($child in Get-ChildProcesses $ProcessId) { Stop-ProcessTree ([int]$child.ProcessId) -Force:$Force }
    if ($Force) {
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        return
    }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process) { return }
    $closeRequested = $false
    try { $closeRequested = $process.CloseMainWindow() } catch { $closeRequested = $false }
    if (-not $closeRequested) { Stop-Process -Id $ProcessId -ErrorAction SilentlyContinue }
}
function Stop-ValidatedRecord($Record) {
    if (-not (Test-RecordIdentity $Record)) { return $true }
    Stop-ProcessTree ([int]$Record.pid)
    for ($waited = 0; $waited -lt 10; $waited++) {
        if (-not (Test-RecordIdentity $Record)) { return $true }
        Start-Sleep -Seconds 1
    }
    if (Test-RecordIdentity $Record) { Stop-ProcessTree ([int]$Record.pid) -Force }
    for ($waited = 0; $waited -lt 5; $waited++) {
        if (-not (Test-RecordIdentity $Record)) { return $true }
        Start-Sleep -Seconds 1
    }
    return (-not (Test-RecordIdentity $Record))
}
function Write-State($RunId, $Records) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $payload = [pscustomobject]@{ version = 1; runId = $RunId; createdAt = [DateTime]::UtcNow.ToString("o"); records = @($Records) }
    $temporary = "$StateFile.$PID.tmp"
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StateFile -Force
}
function New-ValidatedRecord([string]$Name, $Process, [string]$CommandMarker) {
    $metadata = $null
    for ($attempt = 0; $attempt -lt 10 -and -not $metadata; $attempt++) {
        $metadata = Get-ProcessMetadata ([int]$Process.Id)
        if (-not $metadata) { Start-Sleep -Milliseconds 100 }
    }
    if (-not $metadata) { Fail "Unable to capture $Name process ownership metadata. Check startup logs." }
    $record = [pscustomobject]@{
        name = $Name
        pid = $metadata.pid
        startTime = $metadata.startTime
        executable = $metadata.executable
        commandMarker = $CommandMarker
    }
    if (-not (Test-RecordIdentity $record)) { Fail "$Name process identity did not match the launched command. Check startup logs." }
    return $record
}
function Get-LaunchedProcessRecord([string]$Name, $Process) {
    try {
        if (-not $Process -or $Process.HasExited) { return $null }
        $metadata = Get-ProcessMetadata ([int]$Process.Id)
        if (-not $metadata) { return $null }
        $launchedStart = $Process.StartTime.ToUniversalTime().ToString("o")
        $launchedExecutable = $Process.MainModule.FileName
        if ($metadata.startTime -ne $launchedStart) { return $null }
        if (-not ([string]$metadata.executable).Equals([string]$launchedExecutable, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        # This fallback is used only during launch failure cleanup. The Process
        # object, start time, executable, and complete command line identify the
        # exact process instance returned by Start-Process.
        return [pscustomobject]@{
            name = $Name
            pid = $metadata.pid
            startTime = $metadata.startTime
            executable = $metadata.executable
            commandMarker = $metadata.commandLine
        }
    }
    catch { return $null }
}
function Stop-TrackedRecords($RunId, $Records) {
    $remaining = @()
    foreach ($record in @($Records)) {
        if (-not $record) { continue }
        $stopped = Stop-ValidatedRecord $record
        if (-not $stopped -and (Test-RecordIdentity $record)) { $remaining += $record }
    }
    if ($remaining.Count -gt 0) {
        Write-State $RunId $remaining
        return $false
    }
    Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$StateFile.$PID.tmp" -Force -ErrorAction SilentlyContinue
    return $true
}
function Read-State {
    if (-not (Test-Path -LiteralPath $StateFile)) { return $null }
    try {
        $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        $version = [int]$state.version
        $runId = [string]$state.runId
        $records = @($state.records)
        if ($version -ne 1 -or [string]::IsNullOrWhiteSpace($runId) -or $records.Count -eq 0) { throw "invalid state" }
        foreach ($record in $records) {
            if ([int]$record.pid -lt 1 -or [string]::IsNullOrWhiteSpace([string]$record.startTime) -or [string]::IsNullOrWhiteSpace([string]$record.executable) -or [string]::IsNullOrWhiteSpace([string]$record.commandMarker)) { throw "invalid record" }
        }
        return [pscustomobject]@{ runId = $runId; records = $records }
    }
    catch { Fail "SBOM process state is malformed or invalid. It was preserved: $StateFile" }
}
function Port-Owner([int]$Port) {
    @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1)
}
function Test-Url([string]$Url, [switch]$AllowLocalInsecure) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $args = @("--fail", "--silent", "--show-error", "--max-time", "3")
        if ($AllowLocalInsecure) { $args += "--insecure" }
        & $curl.Source @args $Url | Out-Null
        return $LASTEXITCODE -eq 0
    }
    try { Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null; return $true } catch { return $false }
}
function Test-ComposeDatabase([string]$DatabaseUrl) {
    $expectedPort = Env-Value "POSTGRES_PORT" "55439"
    $env:DATABASE_URL = $DatabaseUrl
    $env:EXPECTED_POSTGRES_PORT = $expectedPort
    $result = & $VenvPython -c "import os; from sqlalchemy.engine import make_url; u=make_url(os.environ['DATABASE_URL']); print('true' if u.get_backend_name().startswith('postgresql') and (u.host or 'localhost') in {'localhost','127.0.0.1','::1'} and (u.port or 5432) == int(os.environ['EXPECTED_POSTGRES_PORT']) and (u.database or '') == 'sbom_analyser' and (u.username or '') == 'sbom' and (u.password or '') == 'sbom' else 'false')" 2>$null
    return ([string]$result).Trim() -eq "true"
}

$mode = Read-SetupMode
if (-not (Test-Path $VenvPython)) { Fail "Missing .venv. Run .\setup\windows\Setup.ps1 first." }
if (-not (Test-Path (Join-Path $FrontendRoot "package.json"))) { Fail "Missing frontend/package.json." }
if (-not (Test-Path (Join-Path $RepoRoot ".env"))) { Fail "Missing .env. Run .\setup\windows\Setup.ps1 first." }
if (-not (Test-Path (Join-Path $FrontendRoot ".env.local"))) { Fail "Missing frontend/.env.local. Run .\setup\windows\Setup.ps1 first." }
Import-DotEnv (Join-Path $RepoRoot ".env")
$nativeConfig = Join-Path $RepoRoot ".windows\sbom.env.ps1"
if ($mode -eq "native") {
    if (-not (Test-Path $nativeConfig)) { Fail "Native setup mode is selected but .windows\sbom.env.ps1 is missing. Run Setup.ps1 again." }
    . $nativeConfig
}
if ($NoAuth) {
    $env:AUTH_ENABLED = "false"; $env:DEV_DEFAULT_TENANT = "true"; $env:NEXT_PUBLIC_AUTH_ENABLED = "false"
}
$backendAuth = (Env-Value "AUTH_ENABLED" "false").ToLowerInvariant()
$frontendAuth = if ($mode -eq "native" -or $NoAuth) { (Env-Value "NEXT_PUBLIC_AUTH_ENABLED" "false").ToLowerInvariant() } else { (Get-DotEnvFileValue (Join-Path $FrontendRoot ".env.local") "NEXT_PUBLIC_AUTH_ENABLED" "false").ToLowerInvariant() }
if (-not $NoAuth -and $backendAuth -ne $frontendAuth) { Fail "Authentication configuration is inconsistent: AUTH_ENABLED=$backendAuth, NEXT_PUBLIC_AUTH_ENABLED=$frontendAuth. Update both files explicitly." }
if (($backendAuth -notin @("true", "false")) -or ($frontendAuth -notin @("true", "false"))) { Fail "AUTH_ENABLED and NEXT_PUBLIC_AUTH_ENABLED must each be true or false." }
$databaseUrl = Env-Value "DATABASE_URL"
if ([string]::IsNullOrWhiteSpace($databaseUrl)) { Fail "DATABASE_URL is missing in .env." }
if ($mode -eq "docker" -and (Test-ComposeDatabase $databaseUrl)) {
    $dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $dockerCommand -or -not ((& $dockerCommand.Source compose version 2>$null) -match "Docker Compose")) {
        Fail "DATABASE_URL selects the repository-managed PostgreSQL service, but Docker Compose is unavailable. Run Setup.ps1 after starting Docker Desktop."
    }
    Push-Location $RepoRoot
    try { & $dockerCommand.Source compose up -d postgres; if ($LASTEXITCODE -ne 0) { Fail "Configured repository PostgreSQL could not be started." } } finally { Pop-Location }
}
$databaseReady = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    & $VenvPython -c "from app.db import engine; c=engine.connect(); c.close(); engine.dispose()" 2>$null
    if ($LASTEXITCODE -eq 0) { $databaseReady = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $databaseReady) { Fail "Database is not reachable after 30 seconds. Run .\setup\windows\Status.ps1 for diagnostics." }
$portText = Env-Value "PORT" "8000"
$backendPort = 0
if (-not [int]::TryParse($portText, [ref]$backendPort) -or $backendPort -lt 1 -or $backendPort -gt 65535) { Fail "PORT must be a valid TCP port in .env." }
$env:NEXT_PUBLIC_API_URL = "http://localhost:$backendPort"
$env:SBOM_API_URL = "http://localhost:$backendPort"
if (Port-Owner $backendPort) { Fail "Port $backendPort is already in use. Stop the existing SBOM API before starting again." }
if (Port-Owner $FrontendPort) { Fail "Port $FrontendPort is already in use. Stop the existing SBOM frontend before starting again." }
$useHttps = $frontendAuth -eq "true"
$frontendUrl = if ($useHttps) { "https://localhost:$FrontendPort" } else { "http://localhost:$FrontendPort" }
if ($useHttps -and (-not (Test-Path (Join-Path $FrontendRoot "certificates\localhost.pem")) -or -not (Test-Path (Join-Path $FrontendRoot "certificates\localhost-key.pem")))) { Fail "Authenticated mode requires both frontend HTTPS certificate files. Run Setup.ps1." }

$existing = Read-State
if ($existing) {
    $active = $false
    foreach ($record in @($existing.records)) {
        if (Test-RecordIdentity $record) { $active = $true; Write-Host "SBOM process $($record.name) is already running (PID $($record.pid))." }
    }
    if ($active) { Fail "A tracked SBOM development run is already active." }
    Remove-Item -LiteralPath $StateFile -Force
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$runId = [Guid]::NewGuid().ToString("N")
$apiProcess = $null
$frontendProcess = $null
$apiRecord = $null
$frontRecord = $null
$apiMarker = ""
$frontendMarker = ""
try {
    $apiScript = Join-Path $RepoRoot "scripts\windows\Start-SbomApi.ps1"
    $frontendScript = Join-Path $RepoRoot "scripts\windows\Start-SbomFrontend.ps1"
    if ($mode -eq "native") {
        $apiArgPath = '"' + $apiScript.Replace('"', '\"') + '"'
        $frontArgPath = '"' + $frontendScript.Replace('"', '\"') + '"'
        $apiArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $apiArgPath); if ($NoAuth) { $apiArgs += "-NoAuth" }
        $frontArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $frontArgPath); if ($NoAuth) { $frontArgs += "-NoAuth" }
        $apiMarker = "Start-SbomApi.ps1"
        $apiProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $apiArgs -WorkingDirectory $RepoRoot -RedirectStandardOutput (Join-Path $LogDir "backend-console.log") -RedirectStandardError (Join-Path $LogDir "backend-console.err.log") -PassThru
        $apiRecord = New-ValidatedRecord "backend" $apiProcess $apiMarker
        Write-State $runId @($apiRecord)
        $frontendMarker = "Start-SbomFrontend.ps1"
        $frontendProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $frontArgs -WorkingDirectory $RepoRoot -RedirectStandardOutput (Join-Path $LogDir "frontend-console.log") -RedirectStandardError (Join-Path $LogDir "frontend-console.err.log") -PassThru
        $frontRecord = New-ValidatedRecord "frontend" $frontendProcess $frontendMarker
    }
    else {
        $apiMarker = "-m uvicorn app.main:app"
        $apiProcess = Start-Process -FilePath $VenvPython -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", (Env-Value "HOST" "127.0.0.1"), "--port", [string]$backendPort, "--reload") -WorkingDirectory $RepoRoot -RedirectStandardOutput (Join-Path $LogDir "backend-console.log") -RedirectStandardError (Join-Path $LogDir "backend-console.err.log") -PassThru
        $apiRecord = New-ValidatedRecord "backend" $apiProcess $apiMarker
        Write-State $runId @($apiRecord)
        $npmCommand = (Get-Command npm.cmd -ErrorAction Stop).Source
        $frontendCommand = if ($useHttps) { "dev:https" } else { "dev" }
        # npm.cmd normally produces a cmd.exe or node/npm-cli.js command line.
        # "run <script>" is the stable marker shared by those launch forms.
        $frontendMarker = "run $frontendCommand"
        $frontendProcess = Start-Process -FilePath $npmCommand -ArgumentList @("run", $frontendCommand) -WorkingDirectory $FrontendRoot -RedirectStandardOutput (Join-Path $LogDir "frontend-console.log") -RedirectStandardError (Join-Path $LogDir "frontend-console.err.log") -PassThru
        $frontRecord = New-ValidatedRecord "frontend" $frontendProcess $frontendMarker
    }
    Write-State $runId @($apiRecord, $frontRecord)
}
catch {
    $startupError = $_.Exception.Message
    if (-not $frontRecord -and $frontendProcess -and $frontendMarker) {
        $candidate = Get-ProcessMetadata ([int]$frontendProcess.Id)
        if ($candidate) {
            $candidateRecord = [pscustomobject]@{ name = "frontend"; pid = $candidate.pid; startTime = $candidate.startTime; executable = $candidate.executable; commandMarker = $frontendMarker }
            if (Test-RecordIdentity $candidateRecord) { $frontRecord = $candidateRecord }
        }
        if (-not $frontRecord) { $frontRecord = Get-LaunchedProcessRecord "frontend" $frontendProcess }
    }
    if (-not $apiRecord -and $apiProcess -and $apiMarker) {
        $candidate = Get-ProcessMetadata ([int]$apiProcess.Id)
        if ($candidate) {
            $candidateRecord = [pscustomobject]@{ name = "backend"; pid = $candidate.pid; startTime = $candidate.startTime; executable = $candidate.executable; commandMarker = $apiMarker }
            if (Test-RecordIdentity $candidateRecord) { $apiRecord = $candidateRecord }
        }
        if (-not $apiRecord) { $apiRecord = Get-LaunchedProcessRecord "backend" $apiProcess }
    }
    $cleaned = Stop-TrackedRecords $runId @($frontRecord, $apiRecord)
    if (-not $cleaned) { Fail "Startup failed and one or more validated processes could not be stopped. Ownership state was preserved in $StateFile. Original error: $startupError" }
    throw $startupError
}

$ready = $false
for ($attempt = 1; $attempt -le 60; $attempt++) {
    $state = Read-State
    $apiRecord = @($state.records | Where-Object { $_.name -eq "backend" })[0]
    $frontRecord = @($state.records | Where-Object { $_.name -eq "frontend" })[0]
    if (-not (Test-RecordIdentity $apiRecord)) {
        $cleaned = Stop-TrackedRecords $runId @($frontRecord, $apiRecord)
        if (-not $cleaned) { Fail "Backend exited during startup and cleanup was incomplete; ownership state was preserved in $StateFile." }
        Fail "Backend exited during startup; inspect .windows/logs/backend-console.err.log."
    }
    if (-not (Test-RecordIdentity $frontRecord)) {
        $cleaned = Stop-TrackedRecords $runId @($frontRecord, $apiRecord)
        if (-not $cleaned) { Fail "Frontend exited during startup and cleanup was incomplete; ownership state was preserved in $StateFile." }
        Fail "Frontend exited during startup; inspect .windows/logs/frontend-console.err.log."
    }
    $apiReady = Test-Url "http://localhost:$backendPort/health"
    $frontReady = if ($useHttps) { Test-Url $frontendUrl -AllowLocalInsecure } else { Test-Url $frontendUrl }
    if ($apiReady -and $frontReady) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    $state = Read-State
    $cleaned = Stop-TrackedRecords $runId @($state.records)
    if (-not $cleaned) { Fail "SBOM services did not become ready and cleanup was incomplete; ownership state was preserved in $StateFile." }
    Fail "SBOM services did not become ready within 60 seconds. Inspect .windows/logs/*.log."
}

Write-Host ""
Write-Host "SBOM Analyser Startup" -ForegroundColor White
Write-Host "---------------------" -ForegroundColor White
Write-Host ("IAM        : {0}" -f ($(if ($backendAuth -eq "true") { "EXTERNAL" } else { "DISABLED" })))
Write-Host "Database   : READY"
Write-Host ("Backend    : READY (http://localhost:{0})" -f $backendPort)
Write-Host ("Frontend   : READY ({0})" -f $frontendUrl)
Write-Host "Admin      : integrated in the frontend (same URL)"
Write-Host "HCL IAM    : external dependency; this script does not start Security Framework"
