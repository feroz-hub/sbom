<# Canonical Windows stop entry point. Stops only validated SBOM processes. #>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$StateFile = Join-Path $RepoRoot ".windows\sbom-processes.json"

function Fail([string]$Message) { throw $Message }
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
    [pscustomobject]@{ pid = $ProcessId; startTime = $creation; executable = $process.ExecutablePath; commandLine = $process.CommandLine }
}
function Test-RecordIdentity($Record) {
    try {
        if (-not $Record -or [int]$Record.pid -lt 1) { return $false }
        $actual = Get-ProcessMetadata ([int]$Record.pid)
        if (-not $actual) { return $false }
        if ($actual.startTime -ne [string]$Record.startTime) { return $false }
        if (-not ([string]$actual.executable).Equals([string]$Record.executable, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        return ([string]$actual.commandLine).IndexOf([string]$Record.commandMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    catch { return $false }
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
function Read-State {
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

if (-not (Test-Path -LiteralPath $StateFile)) {
    Write-Host "No SBOM processes tracked by setup/windows/Start.ps1."
    exit 0
}
$state = Read-State
$stopFailed = $false
foreach ($record in @($state.records)) {
    if (Test-RecordIdentity $record) {
        Write-Host "Stopping validated $($record.name) process (PID $($record.pid), run $($state.runId))"
        $stopped = Stop-ValidatedRecord $record
        if (-not $stopped -and (Test-RecordIdentity $record)) {
            $stopFailed = $true
            Write-Warning "Validated $($record.name) process did not stop; ownership state was preserved."
        }
    }
    else {
        Write-Warning "Ignoring stale or mismatched $($record.name) record (PID $($record.pid)); no process was terminated."
    }
}
if ($stopFailed) { Fail "One or more validated SBOM processes could not be stopped. Retry Stop.ps1; no unrelated process was terminated." }
Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
Write-Host "Stopped validated SBOM development processes. PostgreSQL and external HCL IAM were left running."
