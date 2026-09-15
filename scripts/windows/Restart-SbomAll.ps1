<# Stops the whole local stack, waits for its ports to come free, and starts it again.

   The wait is the point. Windows keeps 127.0.0.1:8000 in LISTENING for a while
   after uvicorn --reload exits, still attributed to the dead parent pid. Because
   Start-SbomAll.ps1 decides what to launch by probing the port, that stale entry
   makes it report "skipped SBOM API (port 8000 already listening)" and start only
   four of the five components. So: wait for the owning process to actually be
   gone, then verify the API answered, and launch it directly if it did not. #>
[CmdletBinding()]
param(
    [switch]$NoAuth,
    # How long to wait for a port's owning process to disappear.
    [int]$PortTimeoutSeconds = 30,
    # How long to wait for /health after starting.
    [int]$HealthTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# A listener whose owning pid is dead is stale: the port is usable even though
# Get-NetTCPConnection still reports it.
function Test-PortHeldByLiveProcess([int]$Port) {
    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $connection) { return $false }
    [bool](Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue)
}

Write-Host "== stopping ==" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'Stop-SbomAll.ps1')

Write-Host ""
Write-Host "== waiting for ports ==" -ForegroundColor Cyan
foreach ($port in 8000, 3000) {
    $deadline = (Get-Date).AddSeconds($PortTimeoutSeconds)
    while ((Test-PortHeldByLiveProcess $port) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    if (Test-PortHeldByLiveProcess $port) {
        Write-Host ("port {0} is still held by a live process after {1}s; start it by hand once that clears" -f $port, $PortTimeoutSeconds) -ForegroundColor Red
    }
    else {
        Write-Host ("port {0} free" -f $port) -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "== starting ==" -ForegroundColor Cyan
$startArgs = @{}
if ($NoAuth) { $startArgs['NoAuth'] = $true }
& (Join-Path $PSScriptRoot 'Start-SbomAll.ps1') @startArgs

# Start-SbomAll may have skipped the API on a stale listener. Only /health proves
# it is actually serving.
Write-Host ""
Write-Host "== waiting for the API ==" -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 200) { $healthy = $true; break }
    }
    catch { Start-Sleep -Seconds 2 }
}

if ($healthy) {
    Write-Host "API healthy (/health 200)" -ForegroundColor Green
}
else {
    Write-Host "API did not answer; launching it directly (Start-SbomAll skips a port it thinks is taken)" -ForegroundColor Yellow
    $apiScript = Join-Path $PSScriptRoot 'Start-SbomApi.ps1'
    $apiSwitch = if ($NoAuth) { '-NoAuth' } else { '' }
    $arguments = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command',
        "`$Host.UI.RawUI.WindowTitle = 'SBOM API (8000)'; & '$apiScript' $apiSwitch")
    Start-Process powershell -ArgumentList $arguments -WorkingDirectory $RepoRoot | Out-Null
}

Write-Host ""
& (Join-Path $PSScriptRoot 'Check-SbomStatus.ps1')
