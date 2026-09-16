<# Stops every component Start-SbomAll.ps1 starts: the API, the frontend and all
   three Celery processes.

   Stop-SbomLocal.ps1 only kills whatever listens on 3000/8000, which leaves Beat
   and both workers running -- they hold no port. This script matches on the
   command line instead, so nothing is missed.

   PostgreSQL, Mailpit and the HCL.CS auth server are deliberately left alone:
   they are shared infrastructure, not part of this stack. #>
[CmdletBinding()]
param(
    # Also stop whatever listens on 3000/8000 even if its command line did not
    # match -- e.g. a process started by hand rather than by Start-SbomAll.
    [switch]$IncludePorts
)

$ErrorActionPreference = "Stop"

# Matched against the full command line. 'next' covers the Next.js dev server and
# the worker children it spawns, which outlive their parent otherwise.
$patterns = @{
    'Celery Beat'             = ' beat '
    'Celery worker (default)' = 'hostname=default@'
    'Celery worker (reports)' = 'hostname=reports@'
    'SBOM API'                = 'uvicorn|app\.main:app'
    'SBOM frontend'           = 'next'
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$all = @(
    Get-CimInstance Win32_Process -Filter "Name like 'python%' or Name like 'celery%' or Name like 'node%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine }
)

# Scope every match to this checkout. Without it, 'next' also matches the Node
# processes Visual Studio hosts under devenv.exe, and this script would kill
# them. Celery qualifies on the app module instead: a worker's cwd is the repo
# but its command line need not name it.
$owned = @(
    $all | Where-Object {
        $_.CommandLine -match [regex]::Escape($RepoRoot) -or
        $_.CommandLine -match 'app\.workers\.celery_app'
    }
)

# Pull in descendants whose own command line does not name the repo. uvicorn
# --reload spawns its server in a child that runs the system python, and that
# child is what actually holds port 8000 -- miss it and the port stays in
# LISTENING under a dead parent pid, which is what makes a restart skip the API.
$ownedIds = [System.Collections.Generic.HashSet[UInt32]]::new()
foreach ($process in $owned) { [void]$ownedIds.Add($process.ProcessId) }
for ($pass = 0; $pass -lt 5; $pass++) {
    $added = $false
    foreach ($process in $all) {
        if ($ownedIds.Contains($process.ProcessId)) { continue }
        if ($ownedIds.Contains($process.ParentProcessId)) {
            [void]$ownedIds.Add($process.ProcessId)
            $added = $true
        }
    }
    if (-not $added) { break }
}
$candidates = @($all | Where-Object { $ownedIds.Contains($_.ProcessId) })

$stopped = 0
foreach ($label in $patterns.Keys | Sort-Object) {
    $pattern = $patterns[$label]
    $matches = @($candidates | Where-Object { $_.CommandLine -match $pattern })
    if (-not $matches) {
        Write-Host ("not running  {0}" -f $label) -ForegroundColor DarkGray
        continue
    }
    foreach ($process in $matches) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            Write-Host ("stopped      {0} (pid {1})" -f $label, $process.ProcessId) -ForegroundColor Green
            $stopped++
        }
        catch {
            # Already gone -- a parent shim often takes its children with it.
            Write-Host ("gone         {0} (pid {1})" -f $label, $process.ProcessId) -ForegroundColor DarkGray
        }
    }
}

if ($IncludePorts) {
    foreach ($port in 3000, 8000) {
        $connection = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $connection) { continue }
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if (-not $process) { continue }
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Host ("stopped      port {0} ({1}, pid {2})" -f $port, $process.ProcessName, $process.Id) -ForegroundColor Green
            $stopped++
        }
        catch {
            Write-Host ("could not stop port {0}: {1}" -f $port, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host ("Stopped {0} process(es)." -f $stopped)
Write-Host "PostgreSQL, Mailpit and the HCL.CS auth server were not touched." -ForegroundColor Cyan
