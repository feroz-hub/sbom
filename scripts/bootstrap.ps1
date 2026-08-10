<#
.SYNOPSIS
    SBOM Analyzer — local-machine bootstrap (Windows).

.DESCRIPTION
    Installs the two prerequisites the project needs to run locally:
      * Python 3.11
      * Node.js 20
    Then creates the backend venv, installs Python deps, installs frontend
    deps, and copies the .env / .env.local templates if they are missing.

    Idempotent — safe to re-run. Every install step checks first; nothing
    is reinstalled if it already meets the required minimum version.

    Package manager: winget (preferred, ships with Windows 10 21H2+ and
    Windows 11). Falls back to Chocolatey if winget is missing; will
    install Chocolatey itself if neither is present.

.PARAMETER SkipSystem
    Skip the system package install step; only set up the venv and npm
    deps. Useful when Python and Node are already installed by other
    means (e.g. corporate image).

.EXAMPLE
    PS> .\scripts\bootstrap.ps1

.EXAMPLE
    PS> .\scripts\bootstrap.ps1 -SkipSystem

.NOTES
    Run from an *elevated* PowerShell session if you want system-level
    Python / Node installs. Per-user installs work without admin but
    your PATH may not include the new tools until you start a new shell.
#>

[CmdletBinding()]
param(
    [switch]$SkipSystem
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RequiredPythonMajor = 3
$RequiredPythonMinor = 11
$RequiredNodeMajor   = 20

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

# ── helpers ──────────────────────────────────────────────────────────────────

function Write-Step  { Write-Host "==> $args" -ForegroundColor Blue }
function Write-Ok    { Write-Host "✓ $args"   -ForegroundColor Green }
function Write-Warn2 { Write-Host "! $args"   -ForegroundColor Yellow }
function Write-Fail  { Write-Host "✗ $args"   -ForegroundColor Red; exit 1 }

function Test-Cmd([string]$Name) {
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Update-PathFromMachine {
    # Refresh PATH for the current session after an installer has updated
    # the user/machine env. Newly installed exes are otherwise invisible
    # until a new shell is opened.
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = ($machine, $user -join ';')
}

function Test-PythonOk {
    foreach ($cmd in @("python$RequiredPythonMajor.$RequiredPythonMinor", "python3", "python")) {
        if (-not (Test-Cmd $cmd)) { continue }
        try {
            & $cmd -c "import sys; sys.exit(0 if sys.version_info >= ($RequiredPythonMajor, $RequiredPythonMinor) else 1)"
            if ($LASTEXITCODE -eq 0) { return $cmd }
        } catch { }
    }
    return $null
}

function Test-NodeOk {
    if (-not (Test-Cmd 'node')) { return $false }
    try {
        $major = (& node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')
        return ([int]$major -ge $RequiredNodeMajor)
    } catch { return $false }
}

# ── package manager bootstrap ────────────────────────────────────────────────

function Get-PackageManager {
    if (Test-Cmd 'winget') { return 'winget' }
    if (Test-Cmd 'choco')  { return 'choco' }

    Write-Step "Neither winget nor Chocolatey found — installing Chocolatey"
    # Chocolatey's official bootstrap (https://chocolatey.org/install).
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = `
        [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(
        'https://community.chocolatey.org/install.ps1'))
    Update-PathFromMachine
    if (-not (Test-Cmd 'choco')) {
        Write-Fail "Chocolatey install failed. Install Python 3.11 + Node 20 manually and re-run with -SkipSystem."
    }
    return 'choco'
}

function Install-Python([string]$Pm) {
    Write-Step "Installing Python $RequiredPythonMajor.$RequiredPythonMinor via $Pm"
    switch ($Pm) {
        'winget' {
            # Python.Python.3.11 is the stable pinned ID on winget.
            & winget install --id "Python.Python.$RequiredPythonMajor.$RequiredPythonMinor" `
                --silent --accept-source-agreements --accept-package-agreements
        }
        'choco' {
            & choco install -y "python$RequiredPythonMajor$RequiredPythonMinor"
        }
    }
    Update-PathFromMachine
}

function Install-Node([string]$Pm) {
    Write-Step "Installing Node $RequiredNodeMajor via $Pm"
    switch ($Pm) {
        'winget' {
            # OpenJS.NodeJS.LTS tracks the current LTS line (20.x today).
            & winget install --id 'OpenJS.NodeJS.LTS' `
                --silent --accept-source-agreements --accept-package-agreements
        }
        'choco' {
            & choco install -y "nodejs-lts" --version="$RequiredNodeMajor.0.0" `
                --allow-downgrade
        }
    }
    Update-PathFromMachine
}

# ── steps ────────────────────────────────────────────────────────────────────

function Step-InstallSystemDeps {
    if ($SkipSystem) {
        Write-Step "-SkipSystem: not touching system packages"
        return
    }

    $pm = Get-PackageManager
    Write-Step "Detected package manager: $pm"

    $py = Test-PythonOk
    if ($py) {
        Write-Ok "Python already installed ($py)"
    } else {
        Install-Python $pm
        if (-not (Test-PythonOk)) {
            Write-Warn2 "Python not visible on PATH yet — open a new PowerShell and re-run with -SkipSystem if the venv step below fails."
        }
    }

    if (Test-NodeOk) {
        $v = (& node -v)
        Write-Ok "Node already installed ($v)"
    } else {
        Install-Node $pm
        if (-not (Test-NodeOk)) {
            Write-Warn2 "Node not visible on PATH yet — open a new PowerShell and re-run with -SkipSystem if needed."
        }
    }
}

function Step-SetupBackend {
    $py = Test-PythonOk
    if (-not $py) {
        Write-Fail "Python $RequiredPythonMajor.$RequiredPythonMinor+ not on PATH. Start a new PowerShell and re-run with -SkipSystem."
    }

    $venv = Join-Path $RepoRoot '.venv'
    if (-not (Test-Path $venv)) {
        Write-Step "Creating venv at $venv using $py"
        & $py -m venv $venv
    } else {
        Write-Ok "venv already exists"
    }

    $venvPython = Join-Path $venv 'Scripts\python.exe'
    Write-Step "Upgrading pip + installing backend deps"
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r (Join-Path $RepoRoot 'requirements.txt')

    $envFile     = Join-Path $RepoRoot '.env'
    $envExample  = Join-Path $RepoRoot '.env.example'
    if (-not (Test-Path $envFile) -and (Test-Path $envExample)) {
        Copy-Item $envExample $envFile
        Write-Ok "Copied .env.example -> .env  (edit it before running in production)"
    }
}

function Step-SetupFrontend {
    $frontend = Join-Path $RepoRoot 'frontend'
    if (-not (Test-Path $frontend)) {
        Write-Warn2 "frontend/ not found — skipping npm install"
        return
    }
    if (-not (Test-Cmd 'npm')) {
        Write-Fail "npm is not on PATH. Open a new PowerShell after Node install and re-run with -SkipSystem."
    }

    Write-Step "Installing frontend deps (npm ci)"
    Push-Location $frontend
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { Write-Fail "npm ci failed" }
    } finally {
        Pop-Location
    }

    $envLocal        = Join-Path $frontend '.env.local'
    $envLocalExample = Join-Path $frontend '.env.local.example'
    if (-not (Test-Path $envLocal) -and (Test-Path $envLocalExample)) {
        Copy-Item $envLocalExample $envLocal
        Write-Ok "Copied frontend/.env.local.example -> frontend/.env.local"
    }
}

# ── main ─────────────────────────────────────────────────────────────────────

Step-InstallSystemDeps
Step-SetupBackend
Step-SetupFrontend

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Bootstrap complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Start the backend:"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    python run.py                       # -> http://localhost:8000"
Write-Host ""
Write-Host "  Start the frontend (in another terminal):"
Write-Host "    cd frontend; npm run dev            # -> http://localhost:3000"
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Green
