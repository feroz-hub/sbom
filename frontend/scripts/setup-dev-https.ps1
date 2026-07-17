$ErrorActionPreference = "Stop"
$frontendRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$certificateDir = Join-Path $frontendRoot "certificates"
New-Item -ItemType Directory -Force $certificateDir | Out-Null

$mkcert = Get-Command mkcert.exe -ErrorAction SilentlyContinue
if (-not $mkcert) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw "mkcert is required. Install it manually or install winget, then run: winget install FiloSottile.mkcert"
    }
    & winget.exe install --exact --id FiloSottile.mkcert --silent --accept-source-agreements --accept-package-agreements
    $mkcert = Get-Command mkcert.exe -ErrorAction SilentlyContinue
    if (-not $mkcert) { throw "mkcert was installed but is not yet on PATH. Open a new PowerShell and rerun this script." }
}

& $mkcert.Source -install
if ($LASTEXITCODE -ne 0) { throw "mkcert trust installation failed." }
& $mkcert.Source -cert-file (Join-Path $certificateDir "localhost.pem") `
    -key-file (Join-Path $certificateDir "localhost-key.pem") localhost 127.0.0.1 ::1
if ($LASTEXITCODE -ne 0) { throw "mkcert certificate generation failed." }
Write-Host "Trusted SBOM frontend certificate created in $certificateDir" -ForegroundColor Green
