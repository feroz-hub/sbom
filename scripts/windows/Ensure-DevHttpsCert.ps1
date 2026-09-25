<#
.SYNOPSIS
    Ensure a trusted localhost certificate exists for the frontend HTTPS dev
    server, creating and trusting one if necessary.

.DESCRIPTION
    `npm run dev:https` expects frontend/certificates/localhost.pem and
    localhost-key.pem. The OIDC redirect URI is https://localhost:3000/auth/
    callback, so the browser must trust the certificate or the sign-in round
    trip breaks on a warning interstitial.

    setup-dev-https.ps1 already does this with mkcert, but it installs mkcert
    through winget, whose UAC prompt cannot surface in a non-interactive shell
    (it auto-denies with exit 1602). This script prefers mkcert when it is
    present and falls back to generating the certificate directly, so a fresh
    checkout can get to HTTPS without an interactive install.

    Idempotent: with a valid, trusted certificate already in place it does
    nothing.

.PARAMETER Force
    Regenerate even when a valid certificate exists.

.NOTES
    The fallback adds the certificate to the CurrentUser Trusted Root store —
    the same thing `mkcert -install` does, scoped to this user, no admin
    needed. Remove it with:
        Get-ChildItem Cert:\CurrentUser\Root |
            Where-Object { $_.Subject -eq 'CN=localhost, O=SBOM Analyzer local dev' } |
            Remove-Item
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$certDir  = Join-Path $repoRoot 'frontend\certificates'
$certPath = Join-Path $certDir 'localhost.pem'
$keyPath  = Join-Path $certDir 'localhost-key.pem'
$subject  = 'CN=localhost, O=SBOM Analyzer local dev'

New-Item -ItemType Directory -Force $certDir | Out-Null

function Test-CertUsable {
    if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) { return $false }
    try {
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    } catch {
        Write-Host '  existing certificate is unreadable; regenerating' -ForegroundColor Yellow
        return $false
    }
    # A certificate expiring within a week is replaced now rather than midway
    # through someone's session.
    if ($c.NotAfter -lt (Get-Date).AddDays(7)) {
        Write-Host "  existing certificate expires $($c.NotAfter.ToString('yyyy-MM-dd')); regenerating" -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Add-ToUserTrustStore([string]$path) {
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
    $already = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $c.Thumbprint }
    if ($already) {
        Write-Host "  already trusted (thumbprint $($c.Thumbprint))" -ForegroundColor DarkGray
        return
    }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $store.Open('ReadWrite'); $store.Add($c); $store.Close()
    Write-Host "  trusted in CurrentUser\Root (thumbprint $($c.Thumbprint))" -ForegroundColor Green
}

function New-CertWithMkcert {
    $mkcert = Get-Command mkcert.exe -ErrorAction SilentlyContinue
    if (-not $mkcert) { return $false }
    Write-Host '  generating with mkcert' -ForegroundColor Cyan
    & $mkcert.Source -install | Out-Null
    & $mkcert.Source -cert-file $certPath -key-file $keyPath localhost 127.0.0.1 ::1 | Out-Null
    return ($LASTEXITCODE -eq 0 -and (Test-Path $certPath) -and (Test-Path $keyPath))
}

function New-CertWithPython {
    # Uses the backend virtualenv, which already ships `cryptography`. Only
    # reached when mkcert is unavailable.
    $py = Join-Path $repoRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path $py)) {
        throw "mkcert is not installed and $py does not exist. Install mkcert (winget install FiloSottile.mkcert) or create the virtualenv, then rerun."
    }
    Write-Host '  mkcert not found; generating with the project virtualenv' -ForegroundColor Cyan
    $script = @'
import datetime, ipaddress, pathlib, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

cert_path, key_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SBOM Analyzer local dev"),
])
now = datetime.datetime.now(datetime.UTC)
cert = (
    x509.CertificateBuilder()
    .subject_name(name).issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=825))
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]), critical=False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]), critical=False)
    .sign(key, hashes.SHA256())
)
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
'@
    $tmp = Join-Path $env:TEMP "sbom-devcert-$PID.py"
    Set-Content -Path $tmp -Value $script -Encoding utf8
    try {
        & $py $tmp $certPath $keyPath
        if ($LASTEXITCODE -ne 0) { throw 'certificate generation failed.' }
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
    return $true
}

Write-Host 'Frontend HTTPS certificate' -ForegroundColor White

if (-not $Force -and (Test-CertUsable)) {
    Write-Host '  present and valid' -ForegroundColor DarkGray
} else {
    if (-not (New-CertWithMkcert)) { [void](New-CertWithPython) }
    Write-Host "  written to $certDir" -ForegroundColor Green
}

Add-ToUserTrustStore $certPath
