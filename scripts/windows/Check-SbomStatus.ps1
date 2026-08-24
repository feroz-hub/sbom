<# Shows what parts of the local SBOM + HCL.CS stack are running. #>
# Internal implementation script — setup/windows/Status.ps1 is the canonical health check.
[CmdletBinding()]
param()

function Get-DotEnvValue([string]$Path, [string]$Name, [string]$Default = '') {
    if (-not (Test-Path -LiteralPath $Path)) { return $Default }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#') -or $trimmed -notmatch '^[A-Za-z_][A-Za-z0-9_]*\s*=') { continue }
        $pair = $trimmed -split '=', 2
        if ($pair[0].Trim() -ne $Name) { continue }
        $value = $pair[1].Trim()
        if (($value.StartsWith([char]34) -and $value.EndsWith([char]34)) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        return $value
    }
    return $Default
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$envPath = Join-Path $repoRoot '.env'
$issuer = Get-DotEnvValue $envPath 'HCL_IAM_ISSUER'
$iamDiscovery = Get-DotEnvValue $envPath 'HCL_IAM_DISCOVERY_URL'
if ([string]::IsNullOrWhiteSpace($iamDiscovery) -and -not [string]::IsNullOrWhiteSpace($issuer)) {
    $iamDiscovery = $issuer.TrimEnd('/') + '/.well-known/openid-configuration'
}
$iamUri = $null
if (-not [string]::IsNullOrWhiteSpace($iamDiscovery)) { try { $iamUri = [Uri]$iamDiscovery } catch { } }
$backendPort = 8000
$portText = Get-DotEnvValue $envPath 'PORT' '8000'
if ($portText -as [int] -and [int]$portText -ge 1 -and [int]$portText -le 65535) { $backendPort = [int]$portText }
$services = @(
    @{ Port = if ($iamUri -and $iamUri.Port -gt 0) { $iamUri.Port } else { 0 }; Name = 'HCL.CS IAM server'; Url = $iamDiscovery },
    @{ Port = $backendPort; Name = 'SBOM API'; Url = "http://localhost:$backendPort" },
    @{ Port = 3000; Name = 'SBOM frontend'; Url = "https://localhost:3000" },
    @{ Port = 5432; Name = 'PostgreSQL'; Url = 'localhost:5432' }
)

foreach ($s in $services) {
    if ($s.Port -eq 0 -or [string]::IsNullOrWhiteSpace($s.Url)) {
        Write-Host ("IAM endpoint: NOT CONFIGURED (set HCL_IAM_ISSUER or HCL_IAM_DISCOVERY_URL in .env)") -ForegroundColor Yellow
        continue
    }
    $c = Get-NetTCPConnection -LocalPort $s.Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) {
        $n = try { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { 'unknown' }
        Write-Host ("Port {0} : RUNNING ({1,-24}) {2,-20} {3}" -f $s.Port, $n, $s.Name, $s.Url) -ForegroundColor Green
    }
    else {
        Write-Host ("Port {0} : DOWN    {1,-26} {2,-20}" -f $s.Port, '', $s.Name) -ForegroundColor Red
    }
}

Write-Host ""
Get-Service 'MSSQL$SQLEXPRESS', postgresql* -ErrorAction SilentlyContinue | Format-Table Name, Status
