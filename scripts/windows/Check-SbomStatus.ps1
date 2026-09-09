<# Shows what parts of the local SBOM + HCL.CS stack are running. #>
[CmdletBinding()]
param()

$services = @(
    @{ Port = 5001; Name = 'HCL.CS auth server'; Url = 'https://localhost:5001' },
    @{ Port = 8000; Name = 'SBOM API';           Url = 'http://localhost:8000'  },
    @{ Port = 3000; Name = 'SBOM frontend';      Url = 'https://localhost:3000' },
    @{ Port = 5432; Name = 'PostgreSQL';         Url = 'localhost:5432'         }
)

foreach ($s in $services) {
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
$celery = Get-CimInstance Win32_Process -Filter "Name like 'python%' or Name like 'celery%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'app\.workers\.celery_app' }
foreach ($c in @(
        @{ Label = 'Celery worker (default)'; Pattern = 'hostname=default@' },
        @{ Label = 'Celery worker (reports)'; Pattern = 'hostname=reports@' },
        @{ Label = 'Celery Beat';             Pattern = ' beat ' }
    )) {
    if ($celery | Where-Object { $_.CommandLine -match $c.Pattern }) {
        Write-Host ("{0,-24}: RUNNING" -f $c.Label) -ForegroundColor Green
    }
    else {
        Write-Host ("{0,-24}: DOWN" -f $c.Label) -ForegroundColor Red
    }
}

Write-Host ""
Get-Service 'MSSQL$SQLEXPRESS', postgresql* -ErrorAction SilentlyContinue | Format-Table Name, Status
