$ErrorActionPreference = "Stop"
$ports = 3000, 8000
$connections = Get-NetTCPConnection -State Listen -LocalPort $ports -ErrorAction SilentlyContinue
$processIds = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
if ($processIds.Count -eq 0) {
    Write-Host "No SBOM native processes are listening on ports $($ports -join ', ')."
    exit 0
}
foreach ($processId in $processIds) {
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Stopping $($process.ProcessName) (PID $processId)"
        Stop-Process -Id $processId
    }
}
