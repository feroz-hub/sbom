<#
Internal compatibility wrapper. The canonical stop command owns process
identity validation; this legacy command delegates to it instead of stopping
whatever happens to be listening on a well-known port.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$canonical = Join-Path $PSScriptRoot "..\..\setup\windows\Stop.ps1"
if (-not (Test-Path -LiteralPath $canonical)) {
    throw "Canonical stop script was not found at $canonical."
}
& $canonical
exit 0
