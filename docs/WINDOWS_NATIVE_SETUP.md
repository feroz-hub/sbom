# Windows / HCL.CS local development


“Native Windows” means host installation, not the Native IAM identity provider.
The PostgreSQL-backed HCL.CS build (historically port 5180) and SF.8 SQL Server
build (historically port 5001) are different provider integrations; neither guide
replaces the other. Do not mix their provider/database procedures. Historical
Windows verification does not establish acceptance of the current launcher.
Apply the [database gate](DATABASE_BOOTSTRAP_AND_UPGRADE.md) before any SBOM setup
or upgrade: fresh targets must be empty; populated pre-UUID targets must not cross
revision 100. External HCL.CS provisioning stays in its own repository/operator
procedure, with separate roles/databases and explicitly approved certificate trust.

The sole manager is scripts/dev.py. Install Python 3.11+, Node.js 20.9+ with npm,
Docker Desktop where required, and explicitly approved HTTPS trust. Open a new
PowerShell terminal at the repository root:

```powershell
python scripts/dev.py doctor --profile legacy --legacy-config windows
python scripts/dev.py setup --profile legacy --legacy-config windows
python scripts/dev.py --profile legacy --legacy-config windows
python scripts/dev.py status --profile legacy
python scripts/dev.py logs --service reports --profile legacy
python scripts/dev.py stop --profile legacy
python scripts/dev.py restart --profile legacy
```

Existing .windows/sbom.env.ps1 is preserved and read as literal
$env:NAME = 'value' assignments. Nonliteral code is rejected. Saved local database,
credentials, Redis broker, ports, authentication and provider CA/redirect settings
remain authoritative. Missing API/frontend ports default to 8000/3000.
Managed Legacy and Greenfield remain separate.

Keep the foreground terminal open. The launcher manages the default worker,
reports worker, separate Beat, API and HTTPS frontend. Windows workers use solo.
Verified process birth identity and descendant checks protect unrelated processes;
occupied ports never authorize termination.

BAT/PowerShell managers and trust-install scripts are removed. Use canonical setup
for project dependencies/leaf certificates. Root trust, external HCL.CS service,
registered redirects, provider CA bundles and initial administrators remain explicit
operator prerequisites. TLS verification is never disabled. Database initialization/
upgrade needs explicit controls in the [bootstrap guide](../scripts/BOOTSTRAP.md).

Native Windows and browser authentication were unavailable. Mocked adapters do not
establish Windows acceptance. Pending Greenfield migration backup/restore remains
blocked on Windows. See [platform evidence](engineering/dev-launcher-platform-matrix.md)
and [HCL settings](HCL_IAM_CONFIGURATION.md).

After validated HCL.CS login, SBOM resolves identity by issuer and immutable subject.
Grant local tenant membership/roles through authorized SBOM administration; a token
claim cannot grant or select tenant access. Revalidate provider build and redirects
against preserved settings before use.
