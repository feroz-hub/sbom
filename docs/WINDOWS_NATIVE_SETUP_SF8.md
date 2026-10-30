# Windows HCL.CS on .NET 8


“Native Windows” means host installation, not the Native IAM identity provider.
The PostgreSQL-backed HCL.CS build (historically port 5180) and SF.8 SQL Server
build (historically port 5001) are different provider integrations; neither guide
replaces the other. Do not mix their provider/database procedures. Historical
Windows verification does not establish acceptance of the current launcher.
Apply the [database gate](DATABASE_BOOTSTRAP_AND_UPGRADE.md) before any SBOM setup
or upgrade: fresh targets must be empty; populated pre-UUID targets must not cross
revision 100. External HCL.CS provisioning stays in its own repository/operator
procedure, with separate roles/databases and explicitly approved certificate trust.

Follow [Windows local development](WINDOWS_NATIVE_SETUP.md) and
[HCL configuration](HCL_IAM_CONFIGURATION.md). Install the provider's required .NET 8
runtime separately. scripts/dev.py manages SBOM and preserves provider settings;
it does not install or migrate the external HCL.CS service.

Use `python scripts/dev.py --profile legacy --legacy-config windows`.
Keep approved HTTPS trust, registered redirects, provider CA bundle and existing
user/database data. Native Windows/.NET authentication remains untested; see the
[platform matrix](engineering/dev-launcher-platform-matrix.md).

After validated HCL.CS login, SBOM resolves identity by issuer and immutable subject.
Grant local tenant membership/roles through authorized SBOM administration; a token
claim cannot grant or select tenant access. Revalidate provider build and redirects
against preserved settings before use.
