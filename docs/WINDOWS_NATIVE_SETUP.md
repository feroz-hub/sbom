# Native Windows setup: HCL.CS and SBOM Analyser

This guide runs both products directly on Windows without Docker. It uses one local PostgreSQL 16 service and separate databases/roles for HCL.CS and SBOM Analyser.

## Recommended directory layout

```text
C:\Projects\SF
C:\Projects\sbom
```

The scripts also support a different HCL.CS location through `-HclCsRoot`.

## 1. Install prerequisites

Open an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

winget install --exact --id PostgreSQL.PostgreSQL.16 --accept-source-agreements --accept-package-agreements
winget install --exact --id Microsoft.DotNet.SDK.8 --accept-source-agreements --accept-package-agreements
winget install --exact --id Python.Python.3.11 --accept-source-agreements --accept-package-agreements
winget install --exact --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
winget install --exact --id FiloSottile.mkcert --accept-source-agreements --accept-package-agreements
```

The PostgreSQL installer asks for the local `postgres` superuser password. Save it in a password manager. Close and reopen PowerShell after installation, then verify:

```powershell
dotnet --version
py -3.11 --version
node --version
npm --version
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' --version
Get-Service postgresql*
```

Start PostgreSQL if needed:

```powershell
Get-Service postgresql* | Start-Service
```

## 2. Initialize the HCL.CS database and dependencies

```powershell
cd C:\Projects\SF
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\Initialize-HclCsLocal.ps1
```

The script prompts for:

- the local PostgreSQL `postgres` password;
- a new password for the least-privileged `hcl_cs` database role.

It creates the `hcl_cs` role/database, restores .NET and Admin UI dependencies, trusts the ASP.NET development certificate, exports its public PEM certificate, and writes ignored local configuration to:

```text
C:\Projects\SF\.windows\hcl-cs.env.ps1
C:\Projects\SF\.windows\certificates\hcl-cs-local.pem
```

Do not commit `.windows`.

## 3. Run the supported HCL.CS Installer once

```powershell
cd C:\Projects\SF
.\scripts\windows\Start-HclCsInstaller.ps1
```

Open:

```text
https://localhost:7039/setup
```

Select PostgreSQL and use:

```text
Host=localhost;Port=5432;Database=hcl_cs;Username=hcl_cs;Password=<the-hcl_cs-password-you-chose>
```

Complete the wizard and record the generated Admin OAuth client ID/secret and local administrator username/password. These values are local secrets and must not be committed.

Use these Admin client values in the Installer seed step:

```text
Client URI: https://localhost:3001
Grant types: authorization_code, refresh_token
Response type: code
Scopes: keep "Use default scopes" enabled
Redirect URI: https://localhost:3001/api/auth/callback/hcl-cs
Post-logout redirect URI: https://localhost:3001/login
```

After the wizard finishes, stop the Installer with `Ctrl+C` and apply all post-bootstrap migrations, including the SBOM public client:

```powershell
.\scripts\windows\Complete-HclCsDatabase.ps1
```

The resulting SBOM client is:

```text
Client ID: sbom-analyser-web
Type: public, no secret
Flow: authorization_code + refresh_token
PKCE: S256 required
Audience: sbom-analyser-api
Redirect: https://localhost:3000/auth/callback
Logout redirect: https://localhost:3000
```

## 4. Configure and start HCL.CS Admin

```powershell
cd C:\Projects\SF\HCL.CS-admin
Copy-Item .env.example .env.local
notepad .env.local
```

Replace the placeholders with the client ID/secret from the Installer. Generate `NEXTAUTH_SECRET` without printing it into source files:

```powershell
$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

Start the identity backend in terminal 1:

```powershell
cd C:\Projects\SF
.\scripts\windows\Start-HclCsIdentity.ps1
```

Start the Admin UI in terminal 2:

```powershell
cd C:\Projects\SF
.\scripts\windows\Start-HclCsAdmin.ps1
```

Verify:

```powershell
Invoke-RestMethod https://localhost:5180/.well-known/openid-configuration
Start-Process https://localhost:3001
```

## 5. Initialize SBOM Analyser

Open another elevated PowerShell:

```powershell
cd C:\Projects\sbom
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\Initialize-SbomLocal.ps1 -HclCsRoot C:\Projects\SF
```

The script prompts for the PostgreSQL superuser password and a new `sbom` role password. It then:

- creates the `sbom` role and `sbom_analyser` database;
- creates `.venv` and installs Python dependencies;
- installs frontend dependencies;
- applies all Alembic migrations;
- installs/trusts a local mkcert CA and creates the Next.js HTTPS certificate;
- writes ignored authentication/database settings to `.windows\sbom.env.ps1`.

No real `.env` file is overwritten.

## 6. Start SBOM backend and frontend

Terminal 3, FastAPI:

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomApi.ps1
```

Terminal 4, Next.js HTTPS frontend:

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomFrontend.ps1
```

Open:

```text
https://localhost:3000
```

## 7. Provision the local HCL.CS tenant claim and SBOM membership

In HCL.CS Admin, assign the test identity a `tenant_id` user claim such as:

```text
tenant_id = local-default
```

Copy the immutable HCL.CS user ID (`sub`), then map it to the SBOM database:

```powershell
cd C:\Projects\sbom
. .\.windows\sbom.env.ps1

.\.venv\Scripts\python.exe .\scripts\seed_hcl_iam_membership.py `
  --subject '<HCL.CS-user-id>' `
  --external-tenant local-default `
  --email test-user@example.local `
  --display-name 'Test User' `
  --role SECURITY_ANALYST
```

This operation is idempotent and cannot seed `PLATFORM_ADMIN`.

## 8. URLs and health checks

```text
HCL.CS Installer: https://localhost:7039/setup  (first setup only)
HCL.CS Identity:  https://localhost:5180
HCL.CS Admin:     https://localhost:3001
SBOM FastAPI:     http://localhost:8000
SBOM Frontend:    https://localhost:3000
PostgreSQL:       localhost:5432
```

```powershell
Invoke-RestMethod https://localhost:5180/health/ready
Invoke-RestMethod https://localhost:5180/.well-known/openid-configuration
Invoke-RestMethod http://localhost:8000/health
Start-Process https://localhost:3000
```

## 9. Normal restart procedure

PostgreSQL runs as a Windows service:

```powershell
Get-Service postgresql* | Restart-Service
```

Then open four PowerShell terminals:

```powershell
# Terminal 1
cd C:\Projects\SF
.\scripts\windows\Start-HclCsIdentity.ps1
```

```powershell
# Terminal 2
cd C:\Projects\SF
.\scripts\windows\Start-HclCsAdmin.ps1
```

```powershell
# Terminal 3
cd C:\Projects\sbom
.\scripts\windows\Start-SbomApi.ps1
```

```powershell
# Terminal 4
cd C:\Projects\sbom
.\scripts\windows\Start-SbomFrontend.ps1
```

Use `Ctrl+C` in each terminal to stop the application. Do not rerun the Installer during ordinary restarts.

To stop native application processes by their local listening ports from any PowerShell window:

```powershell
cd C:\Projects\SF
.\scripts\windows\Stop-HclCsLocal.ps1

cd C:\Projects\sbom
.\scripts\windows\Stop-SbomLocal.ps1
```

These scripts leave the PostgreSQL Windows service running. Run the four start commands above to restart the applications.

## 10. Development mode without HCL.CS

To temporarily run SBOM without authentication:

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomApi.ps1 -NoAuth
```

In a second terminal, start the frontend with the same explicit bypass:

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomFrontend.ps1 -NoAuth
```

Omitting `-NoAuth` always restores authenticated HCL.CS mode from the generated configuration.

## Troubleshooting

- `psql.exe not found`: add `C:\Program Files\PostgreSQL\16\bin` to `PATH` or reopen PowerShell.
- PowerShell script blocked: use `Set-ExecutionPolicy -Scope Process Bypass`.
- Certificate warning: rerun `dotnet dev-certs https --trust` and `frontend\scripts\setup-dev-https.ps1`.
- Node certificate error: ensure `C:\Projects\SF\.windows\certificates\hcl-cs-local.pem` exists and rerun the provided start script.
- `401`: verify issuer/audience and Windows clock synchronization.
- `403 Tenant access denied`: verify the HCL.CS `tenant_id`, local tenant external ID, active user, and membership.
- Port already used:

```powershell
Get-NetTCPConnection -LocalPort 3000,3001,5180,8000 -ErrorAction SilentlyContinue |
  Select-Object LocalPort, OwningProcess
```
