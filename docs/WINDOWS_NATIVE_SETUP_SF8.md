# SBOM Analyser + HCL.CS SF.8 IAM — Windows setup from scratch

Verified end-to-end on Windows 11 on **2026-08-17**. This guide covers the **SF.8 variant** of HCL.CS
(`SF.8.CRS_PL_AG_24`: SQL Server Express + WPF installer + demo server on port **5001**). It replaces
[WINDOWS_NATIVE_SETUP.md](./WINDOWS_NATIVE_SETUP.md), which targets a different, PostgreSQL/Docker-based
HCL.CS build on port 5180 — do not mix the two guides.

All commands run in **PowerShell**. Paths assume:

```text
C:\SF_Main\SF.8.CRS_PL_AG_24     HCL.CS SF.8 source
C:\Projects\sbom                 SBOM Analyser source
```

## 0. What you are setting up

| Component | Port / URL | Role |
|---|---|---|
| HCL.CS auth server (`Cybersecurity-Demo\HCL.CS.SF.DemoServerApp`) | `https://localhost:5001` | OIDC identity provider: login UI, `/security/*`, discovery, JWKS |
| SBOM API (FastAPI) | `http://localhost:8000` | Backend; validates every bearer JWT against HCL.CS |
| SBOM frontend (Next.js BFF) | `https://localhost:3000` | Web UI; performs Authorization Code + PKCE server-side |
| SQL Server Express | `localhost\SQLEXPRESS`, DB `SFDb` | HCL.CS database |
| PostgreSQL 16/17 | `localhost:5432`, DB `sbom_analyser` | SBOM database |

Auth flow: browser → Next.js BFF → `/security/authorize` on 5001 → login page → code + PKCE exchange
(server-side, no client secret) → RS256 access token with `aud=sbom-analyser-api` → FastAPI validates
via discovery + JWKS and resolves the local user by exact `(issuer, subject)`.

## 1. Prerequisites

```powershell
winget install --exact --id Microsoft.DotNet.SDK.8
winget install --exact --id Microsoft.SQLServer.2022.Express
winget install --exact --id Microsoft.Sqlcmd
winget install --exact --id PostgreSQL.PostgreSQL.17
winget install --exact --id Python.Python.3.12          # 3.11+ works
winget install --exact --id OpenJS.NodeJS.LTS           # Node 20+
winget install --exact --id FiloSottile.mkcert
```

Reopen PowerShell, then verify: `dotnet --list-sdks` (8.x), `py --version` (≥3.11), `node --version`,
`sqlcmd -?`, `Get-Service 'MSSQL$SQLEXPRESS', postgresql*` (both Running).

> `sqlcmd` (ODBC 18) rejects SQL Server Express's self-signed TLS cert — always pass **`-C`**.
> Prefer also **`-I`** (QUOTED_IDENTIFIER ON); some SFDb tables have indexed views that fail updates without it.

Trust the ASP.NET dev certificate (serves HTTPS on 5001):

```powershell
dotnet dev-certs https --trust
```

## 2. HCL.CS source patches — REQUIRED for SBOM interop

The pristine SF.8 source violates the OIDC/JWT specs in ways its own .NET demo clients tolerate but
standards-compliant clients (SBOM's `jose` + PyJWT) reject. If your copy of `SF.8.CRS_PL_AG_24` was
taken from this machine after 2026-08-17, these are already applied — verify with the checks in §6.
Otherwise apply all five:

| # | File | Change | Why |
|---|---|---|---|
| 1 | `Cybersecurity-Demo\...\DemoServerApp\Configurations\TokenSettings.json` | `"IssuerUri": "https://localhost:5001"` (was `security.Hcl.com`) | SBOM requires discovery `issuer` == `HCL_IAM_ISSUER` and a same-origin JWKS URL |
| 2 | `HCL.CS\HCL.CS.Domain\Models\Endpoint\Response\JsonWebKeyResponseModel.cs` | Add `[JsonPropertyName("kty")]` etc. (lowercase RFC 7517 names) on every property | JWKS was served PascalCase (`"Kty"`); jose/PyJWT are case-sensitive → `JWKSNoMatchingKey` |
| 3 | `HCL.CS\HCL.CS.Service\...\Extensions\CertificateExtension.cs` (`GetAsymmetricSigningCredentials`) | After creating credentials, set `credentials.Key.KeyId = keyStore[algorithm].KeyId` | Tokens carried no `kid`; FastAPI resolves keys strictly by `kid` |
| 4 | `Cybersecurity-Demo\...\DemoServerApp\Startup.cs` (`LoadAsymmetricCertificate`) | `KeyId = <certificate>.Thumbprint` (was `GenerateRandomSalt(16)`) | Random per-process kid invalidated all outstanding tokens on every SF restart |
| 5 | `HCL.CS\HCL.CS.Service\...\Services\TokenGenerationService.cs` (`CreateAccessTokenPayload`) | For non-client-credentials grants append `email`, `name` (First+Last, fallback UserName), `preferred_username` claims from `TokenDetails.User` | SBOM provisions identities from access-token claims; SF only put profile claims in the ID token |

Side effect of patch 1: the bundled **MVC demo client (port 5004) breaks** — it hard-codes
`security.Hcl.com` as its expected issuer. The HCL.CS.Admin console (3001) is unaffected
(it uses `HCL_CS_ISSUER=https://localhost:5001` from env).

## 3. Create SFDb and run the HCL.CS installer

```powershell
sqlcmd -S "localhost\SQLEXPRESS" -E -C -Q "CREATE DATABASE SFDb;"
```

The installer csproj only copies the MySQL/PostgreSQL scripts to its output — copy the SQL Server
script manually first, then run the wizard:

```powershell
dotnet build "C:\SF_Main\SF.8.CRS_PL_AG_24\Installer\HCL.CS.SF.Setup\HCL.CS.SF.Installer.csproj"
Copy-Item "C:\SF_Main\SF.8.CRS_PL_AG_24\Installer\HCL.CS.SF.Setup\SecurityFrameworkSql.sql" `
          "C:\SF_Main\SF.8.CRS_PL_AG_24\Installer\HCL.CS.SF.Setup\bin\Debug\net8.0-windows\"
dotnet run --project "C:\SF_Main\SF.8.CRS_PL_AG_24\Installer\HCL.CS.SF.Setup"
```

In the wizard:

1. **DB Selection** — SQL Server, connection string
   `Server=localhost\SQLEXPRESS;Database=SFDb;Trusted_Connection=True;MultipleActiveResultSets=True;TrustServerCertificate=True`
2. **Client Info** — values don't matter for SBOM (§5 registers the SBOM client directly); enter anything valid.
3. **User Account Info** — creates your admin user (e.g. `hclcs.admin`) with both roles. **Remember this password.**
4. Run setup. Verify: `sqlcmd -S "localhost\SQLEXPRESS" -E -C -d SFDb -Q "SELECT COUNT(*) FROM sys.tables"` → ~31.

Re-running the installer on an existing DB fails — recover with `DROP DATABASE SFDb;` and restart from the top.

## 4. Token-signing certificates

The signing certs live in `Cybersecurity-Demo\...\DemoServerApp\Certificates\`
(`security.pfx` ECDSA/ES256 + `security_rsa.pfx` RSA/RS256, password `test@123` hard-coded in `Startup.cs`).
The server **refuses to start** if they are expired. Check:

```powershell
$pwd = ConvertTo-SecureString "test@123" -AsPlainText -Force
$certDir = "C:\SF_Main\SF.8.CRS_PL_AG_24\Cybersecurity-Demo\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp\Certificates"
foreach ($f in @("security.pfx","security_rsa.pfx")) {
  $c = Get-PfxCertificate -FilePath "$certDir\$f" -Password $pwd
  "{0}: NotAfter={1}" -f $f, $c.NotAfter
}
```

If expired, regenerate per §6b of `C:\SF_Main\SF.8.CRS_PL_AG_24\SETUP_GUIDE.md` (ECDSA must be exactly P-256).

Also point the server at your DB: in `Cybersecurity-Demo\...\DemoServerApp\Configurations\SystemSettings.json`
set `DBConnectionString` to the same SQL Server string as §3 (the repo may ship another machine's hostname).

## 5. Register the SBOM client, API resource, and permissions in SFDb

The SF.8 framework has an internal grammar the registration MUST follow, or access tokens get the wrong
audience and SBOM rejects them:

- API **scope names must be dotted** (`resource.action`) — a dot-less scope never maps to an audience
  and can crash `ShrinkPermissions`.
- Each scope needs **`SF_ApiScopeClaims` rows** (`permission`, `role`) or user permission claims are
  never attached to the token.
- Roles need a **`permission` claim equal to the scope name** for their users to be granted it.
- `ClientSecret` must be **non-empty even for public clients** (the JWT-header factory throws on blank);
  it is never validated because `RequireClientSecret=0`.

Save as `RegisterSbomClient.sql` and run with `sqlcmd -S "localhost\SQLEXPRESS" -E -C -I -d SFDb -i RegisterSbomClient.sql`:

```sql
-- API resource (its Name becomes the token's aud) + dotted scope + claim types
DECLARE @ResourceId uniqueidentifier = NEWID();
IF NOT EXISTS (SELECT 1 FROM SF_ApiResources WHERE Name = N'sbom-analyser-api')
  INSERT INTO SF_ApiResources (Id, Name, DisplayName, Enabled, IsDeleted, CreatedOn, CreatedBy)
  VALUES (@ResourceId, N'sbom-analyser-api', N'SBOM Analyser API', 1, 0, SYSUTCDATETIME(), N'SFUser');
ELSE
  SET @ResourceId = (SELECT Id FROM SF_ApiResources WHERE Name = N'sbom-analyser-api');

DECLARE @ScopeId uniqueidentifier = NEWID();
IF NOT EXISTS (SELECT 1 FROM SF_ApiScopes WHERE Name = N'sbom-analyser-api.read')
  INSERT INTO SF_ApiScopes (Id, ApiResourceId, Name, DisplayName, IsDeleted, CreatedOn, CreatedBy)
  VALUES (@ScopeId, @ResourceId, N'sbom-analyser-api.read', N'SBOM Analyser API access', 0, SYSUTCDATETIME(), N'SFUser');
ELSE
  SET @ScopeId = (SELECT Id FROM SF_ApiScopes WHERE Name = N'sbom-analyser-api.read');

IF NOT EXISTS (SELECT 1 FROM SF_ApiScopeClaims WHERE ApiScopeId = @ScopeId AND Type = N'permission')
  INSERT INTO SF_ApiScopeClaims (Id, ApiScopeId, Type, IsDeleted, CreatedOn, CreatedBy)
  VALUES (NEWID(), @ScopeId, N'permission', 0, SYSUTCDATETIME(), N'SFUser');
IF NOT EXISTS (SELECT 1 FROM SF_ApiScopeClaims WHERE ApiScopeId = @ScopeId AND Type = N'role')
  INSERT INTO SF_ApiScopeClaims (Id, ApiScopeId, Type, IsDeleted, CreatedOn, CreatedBy)
  VALUES (NEWID(), @ScopeId, N'role', 0, SYSUTCDATETIME(), N'SFUser');

-- Grant the scope-permission to both roles
DECLARE @AdminRole uniqueidentifier = (SELECT Id FROM SF_Roles WHERE Name = N'SFAdmin');
DECLARE @UserRole  uniqueidentifier = (SELECT Id FROM SF_Roles WHERE Name = N'SFUser');
IF NOT EXISTS (SELECT 1 FROM SF_RoleClaims WHERE RoleId = @AdminRole AND ClaimValue = N'sbom-analyser-api.read')
  INSERT INTO SF_RoleClaims (RoleId, ClaimType, ClaimValue, IsDeleted, CreatedOn, CreatedBy)
  VALUES (@AdminRole, N'permission', N'sbom-analyser-api.read', 0, SYSUTCDATETIME(), N'SFUser');
IF NOT EXISTS (SELECT 1 FROM SF_RoleClaims WHERE RoleId = @UserRole AND ClaimValue = N'sbom-analyser-api.read')
  INSERT INTO SF_RoleClaims (RoleId, ClaimType, ClaimValue, IsDeleted, CreatedOn, CreatedBy)
  VALUES (@UserRole, N'permission', N'sbom-analyser-api.read', 0, SYSUTCDATETIME(), N'SFUser');

-- Public PKCE client. ClientSecret is a REQUIRED placeholder (never validated: RequireClientSecret=0).
IF NOT EXISTS (SELECT 1 FROM SF_Clients WHERE ClientId = N'sbom-analyser-web')
BEGIN
  DECLARE @ClientPk uniqueidentifier = NEWID();
  DECLARE @UnixNow bigint = DATEDIFF_BIG(SECOND, '1970-01-01', SYSUTCDATETIME());
  INSERT INTO SF_Clients (
      Id, ClientId, ClientName, ClientUri,
      ClientIdIssuedAt, ClientSecretExpiresAt, ClientSecret,
      LogoUri, TermsOfServiceUri, PolicyUri,
      RefreshTokenExpiration, AccessTokenExpiration, IdentityTokenExpiration,
      LogoutTokenExpiration, AuthorizationCodeExpiration,
      AccessTokenType, RequirePkce, IsPkceTextPlain, RequireClientSecret,
      IsFirstPartyApp, AllowOfflineAccess, AllowedScopes,
      AllowAccessTokensViaBrowser, ApplicationType, AllowedSigningAlgorithm,
      SupportedGrantTypes, SupportedResponseTypes,
      FrontChannelLogoutSessionRequired, FrontChannelLogoutUri,
      BackChannelLogoutSessionRequired, BackChannelLogoutUri,
      IsDeleted, CreatedOn, CreatedBy)
  VALUES (
      @ClientPk,
      N'sbom-analyser-web',
      N'SBOM Analyzer Web',
      N'https://localhost:3000',
      @UnixNow, @UnixNow + 315360000,
      N'unused-public-client-placeholder-secret',
      N'', N'', N'',
      86400, 3600, 3600, 1800, 1800,
      1,              -- JWT access tokens
      1, 0, 0,        -- PKCE required (S256), public client: no secret check
      1, 1,
      N'openid profile email offline_access sbom-analyser-api.read',
      1,
      1,              -- RegularWeb
      N'RS256',
      N'authorization_code refresh_token',
      N'code',
      0, NULL, 0, NULL,
      0, SYSUTCDATETIME(), N'SFUser');

  INSERT INTO SF_ClientRedirectUris (Id, ClientId, RedirectUri, IsDeleted, CreatedOn, CreatedBy)
  VALUES (NEWID(), @ClientPk, N'https://localhost:3000/auth/callback', 0, SYSUTCDATETIME(), N'SFUser');
  INSERT INTO SF_ClientPostLogoutRedirectUris (Id, ClientId, PostLogoutRedirectUri, IsDeleted, CreatedOn, CreatedBy)
  VALUES (NEWID(), @ClientPk, N'https://localhost:3000', 0, SYSUTCDATETIME(), N'SFUser');
END
```

> Note: `SF_RoleClaims.Id` is int IDENTITY (omit it); `SF_ApiScopeClaims.Id` / `SF_Clients.Id` are
> uniqueidentifier (pass `NEWID()`).

## 6. Build, run, and verify the HCL.CS server

```powershell
dotnet build "C:\SF_Main\SF.8.CRS_PL_AG_24\Cybersecurity-Demo\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp.csproj"
dotnet run --project "C:\SF_Main\SF.8.CRS_PL_AG_24\Cybersecurity-Demo\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp" --launch-profile HCL.CS.SF.DemoServerApp
```

Verification (all three must pass before touching SBOM):

```powershell
# issuer must be the URL, not "security.Hcl.com"
(Invoke-RestMethod https://localhost:5001/.well-known/openid-configuration).issuer
# keys must be lowercase JSON with kid; RS256 key present
(Invoke-WebRequest https://localhost:5001/.well-known/openid-configuration/jwks).Content
```

Expected: issuer `https://localhost:5001`; raw JWKS containing `"kty":"RSA"`, `"alg":"RS256"`, `"kid":"<thumbprint>"`
(lowercase field names; the kid must stay the same across server restarts).

## 7. SBOM database and environment

Create the PostgreSQL role and empty DB (enter the postgres superuser password when prompted):

```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -h localhost -U postgres -d postgres -c "CREATE ROLE sbom LOGIN PASSWORD 'postgres';"
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -h localhost -U postgres -d postgres -c "CREATE DATABASE sbom_analyser OWNER sbom;"
```

Python venv + dependencies + frontend dependencies:

```powershell
cd C:\Projects\sbom
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend; npm ci; cd ..
```

Frontend HTTPS certificate (mkcert, trusted local CA):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\frontend\scripts\setup-dev-https.ps1
```

Export the ASP.NET dev certificate as the CA bundle Python/Node use to trust `https://localhost:5001`:

```powershell
New-Item -ItemType Directory -Force C:\Projects\sbom\.certificates | Out-Null
dotnet dev-certs https --export-path C:\Projects\sbom\.certificates\aspnet-dev-localhost.pem --format PEM --no-password
```

Create `C:\Projects\sbom\.windows\sbom.env.ps1` (gitignored; loaded by the start scripts):

```powershell
$env:DATABASE_URL = 'postgresql+psycopg://sbom:postgres@localhost:5432/sbom_analyser'
$env:AUTH_ENABLED = 'true'
$env:DEV_DEFAULT_TENANT = 'false'
$env:HCL_IAM_ISSUER = 'https://localhost:5001'
$env:HCL_IAM_AUDIENCE = 'sbom-analyser-api'
$env:HCL_IAM_CLIENT_ID = 'sbom-analyser-web'
$env:HCL_IAM_DISCOVERY_URL = 'https://localhost:5001/.well-known/openid-configuration'
$env:HCL_IAM_ROLE_CLAIM = 'role'
$env:HCL_IAM_TENANT_CLAIM = 'tenant_id'
$env:HCL_IAM_ALLOWED_ALGORITHMS = 'RS256'
$env:HCL_IAM_CA_BUNDLE = 'C:\Projects\sbom\.certificates\aspnet-dev-localhost.pem'
$env:CORS_ORIGINS = 'https://localhost:3000'
$env:NEXT_PUBLIC_AUTH_ENABLED = 'true'
$env:NEXT_PUBLIC_API_URL = 'http://localhost:8000'
$env:NEXT_PUBLIC_APP_URL = 'https://localhost:3000'
$env:NEXT_PUBLIC_HCL_IAM_ISSUER = 'https://localhost:5001'
$env:NEXT_PUBLIC_HCL_IAM_CLIENT_ID = 'sbom-analyser-web'
$env:NEXT_PUBLIC_HCL_IAM_REDIRECT_URI = 'https://localhost:3000/auth/callback'
$env:NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI = 'https://localhost:3000'
$env:NEXT_PUBLIC_HCL_IAM_SCOPES = 'openid profile email offline_access sbom-analyser-api.read'
$env:SBOM_API_URL = 'http://localhost:8000'
```

> The requested scope is **`sbom-analyser-api.read`** (dotted) while `HCL_IAM_AUDIENCE` stays
> **`sbom-analyser-api`** (the resource name). Both are correct — do not "align" them.

If a root `.env` exists, make sure its `HCL_IAM_ISSUER`, `HCL_IAM_DISCOVERY_URL` and `HCL_IAM_CA_BUNDLE`
match the above (env vars win over `.env`, but keep them consistent).

Bootstrap the schema (empty DB only — the script refuses non-empty databases):

```powershell
cd C:\Projects\sbom
. .\.windows\sbom.env.ps1
.\.venv\Scripts\python.exe .\scripts\bootstrap_fresh_database.py --database-url $env:DATABASE_URL --confirm-empty-database sbom_analyser
```

## 8. Start and verify

Three terminals (HCL.CS first, then API, then frontend):

```powershell
dotnet run --project "C:\SF_Main\SF.8.CRS_PL_AG_24\Cybersecurity-Demo\HCL.CS.SF.DemoServerApp\HCL.CS.SF.DemoServerApp" --launch-profile HCL.CS.SF.DemoServerApp
```

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomApi.ps1
```

```powershell
cd C:\Projects\sbom
.\scripts\windows\Start-SbomFrontend.ps1
```

Health checks: `Invoke-RestMethod http://localhost:8000/health` → `status: ok`;
`https://localhost:3000` in a browser → redirects to the HCL.CS login page on 5001.

## 9. First login and platform administrator

1. Sign in at `https://localhost:3000` with the installer-created user (e.g. `hclcs.admin`).
   You land on the **access pending** page — the login worked and SBOM recorded your identity.
2. The platform-admin bootstrap requires a verified email. With no local SMTP server
   (default config points at `127.0.0.1:1025`), mark it verified directly (local dev only):

```powershell
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -h localhost -U sbom -d sbom_analyser -c "UPDATE iam_users SET email_verified=true, email_verified_at=now(), verification_required=false WHERE id=1;"
```

3. Find your subject (`sub` = the SF user's GUID, lowercase) and grant platform admin:

```powershell
sqlcmd -S "localhost\SQLEXPRESS" -E -C -d SFDb -Q "SELECT LOWER(CONVERT(varchar(36), Id)), UserName FROM SF_Users"
cd C:\Projects\sbom
. .\.windows\sbom.env.ps1
.\.venv\Scripts\python.exe .\scripts\bootstrap_platform_admin.py --issuer https://localhost:5001 --subject <sub-guid> --change-reference LOCAL-SETUP --confirm BOOTSTRAP_PLATFORM_ADMIN
```

4. Refresh the browser — you now have `PLATFORM_ADMIN`: create a tenant, then onboard further users
   (they sign in once → appear as PENDING → activate them via **Settings → Tenant/Platform**).

## 10. Redoing it on THIS machine

Everything in §1–§6 is already done here. To reset only the SBOM data:

```powershell
cd C:\Projects\sbom
.\scripts\windows\Stop-SbomLocal.ps1
$env:PGPASSWORD='postgres'
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -h localhost -U sbom -d postgres -c "DROP DATABASE IF EXISTS sbom_analyser WITH (FORCE);"
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -h localhost -U postgres -d postgres -c "CREATE DATABASE sbom_analyser OWNER sbom;"   # superuser needed: sbom lacks CREATEDB
Remove-Item Env:PGPASSWORD
. .\.windows\sbom.env.ps1
.\.venv\Scripts\python.exe .\scripts\bootstrap_fresh_database.py --database-url $env:DATABASE_URL --confirm-empty-database sbom_analyser
```

Then restart the API/frontend and repeat §9 (first login + platform-admin bootstrap).
To reset HCL.CS too: `DROP DATABASE SFDb` and repeat §3 and §5.

## 11. Daily start / stop

Start (order matters — HCL.CS before frontend logins):

```powershell
# T1: dotnet run ... DemoServerApp (see §8)
# T2: .\scripts\windows\Start-SbomApi.ps1
# T3: .\scripts\windows\Start-SbomFrontend.ps1
```

Stop: `Ctrl+C` in each terminal, or `.\scripts\windows\Stop-SbomLocal.ps1` plus killing the 5001 listener.
The two databases are Windows services and need nothing. A frontend restart clears all login sessions
(the BFF session store is in-memory) — signing in again is expected.

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Callback: `OIDC ID token validation failed (JWKSNoMatchingKey)` | JWKS PascalCase or missing `kid` in token headers | §2 patches 2–3 |
| API 401, `InvalidAudienceError: Audience doesn't match` | Scope not dotted, or scope has no `SF_ApiScopeClaims` rows, or role lacks the permission claim | §5 |
| API 401, `display name must be a string` / `required identity claim is missing` | Access token lacks `email`/`name`/`preferred_username` | §2 patch 5 |
| "Service Temporarily Unavailable" right after an SF restart | Old build with random per-restart `kid` — outstanding tokens invalidated | §2 patch 4, then sign in again |
| `OIDC discovery issuer mismatch` | `TokenSettings.json` IssuerUri not `https://localhost:5001` | §2 patch 1 |
| `certificate verify failed` from FastAPI or the BFF | `HCL_IAM_CA_BUNDLE` missing/pointing at the wrong PEM | §7 dev-cert export |
| Bootstrap: `Email verification is required` | No SMTP locally | §9 step 2 |
| Bootstrap refuses: active platform admin exists | It's one-time by design | Use the authenticated UI/API at `/settings/platform` |
| `Certificate does not have a private key :Certificate Expired` at SF start | Signing certs expired | §4 |
| Login form rejects before showing | client_id / redirect URI mismatch with `SF_Clients` row | §5 (URIs must match exactly) |
| Account locked after failed logins | 3 attempts → 10-min lockout (SystemSettings.json) | Wait, or clear `LockoutEnd` in `SF_Users` |

## Appendix: what talks to what

```text
Browser ── https://localhost:3000 (Next.js BFF)
              │  discovery/JWKS/token calls, trusts aspnet-dev-localhost.pem
              ▼
        https://localhost:5001 (HCL.CS)  ──  SQL Server: SFDb
              ▲
              │  discovery/JWKS + RS256 validation (aud=sbom-analyser-api, kid match)
        http://localhost:8000 (FastAPI)  ──  PostgreSQL: sbom_analyser
```
