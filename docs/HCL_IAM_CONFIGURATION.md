# HCL.CS authentication for SBOM Analyser

## Architecture and ownership

The browser uses OAuth 2.0 Authorization Code with PKCE against HCL.CS. Next.js is a backend-for-frontend (BFF): it generates state, nonce and the PKCE verifier, performs the code exchange, validates the ID token through discovery/JWKS, and stores tokens only in a server-side session. The browser receives an opaque `__Host-sbom-session` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`). Browser API calls go to `/api/backend/*`; that server route attaches the access token only to `SBOM_API_URL`.

FastAPI independently validates every bearer JWT, resolves `sub` and `tenant_id` to local identity/membership tables, applies the local SBOM role, and tenant-scopes ORM reads and writes. HCL.CS owns authentication, tokens, central identity claims and revocation. SBOM owns tenants, memberships, application roles, permissions, inventory and tenant isolation. Frontend visibility rules are never an authorization boundary.

The local in-memory BFF session store is appropriate for one Next.js development process. Production and multi-instance deployment must replace it with an encrypted shared server-side store (for example Redis) while retaining the opaque cookie contract.

## HCL.CS registration

Docker applies `scripts/migrations/20260717_sbom_analyser_client_postgresql.sql` idempotently to the real Demo Server database. It registers:

| Setting | Value |
| --- | --- |
| Client ID | `sbom-analyser-web` |
| Type | Public SPA, no secret |
| Grant types | `authorization_code refresh_token` |
| Response type | `code` |
| PKCE | Required, S256 only |
| Redirect | `https://localhost:3000/auth/callback` |
| Post logout | `https://localhost:3000` |
| Scopes | `openid profile email offline_access sbom-analyser-api` |
| Audience/resource | `sbom-analyser-api` |
| Signing | RS256 |

The Docker runtime is `demos/HCL.CS.Demo.Server/Program.cs`; the placeholder Identity API project is not used for this configuration. CORS/form-action allow `https://localhost:3000` and the admin UI at `https://localhost:3001`.

Discovery is authoritative:

```bash
curl -k https://localhost:5180/.well-known/openid-configuration
curl -k https://localhost:5180/.well-known/openid-configuration/jwks
```

`-k` is local troubleshooting only. Configure trust in normal use. HCL.CS advertises `/security/authorize`, `/security/token`, `/security/revocation`, `/security/endsession`, and its JWKS path through discovery.

## Claims, role and tenant mapping

Access tokens require `iss`, `sub`, `aud`, `exp`; HCL.CS also emits `iat`, `nbf`, `jti`, requested standard identity claims, `role`, and `tenant_id` when assigned. `sub` is the immutable external user key; email is display/contact data only.

Default configurable role mapping:

| HCL.CS role | SBOM role |
| --- | --- |
| `PLATFORM_ADMIN`, `SBOM_PLATFORM_ADMIN` | `PLATFORM_ADMIN` |
| `TENANT_ADMIN`, `SBOM_TENANT_ADMIN` | `TENANT_ADMIN` |
| `SECURITY_ANALYST`, `SBOM_SECURITY_ANALYST` | `SECURITY_ANALYST` |
| `DEVELOPER`, `SBOM_DEVELOPER` | `DEVELOPER` |
| `VIEWER`, `SBOM_VIEWER` | `VIEWER` |

Override with `HCL_IAM_ROLE_MAPPING` JSON. A token role does not grant a tenant role: tenant authorization comes from the active `tenant_users` membership. The only token-level special case is explicit `PLATFORM_ADMIN`, whose cross-tenant selection is deliberate. Normal resolution is:

```text
JWT sub -> iam_users.external_iam_user_id
JWT tenant_id -> tenants.external_iam_tenant_id
iam_users.id + tenants.id -> tenant_users -> local SBOM role/permissions
```

An unknown validated subject is recorded as an active but unassigned IAM user for audit/JIT identity correlation. No tenant or membership is created from an arbitrary claim, so access remains `403` until an administrator assigns membership. Inactive users, inactive tenants, inactive memberships and unknown tenants are `403`. Resource IDs are additionally protected by tenant-bound SQLAlchemy filters and write guards.

## Environment

Backend placeholders are in `.env.hcl-iam.example`:

```env
AUTH_ENABLED=true
DEV_DEFAULT_TENANT=false
HCL_IAM_ISSUER=https://localhost:5180
HCL_IAM_AUDIENCE=sbom-analyser-api
HCL_IAM_CLIENT_ID=sbom-analyser-web
HCL_IAM_DISCOVERY_URL=https://localhost:5180/.well-known/openid-configuration
HCL_IAM_JWKS_URL=
HCL_IAM_ROLE_CLAIM=role
HCL_IAM_TENANT_CLAIM=tenant_id
HCL_IAM_ALLOWED_ALGORITHMS=RS256
HCL_IAM_CLOCK_SKEW_SECONDS=30
HCL_IAM_HTTP_TIMEOUT_SECONDS=5
HCL_IAM_CA_BUNDLE=/absolute/path/to/hcl-cs-local.crt
CORS_ORIGINS=https://localhost:3000
```

`HCL_IAM_JWKS_URL` may be empty; FastAPI reads it from discovery. If set, it must exactly match discovery. The CA bundle is the supported way to trust a private/local issuer; TLS verification is never globally disabled.

Frontend placeholders are in `frontend/.env.local.example`. `SBOM_API_URL` is server-only. There is no client secret and no token in any `NEXT_PUBLIC_*` setting.
`HCL_IAM_CA_BUNDLE` is also server-only and lets the BFF trust the local/private HCL.CS CA without disabling TLS verification.

## Local HTTPS trust

Create the frontend certificate:

```bash
cd /home/kali/sbom/frontend
npm run setup:https
```

`mkcert` is preferred and installs a trusted local CA. The fallback creates a self-signed certificate which must be imported into the workstation trust store. Export the current HCL.CS public development certificate for Node/FastAPI trust:

```bash
mkdir -p /home/kali/sbom/.certificates
docker cp hcl-cs-identity:/app/https/hcl-cs-devcert.crt /home/kali/sbom/.certificates/hcl-cs-local.crt
```

Trust that certificate in the browser/OS. `frontend/certificates/` and `.certificates/` are ignored and must never be committed.

## Seed a local mapping

Create the HCL.CS test identity through the installer/admin UI, assign its `tenant_id` user claim (for example `hcl-cs-local`), and note its immutable user ID/`sub`. Never put its password in a seed file. Then run:

```bash
cd /home/kali/sbom
source .venv/bin/activate
python scripts/seed_hcl_iam_membership.py \
  --subject '<HCL.CS-user-id>' \
  --external-tenant hcl-cs-local \
  --email test-user@example.local \
  --display-name 'Test User' \
  --role SECURITY_ANALYST
```

The helper is idempotent and refuses to seed `PLATFORM_ADMIN`.

## Start both products

```bash
cd /home/kali/SF
docker compose -f docker/docker-compose.yml up -d --build

cd /home/kali/sbom
docker compose up -d postgres
source .venv/bin/activate
alembic upgrade head
AUTH_ENABLED=true DEV_DEFAULT_TENANT=false \
HCL_IAM_ISSUER=https://localhost:5180 \
HCL_IAM_AUDIENCE=sbom-analyser-api HCL_IAM_CLIENT_ID=sbom-analyser-web \
HCL_IAM_ROLE_CLAIM=role HCL_IAM_TENANT_CLAIM=tenant_id \
HCL_IAM_CA_BUNDLE=/home/kali/sbom/.certificates/hcl-cs-local.crt \
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

cd /home/kali/sbom/frontend
npm install
npm run setup:https
npm run dev:https
```

Open `https://localhost:3000`. The BFF discovers HCL.CS endpoints, generates state/nonce/PKCE, and redirects. Callback state and nonce are mandatory, the authorization transaction is single-use, return paths are local-only, and the ID token is verified with RS256/JWKS before session creation.

## Validation and diagnostics

After login:

```bash
curl -i https://localhost:3000/api/auth/session   # cookie-bearing browser request in practice
curl -i http://localhost:8000/api/v1/auth/me      # requires a bearer access token
```

`GET /api/v1/auth/me` and `/api/auth/me` return only safe principal, tenant, role and permission data—never tokens or raw claims. A missing/invalid/expired/wrong-issuer/wrong-audience/unknown-key token returns `401` with `WWW-Authenticate: Bearer`. A valid identity lacking an active membership or permission returns `403`. Tenant-owned resource lookups are filtered by the resolved tenant; concealed cross-tenant resources may return `404` to avoid disclosing existence.

Manual browser checks:

1. Sign in and confirm HCL.CS then `/auth/callback` then the original page.
2. Confirm requests go to `/api/backend/*`; FastAPI receives a bearer token server-side.
3. Confirm localStorage/sessionStorage contain no access, ID or refresh token.
4. Confirm name/email appear in the user menu and logout clears `__Host-sbom-session`.
5. Confirm a viewer receives the permission page for a write (`403`), not a login loop.
6. Change a project/SBOM/run ID to another tenant and confirm it is denied/not disclosed.

## Refresh, logout and key rotation

The BFF refreshes within 60 seconds of expiry and retries one upstream `401` once. Refreshes are single-flight per session; rotation replaces access and refresh tokens together. Failure destroys the local session and triggers a new login, with no infinite loop. Logout attempts provider revocation, clears the local session even if HCL.CS is unavailable, and uses the discovered end-session endpoint.

FastAPI caches discovery/JWKS clients, bounds network calls, and PyJWKClient refreshes the JWKS set once when it sees a new `kid`. Unknown keys fail closed. Only RS256 is accepted by SBOM, even though HCL.CS may advertise other algorithms for other clients.

## Troubleshooting

- `certificate verify failed`: export/trust the HCL.CS certificate and set `HCL_IAM_CA_BUNDLE`; do not disable TLS validation.
- `redirect_uri`: the URI must exactly be `https://localhost:3000/auth/callback`.
- `401`: inspect issuer/audience/time and discovery reachability; do not log the token.
- `403 Tenant access denied`: check the token `tenant_id`, local `external_iam_tenant_id`, active user/tenant/membership, and local role.
- callback state/nonce error: restart sign-in; the prior transaction is intentionally unusable.
- session disappears after a Next.js restart: expected for the local in-memory store; deploy a shared production store.

## Development-mode rollback

Stop the authenticated processes, set the backend to `AUTH_ENABLED=false` and `DEV_DEFAULT_TENANT=true`, set frontend `NEXT_PUBLIC_AUTH_ENABLED=false` and `NEXT_PUBLIC_API_URL=http://localhost:8000`, then start FastAPI and `npm run dev`. FastAPI emits a startup warning. The bypass cannot activate when auth is enabled, and startup rejects `AUTH_ENABLED=true` together with `DEV_DEFAULT_TENANT=true`.

Code rollback consists of reverting the application changes and deleting the seeded HCL.CS rows for client/resource name `sbom-analyser-web`/`sbom-analyser-api` only. Do not remove signing keys, users, or unrelated clients. No SBOM schema migration was added, so there is no Alembic downgrade for this integration.
