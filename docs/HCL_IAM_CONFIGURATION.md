# HCL IAM Configuration Guide

## 1. Purpose

SBOM Analyser uses HCL IAM as an OpenID Connect (OIDC) / OAuth 2.0 identity provider. The Next.js frontend starts the browser login flow, and the FastAPI backend treats the returned access token as the authoritative identity input.

The intended authentication flow is:

```text
Next.js Frontend
-> redirects user to HCL IAM login
-> receives authorization code
-> exchanges token using PKCE
-> sends access token to FastAPI
-> FastAPI validates JWT using HCL IAM JWKS
-> backend resolves user, tenant, roles
-> RBAC permissions are applied
```

Frontend role checks are only for UI visibility. Backend JWT validation, tenant resolution, and RBAC enforcement are mandatory for protected actions.

## 2. Required Information From HCL IAM Team

Do not guess these values. Get them from the HCL IAM/admin team.

| Required Value | Description | Example / Placeholder |
| --- | --- | --- |
| Issuer URL | OIDC issuer used in token `iss` claim | `<HCL_IAM_ISSUER>` |
| Authorization endpoint | Browser login endpoint | `<HCL_IAM_AUTHORIZATION_URL>` |
| Token endpoint | Token exchange endpoint | `<HCL_IAM_TOKEN_URL>` |
| JWKS URL | Public signing keys endpoint | `<HCL_IAM_JWKS_URL>` |
| UserInfo endpoint | Optional user profile endpoint | `<HCL_IAM_USERINFO_URL>` |
| Client ID | SPA client ID for frontend | `<HCL_IAM_CLIENT_ID>` |
| API audience | Audience expected by backend API | `<HCL_IAM_AUDIENCE>` |
| Redirect URI | Frontend callback URL | `http://localhost:3000/auth/callback` |
| Logout URL | IAM logout endpoint | `<HCL_IAM_LOGOUT_URL>` |
| Role/group claim | Claim containing user roles/groups | `roles`, `groups`, or `realm_access.roles` |
| Tenant claim | Claim containing tenant/company identifier | `tenant_id` |
| Email claim | Claim containing email | `email` |

The frontend can derive standard OIDC endpoints from `NEXT_PUBLIC_HCL_IAM_ISSUER`, but explicit endpoint variables are supported when HCL IAM uses non-standard paths.

## 3. HCL IAM Application Registration

### Frontend Client

Recommended IAM-side settings:

```text
Client type: Public SPA
Flow: Authorization Code + PKCE
Client secret: Not used in frontend
Redirect URI local: http://localhost:3000/auth/callback
Redirect URI production: https://<your-domain>/auth/callback
Allowed Web Origin local: http://localhost:3000
Allowed Web Origin production: https://<your-domain>
Scopes: openid profile email roles
Token signing algorithm: RS256
```

Do not configure a client secret in `frontend/.env.local`. This project uses a public browser client with PKCE.

### Backend API / Resource Server

Recommended IAM-side settings:

```text
API audience: sbom-analyser-api
Token type: JWT
Signing algorithm: RS256
JWKS validation: enabled
Issuer validation: enabled
Audience validation: enabled
Expiry validation: enabled
```

The exact audience value must match the value configured in `HCL_IAM_AUDIENCE`.

## 4. Backend Configuration

Configure backend IAM settings in the root `.env` file. These are the actual backend environment variables read by `app/settings.py` and `app/core/security.py`:

```env
AUTH_ENABLED=true
DEV_DEFAULT_TENANT=false

HCL_IAM_ISSUER=<HCL_IAM_ISSUER>
HCL_IAM_AUDIENCE=<HCL_IAM_AUDIENCE>
HCL_IAM_JWKS_URL=<HCL_IAM_JWKS_URL>
HCL_IAM_CLIENT_ID=<HCL_IAM_CLIENT_ID>
HCL_IAM_ALLOWED_ALGORITHMS=RS256

HCL_IAM_ROLE_CLAIM=roles
HCL_IAM_TENANT_CLAIM=tenant_id

CORS_ORIGINS=http://localhost:3000
APP_SECRET_KEY=<strong-random-secret>
```

Notes:

- `HCL_IAM_ROLE_CLAIM` supports dot-path claims such as `realm_access.roles`.
- There is no separate backend `HCL_IAM_GROUP_CLAIM`; point `HCL_IAM_ROLE_CLAIM` at the IAM claim that contains the role or group values.
- Email, name, and username are currently read from standard token claims: `email`, `name`, and `preferred_username`.
- `APP_SECRET_KEY` is used for encrypted application secrets such as lifecycle provider credentials.

Local development mode:

```env
AUTH_ENABLED=false
DEV_DEFAULT_TENANT=true
```

Never use `AUTH_ENABLED=false` in production.

## 5. Frontend Configuration

Create `frontend/.env.local` from `frontend/.env.local.example`. These are the actual frontend environment variables read by `frontend/src/lib/auth.ts` and `frontend/src/lib/env.ts`:

```env
NEXT_PUBLIC_AUTH_ENABLED=true
NEXT_PUBLIC_API_URL=http://localhost:8000

NEXT_PUBLIC_HCL_IAM_ISSUER=<HCL_IAM_ISSUER>
NEXT_PUBLIC_HCL_IAM_CLIENT_ID=<HCL_IAM_CLIENT_ID>
NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL=<HCL_IAM_AUTHORIZATION_URL>
NEXT_PUBLIC_HCL_IAM_TOKEN_URL=<HCL_IAM_TOKEN_URL>
NEXT_PUBLIC_HCL_IAM_LOGOUT_URL=<HCL_IAM_LOGOUT_URL>
NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=http://localhost:3000/auth/callback
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI=http://localhost:3000
NEXT_PUBLIC_HCL_IAM_SCOPES=openid profile email roles
```

Production example:

```env
NEXT_PUBLIC_HCL_IAM_REDIRECT_URI=https://<your-domain>/auth/callback
NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI=https://<your-domain>
```

The redirect URI configured in frontend must exactly match the redirect URI registered in HCL IAM.

## 6. Backend JWT Validation Requirements

FastAPI expects the frontend to send the HCL IAM access token on API calls:

```text
Authorization: Bearer <access_token>
```

The backend must validate:

```text
1. Token signature using HCL IAM JWKS
2. iss equals HCL_IAM_ISSUER
3. aud contains HCL_IAM_AUDIENCE
4. exp is not expired
5. nbf/iat valid if present
6. tenant claim exists or a permitted tenant can otherwise be resolved
7. role/group claim exists when IAM roles are required
8. user is mapped to internal user/tenant membership
9. backend RBAC permission is allowed
```

The current implementation requires `exp` and `sub`, validates signature, issuer, audience, expiry, `nbf`, and configured asymmetric algorithms, then resolves the request context through tenant membership data.

## 7. Role and Group Mapping

SBOM Analyser normalizes role names by uppercasing them and replacing hyphens/spaces with underscores. The backend roles stored in tenant memberships are the unprefixed values shown in the right column. If HCL IAM groups use `SBOM_` prefixes, configure an IAM token mapper or administrative provisioning process so users receive the matching internal SBOM Analyser role.

| HCL IAM Role/Group | SBOM Analyser Role |
| --- | --- |
| `SBOM_PLATFORM_ADMIN` or `PLATFORM_ADMIN` | `PLATFORM_ADMIN` |
| `SBOM_TENANT_ADMIN` or `TENANT_ADMIN` | `TENANT_ADMIN` |
| `SBOM_SECURITY_ANALYST` or `SECURITY_ANALYST` | `SECURITY_ANALYST` |
| `SBOM_DEVELOPER` or `DEVELOPER` | `DEVELOPER` |
| `SBOM_VIEWER` or `VIEWER` | `VIEWER` |

Important implementation detail: IAM token roles currently identify platform-admin access when the normalized token role is `PLATFORM_ADMIN`. Tenant roles are resolved from internal `tenant_users` memberships after the user and tenant are mapped. Provision tenant memberships through the tenant administration APIs/UI.

### PLATFORM_ADMIN

```text
- all tenant access
- lifecycle provider admin
- vendor lifecycle records
- user/tenant administration
- audit logs
- platform administration
```

### TENANT_ADMIN

```text
- tenant projects
- SBOM upload/manage/delete/export
- repair workspace
- lifecycle refresh and overrides
- remediation
- tenant users
- schedules and analysis
```

### SECURITY_ANALYST

```text
- upload/read/update/export SBOMs
- vulnerability analysis
- lifecycle read/override and provider test/read
- VEX/remediation
- repair workspace
- schedules and dashboard
```

### DEVELOPER

```text
- read assigned tenant projects
- read SBOMs and components
- read repair workspace
- read findings, VEX, remediation, schedules, and dashboard
```

### VIEWER

```text
- read-only dashboard
- read-only SBOMs and components
- read repair workspace
- read reports/analysis views
```

These roles and permissions come from `app/core/permissions.py`.

## 8. Tenant Mapping

HCL IAM tokens must contain a tenant/company claim unless the user is explicitly configured as a platform admin and selects an allowed tenant. The backend maps the configured `HCL_IAM_TENANT_CLAIM` value to an internal tenant by matching `tenants.external_iam_tenant_id`, tenant slug, or tenant id where applicable.

All SBOMs, projects, lifecycle data, repair workspaces, audit logs, and remediation records must be tenant-scoped in backend queries.

Example token claims:

```json
{
  "sub": "hcl-user-id",
  "email": "user@hcl.com",
  "preferred_username": "user1",
  "tenant_id": "tenant-1",
  "roles": ["SECURITY_ANALYST"]
}
```

Users without a valid tenant claim or tenant membership are rejected with `403 Tenant access denied` unless they are platform admins with access to the selected tenant.

## 9. `/api/auth/me` Verification

Use this endpoint to verify the backend resolved the authenticated user, active tenant, roles, and permissions:

```http
GET /api/auth/me
```

Actual response shape:

```json
{
  "user_id": 1,
  "external_user_id": "hcl-user-id",
  "email": "user@hcl.com",
  "display_name": "User Name",
  "tenant_id": 1,
  "external_tenant_id": "tenant-1",
  "roles": ["SECURITY_ANALYST"],
  "permissions": [
    "sbom:read",
    "sbom:upload",
    "sbom:repair:read",
    "sbom:repair:update"
  ],
  "is_platform_admin": false
}
```

Curl example:

```bash
curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8000/api/auth/me
```

If the user can access multiple tenants, pass the selected tenant:

```bash
curl \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Tenant-ID: <tenant-id-or-slug-or-external-id>" \
  http://localhost:8000/api/auth/me
```

## 10. Local Startup With IAM Enabled

Backend:

```bash
cd /Users/ferozebasha/sbom
source .venv/bin/activate

export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
export APP_SECRET_KEY="dev-secret-change-this"
export AUTH_ENABLED=true
export DEV_DEFAULT_TENANT=false

export HCL_IAM_ISSUER="<issuer>"
export HCL_IAM_AUDIENCE="sbom-analyser-api"
export HCL_IAM_JWKS_URL="<jwks-url>"
export HCL_IAM_CLIENT_ID="<client-id>"

python -m alembic upgrade head
python run.py
```

Frontend:

```bash
cd frontend
npm run dev
```

Open:

```text
http://localhost:3000
```

Expected flow:

```text
1. Click Login
2. Redirect to HCL IAM
3. Login succeeds
4. Redirect back to /auth/callback
5. Frontend stores active session/token
6. Frontend calls /api/auth/me
7. Backend returns user, tenant, roles, permissions
```

## 11. Local Development Without IAM

Use dev-only mode when you need to run the app without HCL IAM:

Backend:

```env
AUTH_ENABLED=false
DEV_DEFAULT_TENANT=true
```

Frontend:

```env
NEXT_PUBLIC_AUTH_ENABLED=false
```

Use this only for local development. Do not deploy production with authentication disabled.

## 12. CORS Configuration

Local:

```env
CORS_ORIGINS=http://localhost:3000
```

Production:

```env
CORS_ORIGINS=https://<your-frontend-domain>
```

Do not use wildcard CORS in production.

## 13. Security Rules

- Do not expose a client secret in the frontend.
- Do not log access tokens.
- Do not store tokens in server logs.
- Validate issuer, audience, signature, and expiry.
- Use asymmetric signing algorithms such as `RS256`; do not use HMAC algorithms for HCL IAM.
- Use HTTPS in production.
- Restrict CORS.
- Keep `APP_SECRET_KEY` strong and private.
- Do not commit `.env` files.
- Backend RBAC must enforce all protected actions.
- Tenant isolation must be enforced in backend queries.

## 14. Troubleshooting

| Problem | Cause | Fix |
| --- | --- | --- |
| Login redirects but callback fails | Redirect URI mismatch | Register exact callback URL in HCL IAM |
| Backend returns 401 | Missing/invalid token | Check `Authorization` header |
| Backend returns 401 invalid issuer | Issuer mismatch | Set correct `HCL_IAM_ISSUER` |
| Backend returns 401 invalid audience | Audience mismatch | Set correct `HCL_IAM_AUDIENCE` |
| Backend returns 403 | User authenticated but lacks permission | Check role/membership mapping |
| User sees no tenant data | Tenant claim missing or mapped wrong | Check `HCL_IAM_TENANT_CLAIM` and tenant membership |
| JWKS fetch fails | JWKS URL wrong/network blocked | Check `HCL_IAM_JWKS_URL` |
| Startup fails with JWKS HTTPS error | JWKS URL is not HTTPS | Use the production HTTPS JWKS URL from HCL IAM |
| CORS error | Frontend origin not allowed | Set `CORS_ORIGINS` |
| Logout not working | Logout URL missing/wrong | Configure HCL logout endpoint |
| Token exchange fails | Client, PKCE, or CORS setting mismatch | Check SPA client, web origin, redirect URI, and token endpoint |

## 15. Verification Checklist

Backend:

```text
[ ] AUTH_ENABLED=true
[ ] DEV_DEFAULT_TENANT=false
[ ] HCL_IAM_ISSUER configured
[ ] HCL_IAM_JWKS_URL configured
[ ] HCL_IAM_AUDIENCE configured
[ ] HCL_IAM_CLIENT_ID configured
[ ] JWT validation works
[ ] /api/auth/me works
[ ] RBAC enforced
[ ] Tenant isolation enforced
```

Frontend:

```text
[ ] NEXT_PUBLIC_AUTH_ENABLED=true
[ ] NEXT_PUBLIC_API_URL configured
[ ] Client ID configured
[ ] Authorization URL configured or issuer-derived endpoint verified
[ ] Token URL configured or issuer-derived endpoint verified
[ ] Redirect URI configured
[ ] Login button works
[ ] Callback works
[ ] Access token sent to backend
[ ] Logout works
```

HCL IAM:

```text
[ ] SPA client created
[ ] Authorization Code + PKCE enabled
[ ] Redirect URI added
[ ] Web origin added
[ ] API audience configured
[ ] Roles/groups assigned to test user
[ ] Tenant claim configured
```
