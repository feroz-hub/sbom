# Microsoft Entra Phase 1 — HCL workforce directory

## Scope and authority

This opt-in provider accepts delegated API access tokens from **one configured HCL
Microsoft Entra directory**. It coexists with Native and HCL.CS. Olympus, MedTech
and other SBOM tenants remain application tenants, unrelated to the Entra tenant ID.

Microsoft authenticates the person, including password, MFA and Conditional Access.
SBOM Analyzer never receives the Microsoft password. Microsoft groups, app roles,
email domain, department and tenant claims do not grant SBOM authority.

```text
Feroze → Microsoft PKCE sign-in → API access token → signature/claims validation
       → UserIdentity(MICROSOFT_ENTRA, issuer, oid) → existing IAMUser
       → AuthContextService → local status → local memberships/roles/permissions
```

An unknown immutable identity creates exactly one `IAMUser` in `PENDING` and one
`UserIdentity`. It creates no credential, platform grant, membership or role.
The existing unique `(provider_type, issuer, subject)` constraint arbitrates
concurrent provisioning; a losing transaction rolls back its candidate user.
Email is display/search metadata and never links users. An existing Native or
HCL.CS user with the same email remains a separate user. This phase has no linking UI.

Signed member-directory authentication satisfies the shared identity-verification
gate, but does **not** mark `email_verified` true or claim mailbox ownership.
Entra-only users have `verification_required=false`; Native/HCL.CS still require
their existing email verification. The shared eligibility policy is used by access
resolution, administrator counts, role assignment and candidate selection.

## Configuration

Supply these values to both the backend and frontend/BFF runtime:

| Variable | Value |
| --- | --- |
| `ENTRA_ENABLED` | `false` by default; explicitly set `true` to enable |
| `ENTRA_TENANT_ID` | HCL directory UUID, lowercase canonical form |
| `ENTRA_FRONTEND_CLIENT_ID` | SPA registration UUID |
| `ENTRA_API_CLIENT_ID` | Separate API registration UUID; v2 access-token audience |
| `ENTRA_API_SCOPE` | Full delegated API scope, e.g. `api://<API-ID>/access_as_user` |

Also use `AUTH_ENABLED=true`, `DEV_DEFAULT_TENANT=false`, database authorization
catalogue/role assignment and their fail-closed settings. The BFF requires
`NEXT_PUBLIC_AUTH_ENABLED=true`, canonical HTTPS `APP_ORIGIN`, and its existing
`SBOM_API_URL`. Set `HCL_AUTH_ENABLED=false` and `NEXT_PUBLIC_HCL_AUTH_ENABLED=false`
only when HCL.CS login is intentionally unused. Native flags are independent.
Leave Native enabled for the existing Platform Administrator/bootstrap workflow.

Production BFFs require the existing shared Redis session store, Redis URL and
32-byte session encryption key. No Entra client secret is used. When Entra is
disabled, Microsoft configuration and discovery are not required. When enabled,
invalid/missing configuration fails startup safely without printing values.

For `python scripts/dev.py`, add the five `ENTRA_*` settings to the ignored
`.env.dev.local`. The launcher retains these settings and passes the same values
to its children; it continues to enable Native and disable HCL.CS locally. Register
the launcher's actual HTTPS origin, including its port. Do not put real IDs or
secrets into committed examples. Restart processes after changing configuration.

## Required HCL registration work

Ask the HCL Entra team for:

1. The single workforce Directory/Tenant ID.
2. A **single-tenant SPA** registration and its Application/Client ID.
3. A distinct single-tenant API registration and its Application/Client ID.
4. API Application ID URI and one delegated scope; grant/consent the SPA access.
5. API access-token version **2** (`api.requestedAccessTokenVersion=2`).
6. API access-token optional claim **`acct`**. This phase requires `acct=0`
   (directory member); guests (`acct=1`) and missing account type fail closed.
7. Approved SPA redirect URI: `<APP_ORIGIN>/auth/entra-callback`, including exact
   scheme, hostname, path and port. Register it as SPA, not Web.
8. Workforce assignment/Conditional Access policy and approved member/guest test
   accounts for live acceptance. Do not use customer directories or B2B federation.

The authority is derived as `https://login.microsoftonline.com/<TENANT-ID>`.
There is no `/common`, `/organizations` or `/consumers` option. Do not supply a
Microsoft Graph scope or `.default` instead of the delegated SBOM API scope.

## Browser and session behavior

`/sign-in` offers Microsoft and the enabled existing providers. MSAL Browser uses
authorization code + PKCE in a popup, with an in-memory token cache and no logging
callback. It requests the SBOM API scope. Only `accessToken` goes in a same-origin
POST to `/api/auth/entra`; the ID token is never an API credential.

The BFF sends that token as an Authorization bearer header to FastAPI's
`/api/auth/entra/session`. FastAPI validates it before provisioning. The BFF stores
the access token using the existing protected session store and returns only an
opaque HttpOnly/Secure/SameSite=Lax cookie. MSAL's cache is cleared after exchange;
no Microsoft refresh token is retained by the BFF. Transient browser possession
of the access token is required by the SPA flow; it is not placed in application
localStorage, query strings or browser cookies.

The standalone callback route serves Microsoft's installed redirect bridge from
this application's origin. It runs without React auth guards or application code.
Keep `Cache-Control: no-store` and **do not add Cross-Origin-Opener-Policy** to this
callback at ingress. Do not log callback query strings, Authorization headers,
session cookies, exchange request bodies or MSAL diagnostic payloads in proxies/APM.

Entra sessions expire with the API access token. No silent BFF refresh is added;
sign in again through Microsoft when expired. Existing Microsoft SSO may avoid a
password prompt, subject to Conditional Access. HCL refresh remains on its existing
provider branch. Local logout destroys the BFF session and clears its cookie;
it does not log the person out of Microsoft applications or revoke a copied access
token. Every API request still checks current local status and database authority.

## Approval and access

1. First valid sign-in returns `USER_ACCESS_PENDING`. The UI says authentication
   succeeded and asks the user to wait for Platform Administrator approval.
2. In Administration → Users, filter Provider **Microsoft Entra**, Status **PENDING**.
   Inspect the profile and approve the account using the existing status endpoint.
3. Approval changes only `PENDING → ACTIVE`. With no memberships/platform grant,
   the user receives `NO_TENANT` and cannot access business data.
4. Use the existing tenant-management user search and membership/role controls to
   assign Olympus and the approved local role, e.g. `SECURITY_ANALYST`.
5. The user selects/retries Olympus. Permissions come from the local catalogue.
   MedTech is denied until a separate membership and role assignment exists.

Global suspension/disable applies on the next API request, even with an unexpired
Microsoft token. Existing identities are never recreated to bypass those states.
Resuming an account restores only independently active memberships. Last-platform-
administrator and last-tenant-administrator protections remain in force.

| State | Context / business response |
| --- | --- |
| Pending Entra account | `USER_ACCESS_PENDING`; business API 403 |
| Suspended account | `USER_SUSPENDED`; business API 403 |
| Disabled account | `ACCOUNT_DISABLED` / `IAM_ACCOUNT_DISABLED`; business API 403 |
| Active, no assigned access | `NO_TENANT` / `IAM_NO_TENANT`; business API 403 |
| Missing operation permission | Existing permission-denied response, 403 |
| Invalid/expired token | Authentication failure, 401 |

Provisioning and identity ownership are audited with the existing
`IAM_USER_PROVISIONED` and `IAM_EXTERNAL_IDENTITY_LINKED` events and safe provider
metadata. The latter records a newly created identity's ownership, **not linking
to a pre-existing account**. Approval, suspension, disable, membership and role
changes reuse existing audit transactions; audit failure must roll back mutations.

## Validation and rollout

Migration `063_microsoft_entra_identity` extends existing check constraints only.
Run `alembic upgrade head` through the approved migration process after backup and
target verification. It retains identity uniqueness and all existing data.
Downgrade refuses to discard Entra identities or suspended accounts. Operational
rollback is to disable Entra on API/BFF and retain the additive schema and data.

Token validation checks RS256, Microsoft discovery/JWKS, key issuer when supplied,
exact v2 issuer/audience/directory, `exp`, `iat`, optional `nbf`, canonical `oid`,
nonempty subject, delegated scope, authorized SPA `azp`, and member `acct`.
Application-only tokens and frontend ID tokens are rejected. Unknown signing keys
use PyJWKClient's JWKS refresh; network/validation failures fail closed.

Automated tests sign temporary RSA tokens and supply mocked Microsoft JWKS while
exercising actual validation and PostgreSQL provisioning. No production simulator,
impersonation endpoint or committed private key is added. Run:

```sh
.venv/bin/python -m pytest -q tests/test_entra_auth.py
cd frontend
npm test -- --maxWorkers=2 --testTimeout=15000
npx tsc --noEmit
npm run build
```

On Windows use `.venv\Scripts\python.exe`. The initial unchanged-branch baseline
at `9a7ade96c89a769d2565328aa8c317e31e2c7c0e` had 171 passing backend tests and
one existing failure: `test_identity_administration.py::test_last_active_tenant_admin_is_protected`
(403 received, 409 expected for role replacement). The frontend baseline passed
1,036 tests across 141 files. See the acceptance report for final run results.

Before production acceptance, perform real HCL sign-in with MFA/Conditional Access,
member/guest rejection, popup callback on supported browsers, first-login pending,
administrator approval, explicit Olympus role assignment, MedTech denial, account
suspend/disable, session expiry/logout and a second BFF replica. Confirm all API
replicas share the same Entra configuration, Microsoft metadata is reachable, proxy
logging is redacted, Redis is fail-closed, and deployment clocks are synchronized.
Automated mocks/builds do not replace this registration and live acceptance work.

## Microsoft references

- [Access token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- [Account type optional claim](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
- [MSAL redirect bridge](https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-browser/docs/redirect-bridge.md)

Multi-directory/customer Entra, automatic provider linking, Graph synchronization,
SCIM, group/app-role authorization mapping and HCL.CS removal remain out of scope.
