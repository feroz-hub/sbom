# Native IAM Phase 2

Native authentication is additive to HCL.CS. Existing users, identity tables,
tenant memberships and role assignments are reused. Alembic head remains
`060_native_identity_foundation`; no schema change is required.

## Configuration and deployment

See `.env.native-iam.example`. Enable `NATIVE_USER_CREATION_ENABLED` to invite and
activate accounts; enable `NATIVE_AUTH_ENABLED` in both API and BFF for login.
`AUTH_ENABLED=true`, the existing HCL configuration, DATABASE authorization modes,
and fail-closed resolution are required. Inject a >=2048-bit RSA PEM private key
as `NATIVE_JWT_PRIVATE_KEY` through the deployment secret manager. No key is supplied
or committed by this implementation. Keep the native issuer distinct from HCL.
Only RS256 is accepted. TTL defaults to 900 seconds (60–3600 permitted).

The BFF requires HTTPS and `APP_ORIGIN` set to its canonical origin. It falls back
to the configured HCL redirect origin, then https://localhost:3000. POST login,
activation, logout and generic proxy mutations reject absent/untrusted Origin.
Keep TLS, SameSite and cookie security enabled. The backend native endpoints use
JSON credentials or a single-use token, not cookies; they do not consume sessions.
Deploy the existing request rate limiter/reverse proxy limits in addition to
per-account lockout. Unknown-email traffic still consumes Argon2 resources.

## API

| Method | Path | Access |
|---|---|---|
| POST | `/api/auth/native/login` | Public credentials |
| POST | `/api/auth/native/activate` | Public activation token and password |
| POST | `/api/platform/native-users` | Explicit `platform:user:manage_status` |
| POST | `/api/tenants/{tenant_id}/native-users` | Explicit `tenant:user:invite`, selected tenant admin or platform admin |
| POST | `/api/tenants/{tenant_id}/memberships` | Same permission; stable local `user_id` plus `role_codes` |
| POST | `/api/tenants/{tenant_id}/native-users/{user_id}/resend-activation` | Same permission and scoped existing membership |

Creation accepts `first_name`, `last_name`, `email`, `phone`, `tenant_id`, and
`role_codes[]`. The payload tenant must match the URL on tenant creation routes.
Platform operations can explicitly target other tenants and record actor/tenant
in audits. The existing delegation service rejects TENANT_ADMIN and PLATFORM_ADMIN
for tenant admins and PLATFORM_ADMIN for platform-created tenant memberships.
Custom assignable tenant roles continue to follow the existing catalog policy.
Duplicate native identifiers return 409; use the existing local user ID to add a
membership. Profile email never automatically links HCL and native identities.

Creation commits identity, pending account, membership, roles, activation token
and audits together. SMTP runs after commit through the shared email sender.
The response includes `delivery.status` and `delivery.error_code`; a failed or
skipped delivery leaves the pending account intact. Administrators use resend,
which invalidates the previous token and starts a new five-hour window. Existing
email cooldown, hourly and daily settings apply. Delivery is synchronous; there
is no generic activation outbox in this slice. A process crash after commit can
require authorized resend. Repeating creation cannot create another identity.

## Authentication and authorization

Activation consumes the hashed token conditionally while holding the user lock.
It verifies purpose, expiry, consumption/invalidation, identity email snapshot,
current profile email and pending status. Credential creation, email verification,
account activation and audit all commit atomically. Passwords require at least
12 characters (configurable upward) and at most 1024 UTF-8 bytes. They are not
normalized or truncated. Argon2id uses the existing RFC 9106 low-memory profile.
There is no additional composition rule or breached-password lookup in this phase.

Login resolves only the canonical NATIVE identifier and locks user then credential
rows. Failed attempts cannot lose increments. Five failures default to a global
900-second lock, including the final platform administrator. This security event
intentionally bypasses administrative last-admin protections. Administrative
lifecycle operations retain those protections. An expired temporary lock clears
only on a valid password, with counters/timestamps cleared and USER_UNLOCKED audit.
A manual indefinite lock does not automatically expire. Lifecycle manual unlock
remains supported. Unknown, pending, disabled and locked failures return the same
credential error and perform a dummy Argon2 verification where practical.

JWT claims are `iss`, stable local `sub`, `aud`, `iat`, `exp`, unique `jti`,
`auth_provider=NATIVE`, and integer `security_version`. No tenant role or permission
snapshot is issued. Signature, fixed algorithm, issuer, audience, dates, required
claims and claim types are checked. An unverified issuer selects a fixed validator
only; failed native verification never falls back to HCL. The provider-neutral
principal loads existing native users or provisions HCL identities, then converges
into the same authorization state and CurrentContext pipeline.

Every authenticated native request reloads ACTIVE status, native identity and
credential security version. Lock, disable/re-enable, force-password-change and
lifecycle password change invalidate older tokens. Role changes do not require
new tokens: the selected tenant's membership and current role-permission union
are resolved from the database on every request. Native configuration rejects
legacy authorization modes and non-fail-closed resolution.

## Frontend and security boundaries

`/native-sign-in`, `/activate-account`, and `/settings/native-users` provide the
minimal UI. Existing platform/tenant admin pages link to the invite form. HCL
sign-in remains available. Activation URLs carry the raw token only in the fragment,
so access-log request URLs omit it. Successful activation clears that fragment.
The frontend never stores JWTs in browser storage. Native BFF login rotates an
opaque HttpOnly Secure SameSite=Lax cookie; tokens remain in the existing in-memory
server store. Native sessions expire without HCL refresh or revocation calls.
The generic BFF proxy blocks native credential endpoints, including normalized
paths, to avoid exposing their token response. Native validation errors omit raw
input. Existing request logging omits bodies, headers and query strings.

The session store remains process-local. Restarts lose sessions; multiple BFF
instances require sticky routing until a shared store is introduced. There is no
native refresh token; users sign in again after access-token expiry. A signing-key
replacement immediately rejects old tokens; overlapping key rotation is deferred.

Audits include NATIVE_USER_CREATED, ACCOUNT_ACTIVATION_TOKEN_CREATED,
ACCOUNT_ACTION_TOKEN_CONSUMED, ACCOUNT_ACTIVATION_RESENT, PASSWORD_SET,
ACCOUNT_ACTIVATED, LOGIN_SUCCESS, LOGIN_FAILED, USER_LOCKED, USER_UNLOCKED,
TENANT_MEMBER_ADDED and ROLE_ASSIGNED, plus existing role history events.
Audit failure rolls back security mutations. No password, raw activation token,
private key or JWT is included in these audit records.

## Deferred and Phase 3

Password reset/forgot-password, MFA, object ACLs, full user management, automatic
provider linking, shared sessions and SF cutover remain deferred. Phase 3 should
address durable/shared sessions, delivery recovery, key rotation, layered abuse
controls and broader administrator lifecycle UI before production cutover.
