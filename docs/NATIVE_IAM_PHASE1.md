# Native IAM foundation — Phase 1

## Architecture and scope

`IAMUser` remains the single local account. `UserIdentity` adds HCL_CS and
NATIVE identities beneath it; tenant memberships, platform grants, role
assignments, the authorization catalog and tenant guards remain authoritative.
This phase provides schema and internal services only. It exposes no native
registration, login, activation, reset, or administration HTTP endpoints and
adds no frontend routes. Enabling a flag does not create such endpoints.

HCL OIDC authorization-code/PKCE, issuer/audience/JWT validation, BFF sessions
and logout are unchanged. Existing issuer/subject resolution still decides which
IAMUser owns an HCL login. Provisioning additionally mirrors that already-resolved
identity into `user_identities`; it never searches by email to link accounts.
Historical external columns are retained, with `external_iam_user_id` nullable
so native-only accounts need no fabricated HCL subject.

## Field authority and uniqueness

* `IAMUser.email` remains the application contact/profile address. HCL trusted
  claim synchronization retains its current authority over HCL user profiles.
* `IAMUser.normalized_email` is the derived `email.strip().lower()` search and
  data-quality value. ORM inserts/updates maintain it; migrations and any future
  bulk/Core writers must maintain it explicitly. Blank profiles become NULL.
* `UserIdentity(provider_type=HCL_CS, issuer, subject)` is the external identity
  authority. Its composite database uniqueness is independent of email.
* `UserIdentity(provider_type=NATIVE).provider_identifier` is the canonical
  native login email. Its partial unique index is active immediately and protects
  concurrent enrollment. ORM writes use the existing email validator plus
  trim/lowercase normalization; a check constraint rejects noncanonical writes.
* Global uniqueness on `IAMUser.normalized_email` is deferred. Existing HCL
  profiles may share an address, and future HCL profile changes must not fail
  merely because that address is another person's native login identifier.
  Native login must query the native identity key, never the profile email.
* Future native enrollment must explicitly initialize contact email and native
  identifier consistently. Later native email changes need their own verified,
  audited operation. HCL profile synchronization must never rewrite the native
  login identifier or link another person.
* First name, last name and phone are nullable profile fields. Display name,
  department, `email_verified`, `email_verified_at`, and `verification_required`
  are reused. Names are not inferred by splitting display names.

No plus-address stripping, dot removal, provider-specific alias rules, automatic
account merging or email-only linking is performed. One person can explicitly
own one identity per provider; Phase 1 exposes no linking API.

## Migration and operator preflight

Migration `060_native_identity_foundation` follows the inspected head
`059_vex_analyzer_sources`. It adds the profile fields and three tables:
`user_identities`, `native_user_credentials`, `account_action_tokens`.
It preserves user IDs, external columns, memberships, roles, grants and audit
references. Legacy `PENDING` records keep their exact status and meaning.

Before deployment, inject DATABASE_URL securely and run:

```sh
python scripts/check_native_identity_data.py
alembic upgrade head
```

The read-only preflight outputs local user IDs for duplicate canonical emails and
incomplete legacy identities. Exit 1 means collisions require operator review;
it does not modify data. The online migration repeats the collision inspection
under a table lock and warns that global profile uniqueness remains deferred.
No cleanup is required to preserve HCL login, but collisions must be explicitly
reviewed before native enrollment and any future global uniqueness migration.

Known issuer/subject pairs are backfilled. Incomplete legacy pairs are reported
and deferred until trusted HCL provisioning supplies the missing values. No
issuer is guessed. Offline SQL generation is refused because inspection is
required. Schedule deployment with the table-lock duration in mind.

Downgrade is allowed for an HCL-only deployment without new profile/security
data. It refuses before deleting anything if native identities, credentials,
tokens, new statuses, or first/last-name/phone data exist. Export and explicitly
remediate that data before retrying. Never coerce native users into fake HCL users.

## Status model

The centralized validator accepts only these transitions:

| From | To | Additional condition |
|---|---|---|
| PENDING | ACTIVE | Explicit legacy administrator approval |
| PENDING_EMAIL_VERIFICATION | ACTIVE | Activation completed |
| PENDING_EMAIL_VERIFICATION | DISABLED | Authorized lifecycle caller |
| ACTIVE | LOCKED / DISABLED / FORCE_PASSWORD_CHANGE | Authorized lifecycle caller |
| LOCKED | ACTIVE | Explicit unlock authorization |
| LOCKED | DISABLED | Authorized lifecycle caller |
| DISABLED | ACTIVE | Explicit enable authorization |
| FORCE_PASSWORD_CHANGE | ACTIVE | Successful password update |
| FORCE_PASSWORD_CHANGE | DISABLED | Authorized lifecycle caller |

Unknown states, self-transitions and unlisted transitions fail closed. Existing
idempotent platform status APIs retain their no-op behavior. Legacy PENDING is
not equivalent to PENDING_EMAIL_VERIFICATION. Activation also requires a stored
credential and completed email verification before the mutation helper enables
the user. Phase 2 must compose password storage, verification, token consumption
and state transition in one transaction.

The mutation helper reuses existing last-administrator protections and lock
ordering for access-removing transitions, updates native security version, and
records authorization audit in the same transaction. The HCL authorization
resolver blocks new non-active states rather than accidentally falling through
to membership authority. Native-state UI messaging belongs to Phase 2.

## Credentials and tokens

`NativeUserCredential` stores Argon2id hashes separately from IAMUser. The
password service uses argon2-cffi's RFC 9106 low-memory profile (64 MiB, three
iterations, parallelism four), generated salts, verification and rehash checks.
It never normalizes or truncates passwords. It limits input to 1024 UTF-8 bytes;
minimum-strength/breached-password policy and login throttling belong to Phase 2.
Encoded hashes and passwords are never written to audit. The application engine
hides SQL parameter values in logs and formatted database exceptions.

Account action tokens use 32 random bytes, URL-safe encoding and SHA-256 hashes
in storage. Raw values are returned once in a result whose repr omits the token.
Token lookups bind user ID, purpose and native email snapshot. Activation lasts
exactly 18,000 seconds using its own setting. Reissue invalidates the prior token.
Conditional UPDATE plus row locking permits only one concurrent consumer.
Expiry, changed native email, consumed/invalidated tokens, wrong user, wrong
purpose and ineligible account state are rejected. PASSWORD_RESET and EMAIL_CHANGE
are reserved purposes; their services are not enabled in this phase.

These internal services never commit. Their savepoints include required audit
writes, so audit failure cannot leave a successful token/state mutation even
when a caller catches the exception. Existing HCL EmailVerificationToken and
its 24-hour setting remain unchanged.

## Delegation, audit and tenant safety

Platform Admin can assign TENANT_ADMIN, SECURITY_ANALYST, DEVELOPER and VIEWER.
Tenant Admin can assign SECURITY_ANALYST, DEVELOPER and VIEWER. The shared
validator runs in grant/replace and request-driven initial membership assignment
paths, including legacy membership routes. Catalog scope, protected-role,
version and last-admin validation remain in place. Internal system seed and
platform-authorized tenant creation retain their bootstrap paths.
Existing custom assignable tenant roles continue to use the database catalog;
the new rule restricts administrative delegation without replacing that catalog
with a hardcoded role allowlist.

Lifecycle audit vocabulary includes NATIVE_USER_CREATED, activation token
creation, ACCOUNT_ACTIVATED, PASSWORD_SET/CHANGED, lock/unlock, disable/enable,
forced password change and role assignment/removal. Events for operations not
implemented yet are vocabulary only. Existing role audit event names/history are
retained. No parallel audit subsystem is added.

New identity/credential/token tables are global account data, like IAMUser;
they are not TenantOwnedMixin records and cannot rely on ORM tenant filters.
There are no new tenant-facing endpoints. Internal services require an already
authorized caller and explicitly filter by user ID (plus token purpose/hash).
Operator preflight/migration intentionally inspect all accounts. Phase 2 must
authorize tenant administrators through current context and tenant membership
before calling these primitives; it must not expose arbitrary user-ID access.
Existing X-Tenant-ID selection, platform override, membership predicates and ORM
SELECT/write guards are unchanged.

## Safe defaults and Phase 2

```dotenv
NATIVE_AUTH_ENABLED=false
NATIVE_USER_CREATION_ENABLED=false
NATIVE_ACCOUNT_ACTIVATION_TTL_SECONDS=18000
```

Phase 2 should add administrator-authorized native user creation and an atomic
activation/set-password API, using these models, delegation rules and audits.
Creation must validate the actor, tenant, normalized-email collisions and roles;
email delivery needs an idempotent outbox. Add the minimal activation UI only
after the backend transaction is tested. Native login/session issuance should
remain a separate reviewed slice with rate limits, password policy, CSRF/origin
checks, session revocation and deployment-ready session storage. HCL remains
available throughout. Account linking, per-resource ACLs, MFA and SF removal
remain out of scope.
