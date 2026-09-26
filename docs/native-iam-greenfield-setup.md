# Fresh Native IAM staging setup

No HCL/SF user migration, email-based linking, copied tenant data or source removal is part of this procedure. Do not drop an existing database. Local acceptance is not production readiness.

## Prerequisites and target

Use an approved PostgreSQL server, a separately named empty staging database, an operator identity with database-creation/migration privileges, Redis, the existing Celery worker/Beat deployment and an approved mail destination. Identify the server/database by safe identifiers before executing commands. Preserve any existing database until its disposal is separately authorized. Recoverable backups remain prudent even for test data.

The inspected local environment has PostgreSQL 16 in `sbom-postgres-1` (host port 55439) and existing Mailpit SMTP at loopback port 1025, captured-mail UI at loopback port 8025. These are local observations, not production endpoints. No MailKit-based service was found; MailKit is not introduced. Do not assume local credentials apply elsewhere.

Create the new database using the normal PostgreSQL operator tooling (`createdb` or the approved platform console). Obtain connection credentials through secret management; do not paste a connection string into a ticket, command history or repository. Export `DATABASE_URL` securely to the new database, and verify database name/server and that no public application tables exist. Use matching PostgreSQL-version backup/restore tools.

## Configuration

Use `.env.native-iam.example` as a checklist, supplying real secrets securely:

- `AUTH_ENABLED=true`, `DEV_DEFAULT_TENANT=false`.
- `NATIVE_AUTH_ENABLED=true`, `NATIVE_USER_CREATION_ENABLED=true`.
- `HCL_AUTH_ENABLED=false`; no HCL issuer/client/audience credentials required for Native-only API startup.
- BFF: `NEXT_PUBLIC_AUTH_ENABLED=true`, `NEXT_PUBLIC_HCL_AUTH_ENABLED=false`. Build with these public flags and deploy the same values. HCL login redirects to Native sign-in; HCL code remains available in other deployments.
- Native JWT issuer/audience, active kid, RSA private signing key and matching `NATIVE_JWT_PUBLIC_KEY`; optional bounded public-key overlap configuration. Never commit keys.
- Database-backed authorization catalogue and tenant-role assignment modes, both fail closed.
- `NATIVE_SECURITY_OUTBOX_ENABLED=true`, a secret 32-byte base64 outbox AES-GCM key, bounded retry count, HTTPS activation/reset URLs matching canonical `APP_ORIGIN`.
- `EMAIL_PROVIDER=smtp`, `EMAIL_DELIVERY_ENABLED=true`, sender/support settings and approved transport. Unsupported provider values fail closed; Microsoft Graph is not implemented and needs no credentials here.
- For existing local Mailpit only: SMTP host `127.0.0.1`, port `1025`, TLS/STARTTLS disabled and no SMTP credentials. In containers use the approved reachable test-service hostname, not an assumed loopback. Do not use these test settings for external production mail. Native production validation requires secure SMTP transport; the isolated Mailpit test is explicitly not production mode.
- Shared Redis session store, 32-byte base64 session encryption secret, session Redis URL, shared auth rate-limit Redis URL, canonical HTTPS origin, Celery broker/worker/Beat configuration and readiness probes.
- `NATIVE_PLATFORM_BOOTSTRAP_ENABLED=false` initially; enable explicitly only for the operator enrollment/recovery window.

The API remains authenticated when HCL is disabled. HCL bearer tokens fail closed; Native tokens still use cryptographic validation plus current database authority. HCL-enabled deployments retain their existing configuration requirements.

## Schema and normal seeds

From the repository root with the project virtual environment and securely exported target URL:

```sh
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic current
```

Expected head: `062_native_platform_bootstrap`. On an empty PostgreSQL database, the Alembic environment installs the existing frozen revision-047 schema, stamps that supported baseline and applies 048 through current head. Historical migration 001 used live ORM metadata and is not replayed for fresh PostgreSQL. Migrations 001–061 remain unchanged. This is the repository's existing expected-bootstrap approach, now reachable through ordinary Alembic upgrade; it does not import old identity data.

Migration 048 seeds and validates the immutable authorization catalogue transactionally. Start the normal authenticated API to initialize master/reference data (`app.main` startup); do not use development/auth-disabled seed mode. Verify the five role codes PLATFORM_ADMIN, TENANT_ADMIN, SECURITY_ANALYST, DEVELOPER, VIEWER and catalogue mappings. Verify zero old identities/memberships. No manual grants or password inserts.

Start the normal API, Redis, Celery security-mail worker and Beat, and production-built BFF through the existing deployment tooling. Check backend liveness, IAM readiness/worker heartbeat and BFF `/api/ready`. Configure ingress to block direct backend access and trust only approved proxy ranges. Do not invent HCL settings to satisfy startup.

## Operator bootstrap

Enable `NATIVE_PLATFORM_BOOTSTRAP_ENABLED=true` in the operator environment. Authentication, Native enrollment and encrypted outbox must also be enabled. Use only approved identity information. Example values below are placeholders, not permission to send external mail:

```sh
.venv/bin/python scripts/bootstrap_native_platform_user.py \
  --confirm-database sbom_native_greenfield create \
  --email platform@approved-test-domain.invalid \
  --first-name Platform --last-name Administrator \
  --phone approved-test-phone --operator-reference approved-change-reference
```

The exact confirmation must match the securely supplied `DATABASE_URL` database name. The command has no password option and returns only safe status. It creates one pending global IAMUser, Native identity, singleton PENDING reservation, normal five-hour activation token, encrypted outbox and audit. It creates no tenant or effective platform grant. It does not send mail itself.

The singleton primary key/check constraints plus PostgreSQL transaction advisory lock serialize independent CLI processes before any user creation. Existing usable database Platform Admins, a pending reservation, a completed reservation or identity collisions refuse new enrollment. The reservation uses a restrictive user foreign key and survives completion; disabled/deleted/restarted application state cannot reopen bootstrap. Do not delete the guard manually.

## Activation and completion

The existing Celery security-mail worker dispatches committed outbox rows through `EmailSender` to the configured provider. Open the email only in the approved mailbox/capture UI and follow the HTTPS activation link. The user chooses a compliant password. No operator extracts tokens from the DB or prints an activation URL.

Activation atomically creates the Argon2id credential, marks the user verified/ACTIVE, calls the existing platform authorization service, marks the reservation COMPLETED and persists audits. Failure to grant or audit rolls back activation and token consumption. The reserved user needs no tenant membership. Normal non-bootstrap activation is unchanged.

After completion, disable `NATIVE_PLATFORM_BOOTSTRAP_ENABLED`. Even if accidentally left true, the durable guard refuses another initial user. A pending user's activation can complete after this operator creation flag is disabled; normal Native enrollment/activation flags must remain enabled. Sign in through `/native-sign-in`.

## Status and recovery

```sh
.venv/bin/python scripts/bootstrap_native_platform_user.py \
  --confirm-database sbom_native_greenfield status
.venv/bin/python scripts/bootstrap_native_platform_user.py \
  --confirm-database sbom_native_greenfield resend-activation
```

Status is read-only and works with bootstrap mode disabled. It shows enablement, state, user ID/email/account status, delivery status and usable-admin availability. It never prints hashes, tokens, ciphertext or secrets.

Resend requires explicit bootstrap enablement, no usable admin and the same PENDING reservation. It rotates the normal activation token, cancels earlier pending delivery, enqueues a fresh encrypted email and audits; it never creates another user. Expired activation is recoverable this way. Completion blocks resend. An unrelated account/status conflict requires operator review, not manual grant/guard deletion.

## Tenants, users and roles

Using the activated Platform User, create Olympus and MedTech through the normal UI/API. The tenant-create contract requires an existing initial administrator: the Native Platform User can serve as that initial administrator, then create/invite dedicated Native Tenant Admins through the normal authorized workflow. No HCL identifier is required.

Create approved Native test identities for TENANT_ADMIN, SECURITY_ANALYST, DEVELOPER and VIEWER. Each uses the same activation/outbox pipeline. The Tenant Admin can manage only its tenant and cannot delegate TENANT_ADMIN or PLATFORM_ADMIN under the existing policy. Verify catalogue-defined workflows rather than adding new permissions.

Create one multi-tenant Native user: Olympus SECURITY_ANALYST + DEVELOPER; MedTech VIEWER. Add the second membership by exact user ID through the membership API, never by email linking. Verify tenant-specific role sets. Disable Olympus membership: Olympus denied, MedTech allowed. Globally disable: both denied. Re-enable globally: only the still-active MedTech membership returns. Old JWT/session authority must remain revoked.

## Mail providers and reliability

All Native activation, resend, reset and bootstrap email uses the existing encrypted PostgreSQL outbox when enabled. The worker invokes the common `EmailSender.send_email(message)` protocol. `EmailDeliveryResult` supports status, safe error category, provider, optional safe provider message ID and retryability. SMTP is the only configured implementation in this phase. Future Graph support belongs behind that boundary; it must not change account/token issuance or place OAuth credentials in outbox data.

The outbox persists only encrypted action material and fixed operational metadata; worker task arguments contain no token. Retry sends the same token with stable Message-ID, uses bounded exponential backoff and stops at expiry/cancellation/max attempts. A crash after SMTP acceptance before commit may resend: delivery is at least once. Terminal rows erase ciphertext. Credentials/message bodies/exception strings must never enter audit or operations projections.

Current local Mailpit is the approved test capture transport for this task. External SMTP acceptance remains `BLOCKED_PENDING_APPROVED_TEST_MAILBOX`. If the intended deployment lacks an approved capture service, use `BLOCKED_PENDING_TEST_MAIL_TRANSPORT` and leave bootstrap pending; never bypass verification.

## Rollback, readiness and troubleshooting

Rollback configuration/application routing first; retain the new DB, reservation, users, grants, outbox and keys. Stop mail dispatch safely if necessary; do not delete pending records. No automatic drop or schema downgrade. Migration 062 refuses downgrade with a bootstrap reservation, preventing silent guard erasure. A full DB disposal requires explicit authorization.

A rejected CLI prints only a generic safe error. Check exact target, explicit flags, AES-GCM key configuration, schema head and status. An existing reservation requires recovery, not a new identity. For mail failure inspect safe operations counts and approved transport; never log decrypted bodies. For Native-only startup check both HCL-disabled flags, authentication enabled, and no development tenant fallback. For invalid JWTs check active public/private pairing without printing key material. Rotate outbox keys only after draining pending deliveries; session-key replacement invalidates existing sessions.

Before production acceptance, still validate actual TLS ingress/two replicas, Redis outage/recovery and credentials, live worker/Beat scheduling, secret rotation, backup restore, human accessibility and 15-minute expiry UX. Automated and loopback evidence does not establish production readiness.

## Verification commands

Run normal backend regressions with the project virtual environment. Opt-in operational tests create and remove only their own randomly named disposable databases/processes:

```sh
SBOM_RUN_GREENFIELD_ACCEPTANCE=1 .venv/bin/pytest -q \
  tests/test_native_greenfield_empty.py tests/test_native_bootstrap.py
SBOM_RUN_HTTP_ACCEPTANCE=1 SBOM_RUN_BACKUP_ACCEPTANCE=1 \
  SBOM_ACCEPTANCE_PG_CONTAINER=sbom-postgres-1 .venv/bin/pytest -q \
  tests/test_native_http_acceptance.py tests/test_native_backup_acceptance.py
```

The greenfield test needs the existing approved loopback Mailpit and an explicitly disposable test PostgreSQL URL. It creates a second completely empty DB, runs ordinary Alembic (without fixture seeding there), starts an isolated Redis/Celery worker, races two real bootstrap CLI processes and consumes captured emails. It uses the minimum 30-second activation-resend cooldown and the unchanged 60-second reset cooldown. Do not run it against production infrastructure. The HTTP test needs a Native-only production frontend build and launches two actual BFF processes. The container override selects matching PostgreSQL backup tools, not a production backup target.

Build the Native-only frontend with `NEXT_PUBLIC_AUTH_ENABLED=true`, `NEXT_PUBLIC_HCL_AUTH_ENABLED=false` and empty HCL issuer/client settings. The Dockerfile exposes the new HCL switch as a build argument. The server Compose backfill issuer and OIDC transaction-key file are optional for Native-only mode; HCL deployments must still supply their real backfill identity configuration and mounted transaction key. `NATIVE_IAM_PRODUCTION` defaults true in server Compose; a local Mailpit-only override must be explicitly false and must not be used to claim production validation.
