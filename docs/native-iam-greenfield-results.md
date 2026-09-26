# Native greenfield implementation results

This report supersedes the earlier bootstrap-gap assessment. It is local acceptance evidence, not a production-readiness claim. No SF/HCL identities or old application data were migrated, linked or copied. HCL code remains.

| Requested item | Result |
| --- | --- |
| 1 Branch | `feat/native-user-management` |
| 2 Starting SHA | `dea456fbe902013f5235987e4ed2b5916674899d`, verified HEAD/approved baseline |
| 3 Ending SHA | Unchanged; no commit, merge or push |
| 4 Git status | Uncommitted tracked and new files; earlier acceptance changes preserved |
| 5 Bootstrap solution | Operator-only CLI; no public registration endpoint, password argument, default password or HCL dependency |
| 6 Guard | Durable singleton reservation, restrictive user FK, PENDING/COMPLETED constraints and PostgreSQL transaction advisory lock; one winner across CLI processes |
| 7 Migration | Additive `062_native_platform_bootstrap`; migrations 001–061 unchanged |
| 8 CLI | `scripts/bootstrap_native_platform_user.py`: create, status, resend-activation; explicit enablement and exact database confirmation |
| 9 Activation | Existing five-hour activation token, encrypted outbox, SMTP provider, ordinary password selection and Argon2id credential |
| 10 Grant finalization | Existing platform service called inside activation transaction; ACTIVE, grant, COMPLETED and audit commit together |
| 11 Recovery | Resend targets only reserved pending user, invalidates prior token and cancels pending mail; no duplicate user |
| 12 Audit | NATIVE_PLATFORM_BOOTSTRAP_CREATED, ACTIVATION_RESENT and COMPLETED events, plus existing activation/password/state audits; completion records the platform bootstrap outcome; failures roll back |
| 13 Empty DB | Ordinary `alembic upgrade head` on a newly created empty PostgreSQL DB succeeds through 062, using the repository's frozen 047 starting schema then 048–062 migrations |
| 14 Seeds/catalogue | Normal migration catalogue seed and authenticated app master-data initialization; all five roles verified, zero prior IAM users |
| 15 First Native Platform User | Two independent CLI processes race: one succeeds, one refuses. Captured-mail activation yields an active Native credential and platform authority, then Native login succeeds |
| 16 Tenants | Olympus and MedTech created through normal authenticated API by Native Platform User |
| 17 Users/roles | Native Tenant Admin, Security Analyst, Developer and Viewer created and activated via same provider pipeline; no invented permissions |
| 18 Multi-tenant | One Native user with Olympus analyst+developer and MedTech viewer; tenant-specific role sets checked through authenticated API |
| 19 Lifecycle | Olympus membership disable preserves MedTech; global disable denies both; global re-enable restores only still-active MedTech membership |
| 20 HCL coupling | API/BFF previously required HCL configuration. Explicit HCL-disabled switches now support Native-only mode, with HCL defaults/implementation retained. Legacy Compose backfill issuer no longer mandatory for fresh Native DB |
| 21 Email | Existing Mailpit, not a MailKit/.NET service. Real Celery worker + isolated Redis broker + SMTP capture exercised; external mailbox/provider acceptance remains blocked pending approval |
| 22 New tests | Bootstrap flags, pending/completion, concurrent ownership, expired-token recovery, grant/audit rollback, Native-only setup, public provider selection, real empty DB/CLI/Celery/Mailpit population and frontend config |
| 23–24 Execution/counts | See verification ledger below |
| 25 Security review | No plaintext token persistence, token/URL CLI output, password bootstrap, manual SQL authorization inserts, automatic linking or public bootstrap endpoint. Guard survives process restart/completion and is not removed by account deletion. Required grant/audit failure rolls back activation |
| 26 Files | Complete worktree inventory below; includes preserved prior acceptance files |
| 27 Runbook | `docs/native-iam-greenfield-setup.md` |
| 28 Blockers | Real target/environment approval, external mailbox if needed, TLS ingress and production orchestration, secret/backup recovery and human UX/accessibility signoffs; inherited test defects remain separately reported |
| 29 Recommendation | Proceed to approved Native-only staging rehearsal using new DB and runbook. Do not remove SF/HCL source or claim production readiness from these local results |

## Verification ledger

- Initial broad backend run after bootstrap changes: **430 passed, 5 failed** (435 collected). Two failures were optional email-result metadata compatibility and were fixed; the other three are the inherited authorization/concurrency failures described below.
- Corrected affected backend tests, all bootstrap tests, real SMTP failure/crash tests, two actual Native-only BFF HTTP processes, Redis recovery/expiry and backup/restore: **44 passed**, two Alembic deprecation warnings. No failures.
- Final completion-audit failure rollback check: **9 bootstrap tests passed**; a failure after the platform grant leaves no credential/grant and keeps the reservation pending.
- Full frontend suite: **1,022 passed**, 139 files. This includes Native-only configuration tests and existing HCL/BFF/lifecycle tests.
- TypeScript, normal production build, explicit HCL-disabled Native-only production build, changed-file ESLint, changed Python Ruff and `git diff --check`: passed. Build-generated `next-env.d.ts` drift was restored.
- Final fresh-database/Celery/Mailpit verification: **10 passed** in 111.04 seconds. This includes non-mutating `alembic current`, two CLI processes, captured-email resend/reset re-request and Native tenant-admin delegation. No failures.

The inherited failures are `test_authenticated_tenant_write_preserves_context`, `test_concurrent_grants_create_one_idempotent_effective_grant`, and `test_concurrent_revoke_and_grant_leave_one_consistent_row`. They were reproduced from the exact approved SHA in the earlier acceptance work and their tests/contracts remain unchanged. The first seeds a prohibited tenant-admin delegation; the concurrency expectations conflict with the existing active-platform-grant 409 contract. Details remain in `native-iam-operational-acceptance.md`. The broad run was not wholly green; successful focused reruns do not conceal that fact.

## Evidence boundaries and remaining acceptance

The greenfield API calls use real routers/authentication/database authority in a local TestClient subprocess. Mail runs through an actual Celery worker process and isolated Redis broker into existing loopback Mailpit. The two-BFF harness uses two real production Next HTTP processes, with a real native API and shared Redis; it does not prove staging TLS ingress/browser behavior. The backup test uses disposable data and a separate restored database with matching PostgreSQL tools. No existing application database was dropped.

Worker task arguments are empty; only outbox delivery state is read from the DB. Activation/reset links are consumed from captured recipient email, never extracted from stored ciphertext. The outbox remains provider-independent and uses the shared EmailSender protocol; only SMTP is implemented. Graph is future adapter work. No new mail infrastructure or .NET runtime was introduced. Real provider credentials, managed Redis failover, Celery Beat scheduling under deployed orchestration, external mailbox delivery, live rolling key rotation, human accessibility and 15-minute UX remain deployment acceptance tasks. Live HCL provider acceptance is optional/deferred for this Native-only population; automated HCL compatibility remains required.

The test transport leaves synthetic messages in the existing local Mailpit capture store; no customer/employee addresses were used. Only randomly named disposable acceptance databases/processes were removed by test cleanup. Bootstrap state deletion or schema downgrade is not the rollback mechanism.

## Worktree inventory

```text
 M .env.native-iam.example
 M alembic/env.py
 M app/auth.py
 M app/core/security.py
 M app/models.py
 M app/services/email_sender.py
 M app/services/native_auth_service.py
 M app/services/native_jwt_service.py
 M app/services/native_operations.py
 M app/services/native_password_service.py
 M app/services/native_security_delivery.py
 M app/settings.py
 M docker-compose.server.yml
 M frontend/Dockerfile
 M frontend/src/app/api/auth/login/route.ts
 M frontend/src/components/auth/NativeAuthForm.tsx
 M frontend/src/lib/auth/server-config.ts
 M tests/test_native_iam_phase2.py
 M tests/test_native_iam_phase4.py
 M tests/test_native_iam_phase5.py
?? alembic/versions/062_native_platform_bootstrap.py
?? app/services/native_platform_bootstrap.py
?? docs/native-iam-greenfield-acceptance.md
?? docs/native-iam-greenfield-results.md
?? docs/native-iam-greenfield-setup.md
?? docs/native-iam-operational-acceptance.md
?? frontend/src/lib/auth/native-only-config.test.ts
?? scripts/bootstrap_native_platform_user.py
?? scripts/iam_migration_inventory.py
?? tests/iam_acceptance_server.py
?? tests/native_greenfield_scenario.py
?? tests/test_native_backup_acceptance.py
?? tests/test_native_bootstrap.py
?? tests/test_native_greenfield_empty.py
?? tests/test_native_http_acceptance.py
?? tests/test_native_iam_acceptance.py
?? tests/test_native_mail_acceptance.py
```
