# Native IAM Phase 5 — operational acceptance

This implementation prepares acceptance; it does not claim production readiness, perform SF cutover, or replace existing identity/RBAC systems.

## Repository baseline

Branch: `feat/native-user-management`. Starting HEAD: `a21836bcdd5e952d32035c15001f3332c4f2da81`, exactly the approved Phase 4 baseline. Starting working tree was clean. No unrelated work was discarded, and no commit, merge or push was requested or performed. Ending HEAD remains the starting SHA. Changes remain unstaged for review.

## Administration UI and authorization

Settings remains the administration navigation system. Its permission-aware index links Users & audit history, Roles/permissions & access management, Tenants, Authentication/delivery/operational health, and Platform administrators. The existing sidebar now exposes the unified user directory and operational health; existing tenant and platform routes remain available.

`/settings/native-users` manages all supported providers despite its retained compatibility URL. The directory has a responsive bordered table, accessible headings/labels, loading/empty/error states, search, pagination, account status/role filters, and platform tenant/provider/sort filters. Columns distinguish account status from tenant access, and include provider, active membership count, last login and creation time. Platform roles remain grouped by membership in details; they are never flattened across tenants. Tenant administrators receive only the selected tenant projection from the existing backend. Scope changes remount the view to remove stale tenant information.

Details show profile, identity providers, email verification, authentication/security summary, memberships/roles and a readable audit timeline. Platform security summaries include password last changed, failed-attempt state and lock expiry. Audit rendering uses only timestamp, action, actor ID, tenant ID and outcome; historical JSON is never displayed. Actor/tenant IDs are safe identifiers, not inferred display names. Existing recent-50 audit projection is retained.

Account badges now distinguish ACTIVE, PENDING_EMAIL_VERIFICATION, LOCKED, DISABLED and FORCE_PASSWORD_CHANGE with explanatory text; unknown/missing status is shown safely. Confirmations identify user and scope for global disable/enable, manual unlock, forced change, membership deactivate/reactivate, role replacement/removal, resend activation and administrator logout-all. Existing dialog focus trapping and keyboard behavior are reused. A vitest-axe check covers the directory/detail structure. Native-only actions are hidden for HCL-only users; no native credentials are fabricated.

New `POST /api/platform/users/{user_id}/logout-all` requires the existing platform status-management permission, locks native account/credential, increments security_version and atomically audits ALL_SESSIONS_REVOKED. Tenant administration cannot call it. The UI does not grant authorization; all existing database permission checks remain authoritative.

## PostgreSQL encrypted security-mail outbox

Alembic head was inspected as `060_native_identity_foundation` before adding `061_security_mail_outbox`. This additive migration creates one table; previous IAM migrations are unchanged. PostgreSQL was chosen over Redis to commit user/token/outbound delivery in the same security transaction.

The record includes unique token ID (idempotency key), user, purpose, intended recipient, authenticated ciphertext, expiry, status, attempts, next-attempt, created/sent/failed timestamps. Only the action-token hash remains in AccountActionToken. AES-256-GCM uses an independent 32-byte secret supplied as base64 through `NATIVE_SECURITY_OUTBOX_KEY`; a random 12-byte nonce and authenticated token ID/purpose/recipient binding prevent payload substitution. Invalid encryption configuration rolls back issuance, not just delivery. Database parameter logging remains suppressed by the existing `hide_parameters=True` engine setting.

Enable `NATIVE_SECURITY_OUTBOX_ENABLED=true` on API and workers. It defaults off for compatibility with existing development/test synchronous adapters; production validation requires it when native production mode is enabled. Enabled mode queues activation, resend and reset inside token issuance. API routes return PENDING for activation and the unchanged generic forgot-password response; they do not call SMTP. Reissuance cancels older pending deliveries of the same purpose and erases their ciphertext.

The existing Celery Beat schedules `security_mail.dispatch` every 30 seconds on the existing default worker queue. Task arguments and results contain no user/email/token/payload. PostgreSQL is the durable authority, so broker loss/delayed scheduling does not lose committed delivery records. The worker selects up to 100 due records per run, serializes account and outbox locks in the same order as issuance, checks token invalidation/consumption, identity email, eligibility and expiry, then decrypts only to construct mail through the existing sender. SMTP timeouts bound lock duration. Expired/cancelled records never send; issued tokens are never regenerated by a retry.

Retries use 30, 60, 120, 240… seconds with a one-hour cap and configurable maximum attempts (default five, bounds 1–10). Success becomes DELIVERED; exhaustion becomes FAILED; expiry becomes EXPIRED; obsolete tokens become CANCELLED. Ciphertext is cleared on terminal outcomes. Safe metadata is purged seven days after token expiry. Normal resend/reset-request remains the recovery path after failure, subject to existing quotas.

Concurrent workers cannot send a committed delivered record twice. SMTP does not support a transaction with PostgreSQL: a process crash after SMTP acceptance but before commit can resend the same token. Stable `Message-ID: <security-TOKEN_ID@sbom.invalid>` helps mail systems identify retries but is not an exactly-once guarantee. Required audit failure also rolls back delivery-state persistence and can therefore cause a duplicate accepted email. No duplicate user, membership, password or reset token is created.

Threat boundary: DB/broker readers cannot obtain raw tokens without the outbox key. Trusted API/worker processes and secret-management access can decrypt pending mail; SMTP/mailbox recipients necessarily see emailed tokens. Ciphertext erasure does not erase historical database backups—protect backup access/retention and use separate secrets. Do not enable SMTP debug tracing, request-body/APM local-variable capture, SQL parameter logging or mail-body logs. Rotation of the outbox key must drain pending deliveries first; changing it prematurely causes safe failed retries. This version does not provide overlapping outbox encryption keys.

## Delivery and dependency health

`GET /api/platform/iam/operations` requires platform user-read authority and returns status counts plus the most recent 50 safe delivery events: ID, purpose, status, attempts and timestamps. It never returns recipient, token, ciphertext, JWT or key. `/settings/iam` shows pending/delivered/failed/expired/cancelled counts and readiness. Native login failures/lockouts remain in existing audit data; limiter throttles emit fixed-name events with endpoint only, without account/source/token values. Aggregate these logs in deployment monitoring.

Existing `/health` liveness is unchanged. New `/ready/iam` returns 200/503 for database outbox accessibility, shared rate-limit Redis and security-mail worker heartbeat. The worker refreshes a Redis heartbeat after a successful drain; it expires after 120 seconds. A prolonged batch, missing Beat/worker or dependency loss fails readiness. The native-disabled response is ready with enabled=false. `/api/ready` on the BFF separately checks shared session Redis and returns only ready true/false, no internal URLs. Use readiness for traffic/alerts; do not substitute these probes for liveness or use a transient SMTP outage to restart all services.

## Shared sessions, recovery and logout policy

Existing AES-GCM session records and opaque HttpOnly/Secure cookies are preserved. Redis reconnect delays are bounded (100 ms exponential, maximum 2 seconds, eight attempts), and offline queues remain disabled. Reads/writes during disconnection fail closed. After retry exhaustion, the client is discarded so a subsequent request can establish a fresh connection. Ciphertext authentication failure/wrong key yields no session. Recovered Redis records still require current native database authority; restoring an AOF snapshot cannot restore security_version or disabled-user access.

Real isolated Redis tests use two adapters with independent clients, encrypted records and AOF: creation on A, read on B, logout on B and denial on A; wrong key; expiry; corrupt ciphertext; distributed HCL refresh; logout/refresh race; server stop, fail-closed reads/writes and restart recovery. These are two BFF store adapters, not a claim of two deployed HTTP BFF servers. Existing native backend and BFF tests verify password-change/reset/disable/force/security-version denial. Production ingress/cookies across two actual replicas still need manual acceptance below.

Current-session logout remains Option A: delete shared BFF record and clear cookie; a separately copied access JWT can remain valid until its short expiry. Logout-all remains security_version-based global native revocation. No JTI denylist/permanent token records were added. This retains the approved short-lived JWT threat model; choose a denylist in a separately reviewed change if enterprise policy requires copied bearer revocation on current logout.

Native session lifetime remains 900 seconds by default, with re-login and no refresh credentials. Settings explicitly explains expiry. Security operations require fresh login. HCL OIDC, PKCE, token validation/refresh, provisioning, logout, tenant context and RBAC are retained.

## Rate limits and trusted ingress

Application limits remain endpoint/actual peer/account-hash buckets in shared Redis; account lockout is separate. Neither BFF nor backend blindly derives a client identity from arbitrary X-Forwarded-For. Compose explicitly starts Uvicorn with `--no-proxy-headers`. Clients behind the BFF share its source bucket; hashed account buckets remain independent. This is intentionally conservative and can rate-limit a busy shared BFF source.

`deploy/iam-proxy.nginx.example` supplies an ingress per-client limit snippet for the existing TLS server. Deploy it at the actual internet boundary, overwrite forwarded headers, and block direct backend access. If an upstream load balancer exists, allowlist only its exact private CIDRs and sanitized header before enabling real-IP handling; never trust all addresses. The snippet is an example, not a deployed or syntax-tested Nginx configuration. Tune edge and aggregate application limits under load without weakening account buckets. Tests show spoofed headers do not alter the app source bucket and Redis failure returns safe 503.

## JWT rotation and production validation

The rotation drill uses generated ephemeral RSA keys and separately configured validator snapshots: A active issues A; A learns B's public key; B becomes active and retains A with bounded overlap; both validators accept both tokens; after A removal, both reject A while retaining B. Phase 4 tests cover unknown kid, expired overlap and algorithm substitution. Malformed verification-keyset shapes now reject safely instead of causing attribute errors. Production configuration checks validate public-keyset structure/key type/size.

Production API/worker deployments must set `NATIVE_IAM_PRODUCTION=true`. When native auth is enabled, startup validates existing native signing safeguards, active kid/RSA key/issuer/audience, outbox encryption, canonical HTTPS APP_ORIGIN and matching activation/reset link origins, shared rate-limit Redis with limiting enabled, durable outbox, SMTP sender/host and encrypted SMTP transport. Enrollment can intentionally remain disabled. Safe failure messages contain configuration categories, never values. Validation happens before startup seed work. Compose enables the production gate and wires native configuration to API/worker/Beat.

BFF Node production startup validates native mode through instrumentation: frontend authentication enabled, Redis session store/URL, 32-byte session encryption key and canonical HTTPS origin. Session and outbox keys must be independently generated and shared only with the relevant replicas. Existing HCL transaction-key configuration remains required. No secret values or private keys are in this patch.

## Deployment and rollback runbook

1. Review the migration and provision secrets outside Git. Use separate outbox/session/JWT secrets. Ensure SMTP TLS, private authenticated Redis or TLS where crossing networks, database backup policy and least-privilege worker access.
2. Keep native enrollment/auth disabled while applying the new Alembic head through the existing approved migration job. Do not run ad hoc SQL or edit earlier migrations. Check the actual environment's Alembic state before deployment; no non-test database was migrated by this work.
3. Deploy API/worker/Beat configuration and matching frontend session keys. Enable production validation, outbox and shared limits. Verify safe startup errors for intentionally missing settings in staging.
4. Start Beat/default queue worker. Check `/ready/iam`, BFF `/api/ready` and platform delivery health. Confirm one scheduler and sufficient worker capacity. Alert on old pending records, FAILED deliveries, worker heartbeat loss and limit-storage failures.
5. Perform the manual acceptance checklist below before enabling native enrollment for operators.
6. To rotate JWT A→B: stage B public verification on A validators; switch signing to B while retaining A public key until its bounded deadline; verify A/B on every replica; remove A after overlap. Before the first ever kid rotation, wait out pre-kid token TTL. Never reuse kid values or commit private keys.
7. For Redis loss, expect 503/denial while reconnecting; restore service and verify both replicas recover and revoked sessions remain denied. After retry exhaustion a fresh request creates a new client; if recovery fails, inspect only safe connectivity diagnostics, then restart the frontend. Never enable offline queues or memory fallback in production.
8. For SMTP outage, preserve PostgreSQL outbox and restore SMTP; observe bounded retry. After FAILED/EXPIRED, request a fresh activation/reset through normal authorized flows. Never manually copy/decrypt tokens or requeue expired rows.
9. Rollback: disable enrollment and stop security-mail dispatch before changing code. Do not drop the outbox while pending records exist. Preserve the additive table and compatible application version; reverting to pre-outbox code loses durable delivery guarantees. Do not downgrade an ahead database casually. Session encryption-key replacement logs existing BFF sessions out; outbox key replacement needs pending-drain planning.

## Manual operational acceptance still required

- Two actual frontend HTTP replicas behind the real TLS ingress: login A/use B/logout B/deny A, cookie flags/origin protection, password-change and global-disable denial on both.
- Real SMTP provider: successful activation/reset, controlled outage/retry, duplicate Message-ID behavior, bounced/blocked email handling and support workflow.
- Real Beat/worker restart and broker outage with committed pending delivery; long backlog/heartbeat alert behavior and recovery.
- Redis AOF durability across abrupt crash/host recovery, secret mismatch rollout, failover and network partition under load. Tests use a local orderly restart, not crash durability or managed Redis failover.
- Real API rolling JWT rotation, deadline removal and clock-skew monitoring on every replica.
- Ingress configuration syntax, trusted load-balancer CIDRs, direct-backend blocking, source-limit tuning and spoofed-header requests through the actual topology.
- Human keyboard/screen-reader/contrast review at desktop/mobile sizes. Automated axe does not prove all accessibility criteria.
- HCL OIDC provider and tenant-switch smoke test in staging; existing automated HCL regressions are not a live provider test.

## Verification and final inventory

Verification used Node 20 and disposable PostgreSQL. The Native Phases 1–5 run passed 205 tests before the final operational edge cases were added. The final full frontend suite passed 1,020 tests across 138 files. The production build, TypeScript, changed-file ESLint/Ruff and diff whitespace checks passed. The final operational edge cases are included in the broader backend run below.

Three inherited failures were reproduced using an unchanged archive of `a21836bcdd5e952d32035c15001f3332c4f2da81` and a separate newly created disposable test database (removed after the run):

- `test_auth_integration.py::test_authenticated_tenant_write_preserves_context`: existing fixture attempts unauthorized delegation; its exception path also surfaces TypeError.
- `test_phase6_platform_concurrency.py::test_concurrent_grants_create_one_idempotent_effective_grant`: existing active-grant 409 differs from the idempotency expectation.
- `test_phase6_platform_concurrency.py::test_concurrent_revoke_and_grant_leave_one_consistent_row`: intermittent active-grant 409; passed in the first baseline run, then reproduced in the isolated repeat.

These three test files/expectations were not changed. The migration regression was necessarily updated to discover the current Alembic head instead of hard-coding revision 060; data-preservation assertions remain intact. New migration downgrade refuses pending outbox data loss. An initial baseline attempt against the already-ahead test database was refused because baseline code cannot recognize 061; reproduction then used its own fresh database, without downgrading the shared test database.

Commands:

```sh
.venv/bin/pytest -q tests/test_native_iam_foundation.py tests/test_native_iam_phase2.py tests/test_native_iam_phase3.py tests/test_native_iam_phase4.py tests/test_native_iam_phase5.py
.venv/bin/pytest -q tests/test_native_iam_phase5.py tests/test_native_identity_migration.py tests/test_hcl_iam_auth.py tests/test_auth.py tests/test_auth_integration.py tests/test_tenant_isolation.py tests/test_phase4_auth_context.py tests/test_phase6_platform_users.py tests/test_phase6_platform_status.py tests/test_phase6_platform_administrators.py tests/test_phase6_platform_concurrency.py tests/test_phase6_platform_bootstrap.py tests/test_phase8*.py tests/test_phase9*.py tests/test_tenant_user_candidates.py tests/test_user_search.py tests/test_celery_configuration.py
# From frontend/, with Node 20:
npm test
npx tsc --noEmit
npm run build
# All changed/new source files were passed explicitly:
npx eslint <changed TypeScript files>
.venv/bin/python -m ruff check <changed Python files>
git diff --check
```

Outbox simulations cover separate worker processes with a stub SMTP transport, concurrent workers, successful retry, max attempts, encryption failure, token invalidation/expiry, audit failure and downgrade safety. They do not claim a real external SMTP delivery. Redis tests launch/stop only their own Unix-socket server and verify orderly AOF restart. Existing service processes are left alone. Compose YAML parsed successfully; ingress deployment validation remains manual.

## Deferred scope and recommended Prompt 7

MFA, project/product/SBOM/finding ACLs, automatic provider linking and SF removal/cutover remain excluded. Native refresh credentials, per-session JWT denylist, overlapping outbox encryption-key rotation and SMTP exactly-once delivery are not added.

Recommended Prompt 7: execute and record the staging operational acceptance checklist, resolve resulting deployment defects, validate backup/secret-rotation and incident runbooks, then separately review the three inherited unrelated test failures if authorized. SF migration planning may follow successful acceptance; do not perform cutover implicitly.

## Requested final-report index

| Item | Result / report location |
| --- | --- |
| 1–4 Branch, starting/ending SHA, status | Repository baseline; same SHA, uncommitted changes |
| 5 Files changed | Final inventory below |
| 6–10 Navigation, list/detail, tenant roles, actions, audit | Administration UI and authorization |
| 11–13 Outbox, encryption, retry/idempotency | PostgreSQL encrypted security-mail outbox |
| 14 Delivery health | Delivery and dependency health |
| 15–17 Redis, replica tests, recovery | Shared sessions, recovery and logout policy |
| 18–19 Current logout/JWT decision, expiry UX | Option A and 900-second re-login retained |
| 20 Trusted proxy/rate controls | Rate limits and trusted ingress |
| 21–22 Rotation and production configuration | JWT rotation and production validation |
| 23 Readiness | Separate API/BFF readiness; liveness preserved |
| 24 HCL compatibility | Approved HCL/RBAC flows retained and regression-tested |
| 25 Migration | Additive 061; test databases only; pending-delivery downgrade guard |
| 26–28 Tests and counts | Verification and final results below |
| 29 Baseline failures | Exact Phase 4 reproduction described above |
| 30 Security concerns | SMTP acceptance/commit gap; backup/key boundary; copied current JWT TTL |
| 31 Manual validation | Manual operational acceptance checklist above |
| 32 Deferred scope | MFA/ACL/linking/cutover remain excluded |
| 33 Prompt 7 | Staging acceptance and operational defect closure |

## Final changed-file inventory

- `.env.native-iam.example`
- `.env.server.example`
- `alembic/versions/061_security_mail_outbox.py`
- `app/main.py`
- `app/models.py`
- `app/routers/health.py`
- `app/routers/native_auth.py`
- `app/routers/platform.py`
- `app/services/account_action_token_service.py`
- `app/services/native_abuse_service.py`
- `app/services/native_enrollment_service.py`
- `app/services/native_jwt_service.py`
- `app/services/native_operations.py`
- `app/services/native_password_service.py`
- `app/services/native_security_delivery.py`
- `app/services/security_mail_outbox.py`
- `app/services/user_management_service.py`
- `app/settings.py`
- `app/workers/celery_app.py`
- `app/workers/security_mail.py`
- `deploy/iam-proxy.nginx.example`
- `docker-compose.server.yml`
- `docs/native-iam-phase5.md`
- `frontend/src/app/api/ready/route.ts`
- `frontend/src/app/settings/iam/page.tsx`
- `frontend/src/app/settings/page.tsx`
- `frontend/src/components/admin/IamOperations.test.tsx`
- `frontend/src/components/admin/IamOperations.tsx`
- `frontend/src/components/admin/StatusBadges.tsx`
- `frontend/src/components/admin/UserLifecycle.test.tsx`
- `frontend/src/components/admin/UserLifecycle.tsx`
- `frontend/src/components/auth/NativePasswordSettings.tsx`
- `frontend/src/instrumentation.ts`
- `frontend/src/lib/auth/production-config.test.ts`
- `frontend/src/lib/auth/production-config.ts`
- `frontend/src/lib/auth/shared-session-store.test.ts`
- `frontend/src/lib/auth/shared-session-store.ts`
- `frontend/src/lib/navigation.ts`
- `tests/test_native_iam_phase5.py`
- `tests/test_native_identity_migration.py`

## Final verification results

| Run | Result |
| --- | --- |
| Native Phases 1–5 regression before final operational edge cases | 205 passed |
| Final broader backend, including all 24 Phase 5 cases and migration regressions | 222 passed, 2 inherited failures |
| Exact Phase 4 baseline reproduction | 2 failed, 4 passed; isolated intermittent revoke/grant repeat also failed as expected |
| Final frontend full suite | 1,020 passed, 138 files |
| Production build | Passed |
| TypeScript | Passed |
| Changed/new frontend ESLint | Passed |
| Changed/new backend Ruff | Passed |
| Compose YAML parse and git diff --check | Passed |

The third inherited revoke/grant race passed in the final broader run, but its failure was independently reproduced on the exact baseline. The final broader run's two failures are tenant delegation fixture and concurrent duplicate platform grant. No new unresolved automated failures remain in the executed suites. Counts from overlapping runs must not be summed as unique coverage.

Final Git status: branch `feat/native-user-management`, HEAD `a21836bcdd5e952d32035c15001f3332c4f2da81`; 40 changed/new files, unstaged; no commit, push or merge. Build-generated next-env.d.ts was restored to its original content. All acceptance claims are local automated evidence, not production validation.
