# Native IAM Phase 4 implementation and verification

## 1–5. Repository and changes

- Branch: `feat/native-user-management` only.
- Starting and ending HEAD: `72d5b6136977b20f9c281465425df5e97923b83f`. Baseline ancestry verified. No commit, merge or push performed.
- Initial working tree was clean. Final changes are unstaged implementation, tests, configuration examples and this report; no unrelated changes were discarded.
- Complete changed-file inventory appears below.

## 6–12. Password lifecycle and account policy

Forced login verifies the current native credential and returns only `password_change_required`. It grants no JWT or application session. `/change-password?forced=1` submits email, current password and new password to `POST /api/auth/native/force-change-password`. Completion repeats credential proof under account/credential row locks. The hash is replaced before transitioning to ACTIVE, inside the audited transaction. Failed forced proofs retain FORCE_PASSWORD_CHANGE even when temporary credential lockout applies; manual unlock cannot bypass replacement.

Authenticated `POST /api/auth/native/change-password` requires a validated native issuer/provider JWT, ACTIVE account, matching security version and correct current password. It atomically replaces the Argon2id hash, updates password_changed_at, clears failed-login/lock state and revokes previous authority. The browser must sign in again; no implicit replacement session is issued.

`POST /api/auth/native/forgot-password` always returns “If an eligible account exists, password reset instructions will be sent.” Unknown, HCL-only, disabled and ineligible accounts receive the same response. Every account category incurs a dummy Argon2 verification. Eligible accounts have additional database work, so this is cost normalization, not a claim of perfectly identical timing. SMTP is outside the response and security transaction.

Reset reuses AccountActionToken with PASSWORD_RESET purpose, cryptographically random 32-byte opaque secret, only its hash persisted, native user/email snapshot binding, consumption and invalidation timestamps. TTL defaults to 3600 seconds, configurable from 300 to 86400. A successful new issuance invalidates older outstanding reset tokens. A 60-second cooldown and existing hourly/daily mail budgets suppress repeated issuance with the same generic response; suppressed requests do not rotate a token.

`POST /api/auth/native/reset-password` takes token and new_password. It locks account then credential and conditionally consumes the valid, purpose-bound, unexpired, unconsumed token. Password replacement, token consumption/invalidation, status transition, version increment and required audit commit together. Concurrent consumption has exactly one winner; failed policy/audit rolls everything back.

| Account state | Reset policy |
| --- | --- |
| ACTIVE | Allowed for verified native identity/credential |
| LOCKED | Allowed recovery; clear lock, activate and audit |
| FORCE_PASSWORD_CHANGE | Allowed; fulfills forced replacement, activates and audits |
| DISABLED | Rejected; never re-enabled by reset |
| PENDING_EMAIL_VERIFICATION | Rejected; activation owns initial credential |
| PENDING | Rejected |

Policy is centralized for activation, authenticated change, forced completion and reset. Minimum is configurable but never below 12 characters; maximum is 1024 UTF-8 bytes. Whitespace-only and current-password reuse are rejected. Passwords are neither normalized nor truncated. No arbitrary composition rules, external compromised-password dependency or speculative password-history table were added. Current-password rejection is the chosen reuse control.

## 13–17. Sessions, logout and revocation

An asynchronous SessionStore interface has memory and Redis implementations. Memory is development-only: production refuses it. Redis reuses the existing project Redis deployment and AOF-backed volume; no new datastore or SQL table is introduced. Records contain the existing server token-session data, encrypted with AES-256-GCM, random IV and record-key authenticated data. Redis keys hash the opaque cookie secret; records expire by TTL. Browser cookies retain HttpOnly, Secure and existing SameSite/origin protections; JWTs are not returned to browser storage.

Deployment requires identical `AUTH_SESSION_ENCRYPTION_KEY` (base64 of 32 random bytes) on every frontend replica, `AUTH_SESSION_STORE=redis`, and `AUTH_SESSION_REDIS_URL`. Supply the key through secret management, never NEXT_PUBLIC or source control. Compose uses the existing private Redis network and DB 1. Remote Redis should use authenticated TLS/network isolation. Rotating this encryption key intentionally logs existing sessions out. Redis failures fail closed; the current client disables reconnect/offline queues, so frontend restart may be required after an established connection is lost.

Native sessions expire with the access JWT, default 900 seconds. There is no native refresh token or sliding renewal; re-login is required. Existing HCL refresh behavior remains and uses a distributed Redis lock across replicas. Updating a refreshed record uses Redis XX so logout cannot be undone by an in-flight refresh. Existing HCL storage grace is 24 hours after token expiry.

Current logout requires trusted origin, deletes the server record, clears the cookie and is idempotent. Native sessions never call HCL revocation. HCL revocation/end-session behavior is preserved. Native logout-all increments security_version and clears the current BFF cookie. Current logout does not globally invalidate a separately copied native JWT; logout-all does.

Password change/reset, forced change, disable and security lock invalidate native authority via database security_version/status. Every protected backend request remains database-authoritative. BFF session checks validate native authority with the backend and delete stale records; API 401 also removes the session. Other replicas may retain encrypted stale records until next access/TTL, but these cannot authorize backend operations. No reliance on JWT expiry alone.

## 18–20. Abuse and mail delivery

Native login, forgot, reset, activation and activation resend use endpoint/source and hashed normalized account/token buckets through the existing limits dependency. Defaults are 30/source/minute and 10/account/minute. Forced proof shares login throttling. Account lockout remains separate. Storage failure fails closed. Configure `API_RATE_LIMIT_ENABLED=true`, `NATIVE_AUTH_RATE_LIMIT_ENABLED=true`, and `NATIVE_AUTH_RATE_LIMIT_STORAGE_URI=redis://redis:6379/2` for shared multi-worker buckets. Memory buckets are only suitable for development.

The source is the server-observed request client; arbitrary forwarded headers are not trusted. Behind the BFF, clients share its source bucket. Deployment edge per-client limits are still recommended and require a trusted proxy topology; the application does not invent trust in X-Forwarded-For. Limits therefore trade availability under a shared source for bounded Argon2 CPU.

The reset email uses existing EmailSender infrastructure, includes SBOM Analyser, fragment-token reset link, validity, ignore-if-unrequested and support information. A shared security-mail adapter serves activation and reset. Reset mail runs after commit in a FastAPI background task and records delivery outcome without raw token/error details. Activation/resend retain existing post-commit synchronous delivery.

A durable outbox was deliberately deferred: existing Celery broker/result/log infrastructure is not an encrypted secret-bearing outbox. Serializing raw action tokens into it would weaken the existing hashed-token storage model. Provisioning/security commits do not depend on SMTP success, but process loss after commit can lose mail; there is no automatic durable retry. Explicit resend/re-request rotates tokens subject to cooldown/budget. Production reliable delivery requires an encrypted outbox design with retention, worker idempotency and observable retry states. This is a deployment limitation, not a claim of reliable delivery completion.

## 21–25. Keys, compatibility, audit, UI, migrations

RS256 tokens now carry active `kid`. Configure active private key and `NATIVE_JWT_ACTIVE_KID`; retired public keys are supplied via `NATIVE_JWT_VERIFICATION_KEYS_JSON` as `{ "old-kid": { "public_key": "PEM", "not_after": 1234567890 } }`. Deadlines are Unix seconds. Only RS256, valid claims and known unexpired key overlap are accepted; signing always uses active key. No private keys are committed or stored in the database.

Rotation procedure: deploy kid support first and wait the maximum prior JWT lifetime; stage the new public verification key with bounded overlap on all validators; switch active private key/kid while retaining old public key until its deadline; remove retired entry after overlap. Legacy no-kid tokens use only the active key, so rotating before that initial wait logs those users out. Use distinct kid values and shared configuration across API replicas.

HCL OIDC/PKCE, validation, provisioning and database RBAC remain unchanged. HCL-only accounts cannot use native password operations; linked identities operate only on their native credential. JWT role claims never replace database tenant/membership/role/permission resolution.

Audit includes PASSWORD_CHANGED, PASSWORD_RESET_REQUESTED, PASSWORD_RESET_TOKEN_CREATED, PASSWORD_RESET, ACCOUNT_ACTION_TOKEN_CONSUMED, PASSWORD_ACCOUNT_ACTIVATED/status transition events, ALL_SESSIONS_REVOKED, SESSION_CREATED, SESSION_REVOKED and PASSWORD_RESET_DELIVERY. Required password/security audit failures roll back mutations. Anonymous invalid-token attempts are not individually persisted with sensitive details. Current BFF logout's backend audit is best effort across the Redis/database boundary; deletion still takes precedence when the API is unavailable. Logs/audits do not include raw password/hash/token/JWT/key/session secret.

Minimal pages: `/forgot-password`, `/reset-password`, `/change-password`. Native login links forgot-password and routes forced users into restricted change. Native settings provides change and logout-all; HCL-only settings hides them. Fields use appropriate current/new-password autocomplete and never prepopulate. Reset token is read from fragment and removed on success. Mutation routes retain origin protection.

No SQL migration, database update, production deployment or HCL cutover was performed.

## 26–29. Verification

Added 41 backend Phase 4 cases, including status matrix, policy, old/new credentials, revocation, force restriction, audit rollback, hashed/reset token binding/expiry/rotation, concurrent single-winner changes/resets, dummy-cost normalization, endpoint/account throttling, and key overlap/algorithm rejection. Frontend tests cover password UI, BFF boundaries, logout, expiry, revocation and real isolated Redis adapters simulating two replicas, encrypted records, distributed refresh and logout races.

Executed results:

| Check | Result |
| --- | --- |
| Native Phases 1–4 regression (before six additional Phase 4 edge cases) | 183 passed |
| Broader backend: final 41 Phase 4 cases, native migration, HCL/auth, tenant isolation, auth context, platform administration/status/concurrency/bootstrap, Phase 8/9 catalog/multi-role, candidate/user search | 232 passed, 3 failed |
| Same three failures against archive of approved Phase 3 SHA | Reproduced all 3; 3 other cases passed |
| Frontend full suite | 1008 passed across 136 files |
| TypeScript `npx tsc --noEmit` | Passed |
| Frontend production build | Passed |
| ESLint all changed/new TypeScript files | Passed |
| Ruff all changed/new Python files | Passed |
| `git diff --check` | Passed |

Native regression used `tests/test_native_iam_foundation.py`, `tests/test_native_iam_phase2.py`, `tests/test_native_iam_phase3.py`, and `tests/test_native_iam_phase4.py`. See repository test inventory if naming changes. The complete Phase 3 suite passed, including its six acceptance scenarios.

Broad command:

```sh
.venv/bin/pytest -q tests/test_native_iam_phase4.py tests/test_native_identity_migration.py tests/test_hcl_iam_auth.py tests/test_auth.py tests/test_auth_integration.py tests/test_tenant_isolation.py tests/test_phase4_auth_context.py tests/test_phase6_platform_users.py tests/test_phase6_platform_status.py tests/test_phase6_platform_administrators.py tests/test_phase6_platform_concurrency.py tests/test_phase6_platform_bootstrap.py tests/test_phase8*.py tests/test_phase9*.py tests/test_tenant_user_candidates.py tests/test_user_search.py
```

Pre-existing failures, reproduced without modifying the baseline:

- `test_auth_integration.py::test_authenticated_tenant_write_preserves_context`: fixture attempts role delegation denied by current authorization; exception handling also surfaces TypeError.
- `test_phase6_platform_concurrency.py::test_concurrent_grants_create_one_idempotent_effective_grant`: duplicate active grant returns existing API 409 instead of expected idempotent result.
- `test_phase6_platform_concurrency.py::test_concurrent_revoke_and_grant_leave_one_consistent_row`: same active-grant 409 behavior.

No unrelated tests were changed to hide these failures. Backend suites ran sequentially against disposable test databases. Frontend Redis tests launched and stopped their own isolated Unix-socket server. Node 20 was used. Verification is local automated evidence, not production or real HCL/SMTP deployment acceptance.

## 30–32. Remaining concerns and next scope

Functional password lifecycle, revocation, provider boundaries and prior authorization behavior are implemented and tested. Production rollout still needs shared secrets/Redis configuration, trusted-edge limit tuning, Redis outage/restart drill, real email smoke test and operational key-rotation drill. Durable email delivery is explicitly incomplete; current logout audit is best effort. Test warnings include existing Alembic/Pydantic deprecations, short test HMAC keys and jsdom navigation notices.

Deferred: durable encrypted mail outbox/retries, native refresh credentials, historical-password table, MFA, resource ACLs, automatic linking, SF cutover and major UI redesign.

Recommended Prompt 6: operational hardening and acceptance—encrypted durable security-mail outbox with bounded retries and observable delivery, Redis recovery/multi-replica deployment drill, trusted proxy abuse controls, key-rotation drill, real SMTP/HCL regression smoke tests, and separately approved fixes for the three reproduced baseline test failures. Do not expand into MFA/ACL/cutover without explicit scope.

## Changed-file inventory

- `.env.native-iam.example`
- `.env.server.example`
- `app/routers/native_auth.py`
- `app/services/native_abuse_service.py`
- `app/services/native_auth_service.py`
- `app/services/native_enrollment_service.py`
- `app/services/native_jwt_service.py`
- `app/services/native_password_service.py`
- `app/services/native_security_delivery.py`
- `app/services/password_service.py`
- `app/settings.py`
- `docker-compose.server.yml`
- `docs/native-iam-phase4.md`
- `frontend/package-lock.json`
- `frontend/package.json`
- `frontend/src/app/api/auth/callback/route.ts`
- `frontend/src/app/api/auth/logout/route.test.ts`
- `frontend/src/app/api/auth/logout/route.ts`
- `frontend/src/app/api/auth/native/[action]/route.test.ts`
- `frontend/src/app/api/auth/native/[action]/route.ts`
- `frontend/src/app/api/auth/session/route.test.ts`
- `frontend/src/app/api/auth/session/route.ts`
- `frontend/src/app/api/backend/[...path]/route.ts`
- `frontend/src/app/change-password/page.tsx`
- `frontend/src/app/forgot-password/page.tsx`
- `frontend/src/app/reset-password/page.tsx`
- `frontend/src/app/settings/page.tsx`
- `frontend/src/components/admin/UserLifecycle.test.tsx`
- `frontend/src/components/admin/UserLifecycle.tsx`
- `frontend/src/components/auth/AuthGuard.tsx`
- `frontend/src/components/auth/NativeAuthForm.tsx`
- `frontend/src/components/auth/NativePasswordSettings.tsx`
- `frontend/src/components/auth/PasswordLifecycleForm.test.tsx`
- `frontend/src/components/auth/PasswordLifecycleForm.tsx`
- `frontend/src/components/layout/AppShell.tsx`
- `frontend/src/lib/auth/session-store.test.ts`
- `frontend/src/lib/auth/session-store.ts`
- `frontend/src/lib/auth/shared-session-store.test.ts`
- `frontend/src/lib/auth/shared-session-store.ts`
- `frontend/src/proxy.ts`
- `tests/test_native_iam_phase4.py`
