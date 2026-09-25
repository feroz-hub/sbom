# Native IAM Phase 2 implementation report

## Branch and baseline

- Branch: `feat/native-user-management`.
- Starting and ending HEAD: `efa58642eb1016742f7c744cfd701fa4f7e5fc35`.
- Starting working tree was clean; no commit, push or merge was performed.
- All changes remain available for review in the working tree.

## Implementation

| Requested area | Result |
|---|---|
| Creation and existing-user membership | Transactional native enrollment and explicit stable-ID membership endpoint |
| Multiple tenants and roles | Existing single membership per user/tenant with independent multi-role assignments |
| Activation | Atomic Argon2id credential creation, verification, token consumption and audit |
| Login and lockout | Native-identifier lookup, serialized counters, configurable global lock and valid-password expiry unlock |
| Last platform administrator | Security lockout applies; administrative removal safeguards retained |
| JWT | Fixed RS256, injected private key, required identity/version claims and database checks |
| Revocation | Security-version/status checks each request; current database permissions ignore token snapshots |
| Provider compatibility | Shared principal and authorization pipeline, retained HCL provisioning and OIDC/BFF behavior |
| Tenant isolation | Explicit permission and selected-tenant checks; audited platform cross-tenant operations |
| UI | Native sign-in, activation and shared platform/tenant invitation form |
| Email and audits | Existing sender and audit infrastructure; clear delivery status and authorized resend |
| Schema | No new migration or tables |


The [design and configuration guide](native-iam-phase2.md) describes all six API
endpoints, transaction boundaries, multi-tenant memberships and multi-role unions,
activation and resend, native login, concurrency-safe global lockout, last-admin
security policy, JWT signing/claims/validation, security-version revocation,
database-authoritative permissions, HCL compatibility, frontend/BFF sessions,
audits, settings, and deferred scope.

No migration was added. Inspected Alembic head is `060_native_identity_foundation`.
The existing schema supplies all required persistence. Tests use the repository's
disposable PostgreSQL test database; production/SF databases were not migrated.

## Verification

- Initial focused foundation/HCL/context baseline: 120 passed.
- Final native/foundation/HCL/context run: **172 passed, 0 failed** (52 Phase 2 cases plus 120 regressions).
  Command: `.venv/bin/pytest -q tests/test_native_iam_phase2.py tests/test_native_iam_foundation.py tests/test_hcl_iam_auth.py tests/test_phase4_auth_context.py`.
- Initial Phase 2 security suite: 28 passed; expanded suite: 48 passed.
- Broad backend regression run: 369 passed, 2 failed (371 total).
- Both broad failures reproduce from a temporary `git archive HEAD` copy of the
  approved foundation: 3 passed, 2 failed in the platform concurrency module.
  The failures are `test_concurrent_grants_create_one_idempotent_effective_grant`
  and `test_concurrent_revoke_and_grant_leave_one_consistent_row`. The existing
  grant service returns HTTP 409 for an already-active grant while those tests
  expect an idempotent result. This behavior was not changed.
- Full frontend suite: 962 passed, 2 failed. Both failures were in untouched
  FindingsTable/SbomDetail tests and passed on isolated rerun (18/18). This is
  evidence of timing-sensitive failures under the full run, not a claim that
  the full suite was green.
- Focused frontend auth/BFF/context run: 70 passed. Latest changed BFF/auth
  subset: 31 passed, including encoded/normalized path protection.
- Next.js production build (`next build --webpack`): passed.
- TypeScript `tsc --noEmit`, targeted ESLint, changed-backend Ruff and
  `git diff --check`: passed.
- Chrome rendered native sign-in and activation forms. This was a public-page
  visual check, not a live SMTP/HCL/native end-to-end authentication claim.
  The temporary preview process was stopped and port 3000 released.
- Initial collection needed already-declared Argon2 and pytest-timeout packages
  installed into the local virtual environment. No dependency manifest change.

Commands were run with `.venv/bin/pytest`, `.venv/bin/python -m ruff`, and frontend
Node 20 tools. Logs are under `/tmp/native-*.log`; these are local verification
artifacts, not committed application files.

## Security review and remaining limitations

Fixed-algorithm RS256 rejects algorithm substitution, wrong issuer/audience,
invalid signature, invalid/missing claims, stale versions and non-ACTIVE users.
Provider routing never falls back after failed native validation. Same-token
multi-tenant tests prove selected-membership role separation and live permission
removal/addition. Security lockout covers the last platform administrator.
Concurrency and required-audit rollback have PostgreSQL tests.

Native identity uniqueness prevents duplicate enrollment without linking profile
emails. Backend permissions and tenant scope are explicit. Activation tokens use
hashed storage, five-hour expiry, single consumption, resend invalidation and
fragment URLs. Password/token validation inputs are not reflected in API errors.
BFF tokens remain server-side; origin checks protect cookie mutations and generic
proxy paths cannot expose native login token responses.

Deployment requires injected signing material, enabled flags, canonical HTTPS
origin and existing SMTP/HCL configuration. No live external SMTP delivery or HCL
provider login was exercised; HCL automated regressions passed. Sessions remain
in-memory and process-local, native sessions have no refresh token, and delivery
has no durable outbox. Unknown-account abuse still needs deployment-level rate
limits. Key rotation with overlapping keys is deferred.

Password reset, forgot-password, MFA, object ACLs, automatic provider linking,
full user-management UI, shared-session migration and SF cutover remain out of
scope. Recommended Phase 3: shared/durable sessions, delivery recovery, key
rotation, layered abuse controls and administrator lifecycle UI.

## Files changed

- `.env.native-iam.example`
- `.gitignore`
- `app/auth.py`
- `app/core/security.py`
- `app/error_handlers.py`
- `app/main.py`
- `app/routers/native_auth.py`
- `app/routers/tenants.py`
- `app/services/account_action_token_service.py`
- `app/services/account_state_service.py`
- `app/services/authenticated_principal_service.py`
- `app/services/native_auth_service.py`
- `app/services/native_enrollment_service.py`
- `app/services/native_jwt_service.py`
- `app/services/platform_service.py`
- `app/settings.py`
- `docs/native-iam-phase2.md`
- `frontend/src/app/activate-account/page.tsx`
- `frontend/src/app/api/auth/logout/route.test.ts`
- `frontend/src/app/api/auth/logout/route.ts`
- `frontend/src/app/api/auth/native/[action]/route.test.ts`
- `frontend/src/app/api/auth/native/[action]/route.ts`
- `frontend/src/app/api/auth/session/route.ts`
- `frontend/src/app/api/backend/[...path]/route.test.ts`
- `frontend/src/app/api/backend/[...path]/route.ts`
- `frontend/src/app/logged-out/page.tsx`
- `frontend/src/app/native-sign-in/page.tsx`
- `frontend/src/app/settings/native-users/page.tsx`
- `frontend/src/app/settings/platform/page.tsx`
- `frontend/src/app/settings/tenant/page.tsx`
- `frontend/src/components/auth/AuthGuard.tsx`
- `frontend/src/components/auth/NativeAuthForm.tsx`
- `frontend/src/components/layout/AppShell.tsx`
- `frontend/src/lib/auth/origin.test.ts`
- `frontend/src/lib/auth/origin.ts`
- `frontend/src/lib/auth/session-store.ts`
- `frontend/src/proxy.ts`
- `tests/test_native_iam_phase2.py`
- `docs/native-iam-phase2-report.md`

## Final Git status

```text
## feat/native-user-management...origin/feat/native-user-management
 M .gitignore
 M app/auth.py
 M app/core/security.py
 M app/error_handlers.py
 M app/main.py
 M app/routers/tenants.py
 M app/services/account_action_token_service.py
 M app/services/account_state_service.py
 M app/services/platform_service.py
 M app/settings.py
 M frontend/src/app/api/auth/logout/route.ts
 M frontend/src/app/api/auth/session/route.ts
 M frontend/src/app/api/backend/[...path]/route.test.ts
 M frontend/src/app/api/backend/[...path]/route.ts
 M frontend/src/app/logged-out/page.tsx
 M frontend/src/app/settings/platform/page.tsx
 M frontend/src/app/settings/tenant/page.tsx
 M frontend/src/components/auth/AuthGuard.tsx
 M frontend/src/components/layout/AppShell.tsx
 M frontend/src/lib/auth/session-store.ts
 M frontend/src/proxy.ts
?? .env.native-iam.example
?? app/routers/native_auth.py
?? app/services/authenticated_principal_service.py
?? app/services/native_auth_service.py
?? app/services/native_enrollment_service.py
?? app/services/native_jwt_service.py
?? docs/native-iam-phase2-report.md
?? docs/native-iam-phase2.md
?? frontend/src/app/activate-account/
?? frontend/src/app/api/auth/logout/route.test.ts
?? frontend/src/app/api/auth/native/
?? frontend/src/app/native-sign-in/
?? frontend/src/app/settings/native-users/
?? frontend/src/components/auth/NativeAuthForm.tsx
?? frontend/src/lib/auth/origin.test.ts
?? frontend/src/lib/auth/origin.ts
?? tests/test_native_iam_phase2.py
```
