# Microsoft Entra Phase 1 acceptance record

Branch: `feat/native-user-management`  
Starting/current commit: `9a7ade96c89a769d2565328aa8c317e31e2c7c0e`  
Initial working tree: clean. The implementation is being verified for the requested commit. No push, merge or pull request performed.

## Implementation

The existing Native/HCL.CS paths converge through AuthenticatedPrincipalService,
IAMUser, AuthContextService and database roles/memberships. Entra adds a validated
provider at that same boundary. No second user or permission system was introduced.

First login: Microsoft member authentication → pending IAMUser/UserIdentity → no
roles/memberships/password → administrator approval → ACTIVE → explicit tenant/role
assignment → existing database permission checks. Email never links accounts.
The member-directory verification rule is distinct from mailbox verification.

Migration: `063_microsoft_entra_identity`, additive check-constraint changes only.
Existing Native/HCL identity uniqueness remains unchanged. Downgrade refuses to
remove Entra identities or suspended account data.

See [the implementation and registration runbook](microsoft-entra-phase1.md) for
configuration, all security controls, administrator workflow and deployment steps.

## Baseline before source changes

- Backend: 171 passed, 1 failed. The failure is
  `tests/test_identity_administration.py::test_last_active_tenant_admin_is_protected`:
  role-change request receives 403; fixture expects 409. The contract was not changed.
- Frontend: 141 files, 1,036 tests passed.
- The system Node binary could not load its Homebrew simdutf library. Frontend
  validation used the installed bundled Node runtime instead; no machine repair.

## Verification

| Check | Result |
| --- | --- |
| Combined backend IAM regression (18 files, 409 tests) | 407 passed, 2 failed before the test logging isolation fix described below |
| Post-fix Entra + shared auth-context regression | 74 passed, 0 failed |
| Full frontend suite | 145 files, 1,064 tests passed |
| TypeScript (`npx tsc --noEmit`) | Passed |
| Production frontend build (`npm run build`) | Passed |
| Ruff, all 23 changed/new Python files | Passed |
| ESLint, changed/new frontend files | No errors; 3 existing unused-variable warnings |
| `git diff --check` | Passed |
| Standalone production HTTP smoke | Passed for config, callback and bridge endpoints |

Backend coverage includes new Entra validation/provisioning/discovery/migration,
HCL authentication, Native foundation/Phases 2–5/bootstrap, shared auth context,
identity provisioning/administration, tenant candidates, platform users/status/
administrators and authorization catalogue. The full unrelated backend suite was
not run.

The combined run retained the baseline tenant-admin 403/409 failure. Its other
failure was a test-isolation issue: in-process Alembic migration tests disabled an
existing logger, so a subsequent auth-context test could not capture a diagnostic
message. Authorization assertions passed. The migration tests now suppress only
Alembic's logging reconfiguration with a scoped pytest monkeypatch; application
logging and the existing regression test are unchanged. A post-fix focused run
covered all new backend tests followed by the affected auth-context file: **74 passed, 0 failed**. The full 409-test combination was not repeated after this test-only isolation fix.

Validation logs are local `/tmp/sbom-entra-*` files; they are not committed artifacts.
No real Microsoft sign-in is represented by the automated or HTTP smoke results.

The production standalone HTTP smoke test verified 200 responses for the disabled
provider configuration, `/auth/entra-callback` and `/api/auth/entra/bridge`, with
no-store headers. The bridge is served from installed, traced MSAL assets on the
same origin; no CDN or application auth guard is involved.

Intermediate validation caught and fixed a standalone module-path issue in the
bridge and an unintended PENDING-to-DISABLED transition. The existing pending
transition contract is preserved. Provider-neutral UI text expectations were
updated intentionally; unrelated tests were not changed to suppress failures.

## Final pre-commit review

- Reviewed authentication routing, immutable identity provisioning, pending/status
  enforcement, shared DB authorization, provider-specific BFF sessions/logout,
  administration UI, configuration and migration changes.
- `alembic heads` reports only `063_microsoft_entra_identity`, following `062`.
  The migration modifies three check constraints; it does not change identity
  uniqueness or delete records. Upgrade/downgrade and refusal checks run against
  disposable PostgreSQL in `tests/test_entra_migration.py`.
- Changed/new files contain no embedded private-key material, complete JWTs or
  action-token URLs in the targeted scan. Configured local secrets were compared
  without printing their values.
- One earlier local failure log contained a configured API key in diagnostic
  output. It was redacted; verification logs have mode `0600`. No such value was
  found in the changed source files. Logs are outside the repository and are not
  part of the commit.
- Both environment examples use blank Entra registration settings. The root
  example's inherited development database password is now the explicit
  `replace-with-local-password` placeholder in both password and URL fields.
  Other examples are non-secret localhost configuration/defaults.
- These are targeted secret checks, not a guarantee about unrelated historical
  repository content or logs outside this task.

## Live acceptance still required

No real HCL Entra registration or organizational test identity was supplied. Live
Microsoft authentication, MFA/Conditional Access, real consent/scope/account-type
claims, popup/browser behavior, ingress callback headers and multi-replica operation
remain unverified. This is not a production-readiness or cutover approval.

Need from HCL: directory UUID; distinct SPA/API application UUIDs; delegated API
scope/URI; v2 API access tokens; `acct` optional access-token claim; exact approved
HTTPS SPA redirect URI; consent/assignment policies and approved member/guest test
accounts. No client secret or Microsoft password is required by this integration.

Limitations: single HCL directory; local BFF logout only; no Entra BFF refresh
credential; no group/app-role authorization mapping; no automatic identity linking.
Native and HCL.CS implementations remain available.

## Files changed

| File | Reason |
| --- | --- |
| `.env.example` | Document opt-in Entra runtime settings |
| `alembic/versions/063_microsoft_entra_identity.py` | Add Entra provider and suspended-state constraints; protect downgrade |
| `app/auth.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/core/identity_states.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/core/native_identity.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/core/security.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/main.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/models.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/routers/entra_auth.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/routers/platform.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/routers/tenants.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/schemas_platform.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/account_state_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/auth_context_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/authenticated_principal_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/entra_auth_service.py` | Validate single-directory API JWTs and provision pending identities atomically |
| `app/services/identity_verification_policy.py` | Share directory identity eligibility without claiming mailbox verification |
| `app/services/platform_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/tenant_role_assignment_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/services/tenant_service.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `app/settings.py` | Integrate Entra with existing principal, status, identity and DB authorization services |
| `docs/microsoft-entra-phase1-acceptance.md` | Verification evidence, limitations and per-file change manifest |
| `docs/microsoft-entra-phase1.md` | Architecture, configuration and acceptance runbook |
| `frontend/.env.local.example` | Document opt-in Entra runtime settings |
| `frontend/package-lock.json` | Pin Microsoft MSAL Browser and its lockfile dependency |
| `frontend/package.json` | Pin Microsoft MSAL Browser and its lockfile dependency |
| `frontend/src/app/__tests__/userStates.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/access-denied/page.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/app/access-pending/page.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/access-pending/page.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/app/api/auth/entra/bridge/route.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/api/auth/entra/bridge/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/api/auth/entra/route.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/api/auth/entra/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/api/auth/login/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/api/auth/logout/route.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/api/auth/logout/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/api/auth/session/route.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/app/api/auth/session/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/api/backend/[...path]/route.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/app/auth/entra-callback/route.ts` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/app/logged-out/page.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/app/native-sign-in/page.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/app/settings/platform/page.tsx` | Display Entra users, approval, suspension and eligible identity selection |
| `frontend/src/app/sign-in/page.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/components/admin/StatusBadges.tsx` | Display Entra users, approval, suspension and eligible identity selection |
| `frontend/src/components/admin/TenantMembersTable.tsx` | Display Entra users, approval, suspension and eligible identity selection |
| `frontend/src/components/admin/UserLifecycle.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/components/admin/UserLifecycle.tsx` | Display Entra users, approval, suspension and eligible identity selection |
| `frontend/src/components/admin/UserSearchCombobox.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/components/admin/UserSearchCombobox.tsx` | Display Entra users, approval, suspension and eligible identity selection |
| `frontend/src/components/auth/AuthGuard.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/components/auth/MicrosoftSignIn.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/components/auth/MicrosoftSignIn.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/components/auth/NativeAuthForm.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/components/auth/__tests__/AuthGuard.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/components/layout/AppShell.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/hooks/useAuth.test.tsx` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/hooks/useAuth.tsx` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/lib/api.ts` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `frontend/src/lib/auth/entra-config.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/lib/auth/entra-config.ts` | Validate safe server-side Entra configuration |
| `frontend/src/lib/auth/production-config.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/lib/auth/production-config.ts` | Validate safe server-side Entra configuration |
| `frontend/src/lib/auth/session-store.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/lib/auth/shared-session-store.ts` | BFF token exchange, callback bridge and provider-specific session/logout behavior |
| `frontend/src/proxy.test.ts` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `frontend/src/proxy.ts` | Microsoft sign-in, pending/denied routing and provider-neutral presentation |
| `tests/test_entra_auth.py` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `tests/test_entra_discovery.py` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
| `tests/test_entra_migration.py` | Entra validation, provisioning, UI/session coverage or corresponding regression expectations |
