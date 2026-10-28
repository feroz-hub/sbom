# Native IAM Phase 3 — administrator lifecycle

## Repository state

1. **Branch:** `feat/native-user-management` only.
2. **Starting commit:** `6ce3d4e6fc55baa2006be61665e2d099d1b1e323` (`feat(iam): add native enrollment activation login and jwt`). Confirmed HEAD and ancestor before implementation; initial worktree was clean.
3. **Ending commit:** no commit created; HEAD remains the approved baseline. Nothing merged or pushed.
4. **Git status:** implementation is intentionally uncommitted. Final changed-file inventory and verification counts are recorded below.
5. **Files changed:** backend route/schema/service changes; existing settings pages and new lifecycle/invitation components; focused lifecycle tests; directly affected user-detail and candidate-search tests; this report. No unrelated work was discarded.

## APIs and behavior

6. **Added/extended APIs** (all paths below start with `/api`):

| Route | Change | Explicit authority |
| --- | --- | --- |
| `GET /platform/users` | Existing pagination/search plus all account states, tenant/role/provider filters and name/email/created/login sorting | `platform:user:read` and platform authority |
| `GET /platform/users/{user_id}` | Safe profile, all membership roles/versions, provider indicators, security and activity | `platform:user:read` and platform authority |
| `PATCH /platform/users/{user_id}/profile` | First name, last name, phone only | `platform:user:write` and platform authority |
| `PATCH /platform/users/{user_id}/status` | Existing route now uses central lifecycle for native/global transitions; legacy approval/idempotence retained | `platform:user:manage_status` and platform authority |
| `POST /platform/users/{user_id}/unlock` | Clear global lock and counters | `platform:user:manage_status` and platform authority |
| `POST /platform/users/{user_id}/force-password-change` | Native credential required; revoke tokens and block normal access | `platform:user:manage_status` and platform authority |
| `GET /platform/users/{user_id}/audit` | Safe, paginated user audit | `platform:user:read` and platform authority |
| `GET /tenants/{tenant_id}/users` | Paginated profile/membership results with search/account-status/role filters | `tenant:user:read` and selected tenant |
| `GET /tenants/{tenant_id}/users/{membership_id}` | Safe profile, this membership and this tenant's activity only | `tenant:user:read` and selected tenant |
| `PATCH /tenants/{tenant_id}/users/{membership_id}/profile` | Scoped profile edit | `tenant:user:update` and selected tenant |
| `GET /tenants/{tenant_id}/users/{membership_id}/audit` | Paginated audit scoped to target user and selected tenant | `tenant:user:read` and selected tenant |
| `GET /tenants/{tenant_id}/user-candidates` | Search restricted to existing members of selected tenant; external identity values withheld | `tenant:user:invite` and selected tenant |

Reused without duplicate APIs: membership addition (`POST /tenants/{tenant_id}/memberships`), membership `activate`/`deactivate`, multi-role grant/replace/revoke APIs, activation resend, and the deprecated platform status alias. Membership detail/status paths use **membership IDs**; role paths use **user IDs**. The frontend preserves that distinction.

7. **User list:** platform results remain bounded; tenant pagination is opt-in through `page` or filters so existing callers without paging retain their list response. Role filters use database catalog assignments with explicit membership and tenant predicates. Platform defaults retain existing sorting; new sort choices support ascending/descending API order. Native/HCL provider filters expose no identity secrets.
8. **User detail:** platform users see all memberships, including disabled memberships and their retained role assignments. Tenant users see only the selected membership; no other tenant names, memberships, roles, global audit history, or failed-login counters are included. Both receive safe profile/account/provider/timestamp fields.
9. **Profile editing:** extra payload fields are rejected. Names and phone have length/format checks. Email, normalized email, verification flags, identity identifiers, hashes, security versions and audit actor identity cannot be edited. The service also enforces its own field allowlist. Changes lock the account, check scoped membership, and record old/new values atomically. These are shared user profile fields, so the UI explains that edits apply across tenants.
10. **Global lifecycle:** platform-only status mutation uses central transitions, last-admin checks, user/credential locking, security-version revocation and sensitive-token invalidation. Memberships and assignments remain stored. Eligible re-enable changes the account only. A pending native enrollment cannot be enabled without its credential/verification; disable/enable cannot bypass an outstanding forced password change. Legacy HCL account approval remains supported.
11. **Membership lifecycle:** membership deactivation never changes global account status or another tenant's access. Reactivation requires usable assignments. Status operations serialize using tenant → user → membership locks compatible with role/global mutations. Existing last-tenant-admin safeguards and audit events remain intact. Stable user-ID addition reuses the same identity and rejects duplicates.
12. **Role management:** existing multi-role/catalog services remain authoritative. Grant, replacement, primary-role selection, revoke and optimistic versions remain in use. Tenant Admins cannot assign or remove `TENANT_ADMIN` authority or assign platform authority. Stale changes return conflicts; no silent merges. Current permissions remain the union of active roles in the selected tenant.
13. **Privacy/isolation:** all tenant reads and writes validate selected context and tenant/member ownership. The previous candidate-search behavior intentionally exposed global users to Tenant Admins; it conflicts with this phase's explicit privacy requirement and is now restricted. The older tenant page accepts a known stable user ID; only Platform Admins use global discovery. Existing candidate-search tests were updated to the new contract; their tenant seed was also corrected to supply required timestamps and retain fixture IDs after session close so they exercise the endpoint.
14. **Unlock:** platform-only, requires `LOCKED`, transitions to `ACTIVE`, clears failed-login count and lock timestamps, rotates native security version and records `USER_UNLOCKED`. Phase 2 automatic expiry handling and brute-force lockout remain unchanged.
15. **Force password change:** platform-only, enrolled native accounts only. Central transition records `FORCE_PASSWORD_CHANGE_SET`, revokes old native JWTs and prevents normal login/application access. **Completion is explicitly deferred to Prompt 5.** The confirmation warns that the user will remain blocked until that flow exists. No temporary normal-access token or unsafe administrative bypass was added.
16. **Resend activation:** lifecycle UI calls the existing scoped endpoint for pending native members. Existing five-hour token issuance, replacement/invalidation, cooldown/hour/day limits and email infrastructure remain in use. Delivery status/errors are shown. Phase 2 token rotation and scope regressions are included in verification.
17. **Audit:** uses existing `AuthorizationAuditLog`. User-specific projections expose only event ID, action, outcome, actor ID, tenant ID and timestamp; arbitrary historical JSON is not returned. Detail shows the newest 50 events; dedicated APIs paginate history. Tenant history requires both target membership and exact tenant scope. Profile and global lifecycle audit failures roll back their changes.
18. **HCL/native compatibility:** local membership, role and account authorization remains provider-neutral. Tests exercise HCL principal resolution through tenant deactivation and global disable. HCL-only accounts never acquire fabricated native credentials and reject native force-password actions. No linking or SF cutover was introduced.
19. **JWT/security version:** roles and membership changes require no replacement JWT. Tests reuse the identical token to demonstrate immediate permission loss and tenant-specific denial after committed changes. Global disable rejects that JWT in every tenant; later re-enable does not revive it. A concurrent request authorized before mutation commit may finish; subsequent resolution observes committed state.
20. **Frontend:** `/settings/native-users` contains search, status/role filters, platform tenant/provider/sort filters, pagination, profile editing, provider/activity/security display, membership controls, role/primary-role changes, add-membership, resend, global status, unlock and force-change actions. Permissions control visibility independently of backend enforcement. Existing shared confirmation dialog handles global disable, membership deactivation, role removal and force change. Tenant changes remount the lifecycle view so old details cannot remain visible. The original invitation form remains available.
21. **Migration:** none. Existing schema, authorization catalog, permissions, audit table and role assignment model are reused. All database verification targets the disposable test database; no application database migration was applied by this task.

## Verification

22. **Tests added:** 31 focused backend lifecycle tests, including parameterized restrictions, PostgreSQL concurrency, audit rollback, same-JWT behavior, native/HCL isolation, forbidden delegation and duplicate membership. Ten frontend lifecycle tests cover lists, scope, destructive confirmations, role versions, global actions, resend, loading/error states and tenant-switch privacy. An existing tenant-page test now verifies known-ID addition without global search. Existing detail/candidate-search assertions reflect the requested response/privacy contract.
23. **Commands run:** see the command block below. The main backend run includes native Phases 1/2, HCL/authentication, isolation, catalog, multi-role, platform-admin and candidate-search regressions. Baseline failures were reproduced from a read-only `git archive` export of the approved commit using the same interpreter and disposable test database, sequentially with other backend runs.
24. **Pass/fail counts:** across the latest result for each of **342 distinct backend tests, 339 pass and 3 baseline failures remain**. This is an aggregate of the broad run and focused rerun, not a claim of a single all-green invocation:
   - Broad regression: **318 passed, 21 failed**. Three are the baseline failures below; 18 were candidate-search fixture failures, subsequently corrected.
   - Final affected/supplemental run: **51 passed** = 31 lifecycle + 18 candidate-search + 2 native migration tests. This reran the corrected candidate fixtures and the lifecycle suite, including the additional two-administrator race.
   - Frontend full suite: **980 passed in 133 files**. After adding explicit retry behavior, its focused lifecycle suite passed **10/10** again.
   - Production frontend build and standalone TypeScript check: passed.
   - Changed Python Ruff and `git diff --check`: passed.
   - Changed frontend ESLint: **0 errors, 1 existing warning** (`_res` unused in the unchanged callback in `settings/platform/page.tsx`).
   - Warnings from tests include existing framework deprecations, legacy short HMAC test keys, jsdom limitations, and the native migration's deliberate duplicate-profile-email diagnostic. No warnings were globally suppressed.
25. **Pre-existing failures:** reproduced on the approved baseline:
   - `test_authenticated_tenant_write_preserves_context`: fixture attempts to create a `TENANT_ADMIN` role using Tenant Admin delegation; the existing guard rejects it (followed by the frozen exception traceback error).
   - `test_concurrent_grants_create_one_idempotent_effective_grant`: expects idempotent grant behavior; existing API returns `IAM_PLATFORM_ADMIN_ALREADY_GRANTED` (409).
   - `test_concurrent_revoke_and_grant_leave_one_consistent_row`: same existing active-grant conflict contract.
   - Candidate-search fixture omitted required tenant timestamps; reproduced separately. Its subsequent detached-instance issue was also fixed by retaining fixture values across commit. Both repairs are confined to this directly affected test file so the new privacy contract can be tested.
26. **Security findings addressed:** global candidate discovery by Tenant Admins; legacy status transitions missing centralized native lifecycle handling; disabling/enabling bypassing forced-password state; Tenant Admin removal of another admin role; membership status races; secret-safe scoped projections. No production penetration test or live HCL server login is claimed. Forced-change re-enable eligibility consults retained successful audit events and `password_changed_at`; Prompt 5 must preserve that invariant when completing password changes.
27. **Deferred scope:** password-change completion, forgot/reset-password, MFA, shared sessions, refresh tokens, key rotation, resource ACLs, automatic identity linking, SF cutover, full UI redesign. No unrequested infrastructure or production deployment.
28. **Recommended Prompt 5:** implement proof-bound native password-change completion for forced accounts, with fresh credential verification, strong password validation, atomic hash/timestamp/status/version updates, audit, rate limiting, replay/race tests, and session/token revocation. Define separately authorized reset/recovery requirements before building those flows. Preserve tenant membership and database-authoritative permission semantics.

### Acceptance evidence

| Required scenario | Test |
| --- | --- |
| A: same user, different roles in A/B | `test_platform_list_filters_detail_and_redaction`, `test_membership_deactivate_preserves_global_and_other_tenant` |
| B: A deactivated; B remains authorized | `test_membership_deactivate_preserves_global_and_other_tenant` |
| C: global disable denies both and old JWT | `test_global_disable_and_reenable_preserve_memberships`, `test_concurrent_disable_vs_login` |
| D: same JWT loses removed A permission | `test_roles_version_and_same_jwt` |
| E: tenant cannot view/modify B | `test_tenant_list_detail_search_and_audit_private`, `test_profile_payload_scope_and_role_assignment_tampering` |
| F: HCL follows same local RBAC | `test_hcl_same_principal_obeys_membership_roles_and_global_status`, existing HCL/auth tests |

Concurrency cases: disable/login, membership deactivate/authorization, replace/grant, enable/disable, unlock/login, plus existing two-administrator optimistic-version and last-admin concurrency suites. Tests use independent database sessions and barriers for the new races.

```sh
.venv/bin/pytest -q \
  tests/test_native_iam_phase3.py tests/test_native_iam_foundation.py tests/test_native_iam_phase2.py \
  tests/test_hcl_iam_auth.py tests/test_auth.py tests/test_auth_integration.py \
  tests/test_tenant_isolation.py tests/test_phase4_auth_context.py \
  tests/test_phase6_platform_users.py tests/test_phase6_platform_status.py \
  tests/test_phase6_platform_administrators.py tests/test_phase6_platform_concurrency.py \
  tests/test_phase6_platform_bootstrap.py tests/test_phase8*.py tests/test_phase9*.py \
  tests/test_tenant_user_candidates.py tests/test_user_search.py
.venv/bin/pytest -q tests/test_tenant_user_candidates.py tests/test_native_iam_phase3.py tests/test_native_identity_migration.py
# In frontend, with Node 20 on PATH:
npm test
npx tsc --noEmit
npm run build
# Changed backend files and tests:
.venv/bin/python -m ruff check app/core/security.py app/routers/platform.py app/routers/tenants.py \
  app/schemas_platform.py app/schemas_user_management.py app/services/account_state_service.py \
  app/services/platform_service.py app/services/tenant_role_assignment_service.py \
  app/services/user_management_service.py tests/test_native_iam_phase3.py \
  tests/test_phase6_platform_users.py tests/test_tenant_user_candidates.py
# Changed frontend files:
npx eslint src/components/admin/UserLifecycle.tsx src/components/admin/UserLifecycle.test.tsx \
  src/components/admin/NativeUserInviteForm.tsx src/app/settings/native-users/page.tsx \
  src/app/settings/tenant/page.tsx src/app/settings/tenant/page.test.tsx src/app/settings/platform/page.tsx
git diff --check
git status --short --branch
```

### Final worktree inventory

```text
## feat/native-user-management...origin/feat/native-user-management
 M app/core/security.py
 M app/routers/platform.py
 M app/routers/tenants.py
 M app/schemas_platform.py
 M app/services/account_state_service.py
 M app/services/platform_service.py
 M app/services/tenant_role_assignment_service.py
 M frontend/src/app/settings/native-users/page.tsx
 M frontend/src/app/settings/platform/page.tsx
 M frontend/src/app/settings/tenant/page.test.tsx
 M frontend/src/app/settings/tenant/page.tsx
 M tests/test_phase6_platform_users.py
 M tests/test_tenant_user_candidates.py
?? app/schemas_user_management.py
?? app/services/user_management_service.py
?? docs/native-iam-phase3.md
?? frontend/src/components/admin/NativeUserInviteForm.tsx
?? frontend/src/components/admin/UserLifecycle.test.tsx
?? frontend/src/components/admin/UserLifecycle.tsx
?? tests/test_native_iam_phase3.py
```

HEAD remains `6ce3d4e6fc55baa2006be61665e2d099d1b1e323`. No files were staged or committed. Build-generated changes to `frontend/next-env.d.ts` were restored to the original tracked content.
