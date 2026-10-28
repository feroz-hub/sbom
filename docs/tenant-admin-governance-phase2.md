# Tenant Administrator Governance — Phase 2 implementation report

Review date: 24 October 2026. Tracking: SBO-83; acceptance follow-up: SBO-84.

Sections 1–20 preserve the implementation-stage evidence and its original Git
status. Section 21 records the subsequent independent agent review and fresh
validation, and supersedes the earlier build/status limitations where stated.

## 1. Executive summary

The existing platform tenant detail page now supports restricted Tenant
Administrator governance: revoke administrator authority, deactivate membership,
and remove membership. Each action has a distinct confirmation with accurate
tenant/global-account scope, optional audit reason, server-confirmed success,
and actionable failure handling.

A narrow, read-only platform metadata endpoint closes disabled-administrator
discovery and supplies assignable ordinary replacement roles. Phase 1 mutation
semantics, permissions, transactions, audit, and isolation protections are
unchanged. No Phase 3 implementation, deployment, push, or Git commit is included.

## 2. Repository and branch

Repository: `/Users/ferozebasha/sbom`. Branch: `feat/native-user-management`.
The initial working tree and index were clean. No unrelated starting changes
were present. Local-only implementation changes remain available for review.

## 3. Starting commit

`e7fa95965edbc64a77b7c8ae61792887273154eb`

The commit was verified as HEAD before implementation. Its Phase 1 report was
read in full. The current handlers, Pydantic models, route policies, permission
resolution, public UUID boundary, and newly generated OpenAPI were inspected.
Historical saved OpenAPI snapshots were not used as the authority or overwritten.

## 4. Architecture findings

- `useAuth` exposes server-resolved permissions and `isPlatformContext`;
  `usePermissions` fails closed during bootstrap or tenant-context resolution.
- The shared client uses the authenticated Next.js `/api/backend` proxy when
  authentication is enabled; platform requests strip `X-Tenant-ID`. Existing
  cookies, session refresh, trusted-origin checks, and provider flows are reused.
- TanStack Query owns server state. Existing centralized invalidation helpers
  cover platform summary, tenant list variants, tenant details, and membership
  projections. Query defaults normally retain data for five minutes.
- Existing `Dialog`, `Button`, toast notifications, role labels, and mutation
  scope guards provide the confirmation and asynchronous lifecycle conventions.
- Existing tenant detail exposes effective administrators only. The ordinary
  `/api/tenant-roles` catalogue requires tenant-user read permission. Granting
  that permission to Platform Admin would violate Option A. The general platform
  catalogue also requires an unrelated authorization catalogue permission.
- `PlatformTenantOverview` already rendered current administrators as well as
  initial-setup identity information. Its optional current-list display is
  suppressed on this page so the governance directory is the single current list.
  Initial setup information remains explicitly historical.

## 5. UI components created or modified

`TenantAdministratorGovernance` contains the administrator membership directory
and operation-specific confirmation content using the shared accessible dialog.
It lives under Settings → Platform → Tenants → selected tenant. The page and
directory require platform context; actions additionally require
`platform:tenant_admin:manage`.

Rows show identity, membership status, primary and other assigned roles, and
effective authority. Ineffective or disabled memberships retain visible
administrator assignments with an explicit “not effective” status. Deactivate
is offered only for active memberships; revoke/remove remain available for
preserved administrator assignments. Backend eligibility remains authoritative.

Controls wrap at smaller widths; theme tokens and dark variants match existing
components. Dialogs have labels, descriptions, focus trapping/restoration,
Escape/cancel handling, loading state, and guarded dismissal during submission.

## 6. API client changes and exact contracts

All new identity selectors are UUID strings. The membership selector never uses
the global user UUID, platform grant UUID, or an internal integer.

| Method / path under `/api/platform/tenants/{tenant_id}` | Request | Success |
| --- | --- | --- |
| `GET /administrators` (new) | Tenant UUID; cancellable GET | 200 `TenantAdministratorDirectory` |
| `POST /administrators/{membership_id}/revoke` | JSON `expected_version` >= 1, conditional `replacement_primary_role_code`, optional `reason` | 200 `TenantAdministratorGovernanceResponse` |
| `POST /administrators/{membership_id}/deactivate` | JSON optional `reason`; client sends `{}` if absent | 200 `TenantAdministratorGovernanceResponse` |
| `DELETE /administrators/{membership_id}` | Optional URL-encoded `reason` query; no request body | 204, empty body |

The three Phase 1 mutation responses contain `tenant_id`, `membership_id`,
`user_id`, `status`, `roles`, `primary_role`, and `role_assignment_version`.
Their semantics and schemas are unchanged.

New directory response:

```json
{
  "tenant_id": "00000000-0000-4000-8000-000000000007",
  "administrators": [{
    "tenant_id": "00000000-0000-4000-8000-000000000007",
    "membership_id": "00000000-0000-4000-8000-000000000008",
    "user_id": "00000000-0000-4000-8000-000000000009",
    "status": "DISABLED",
    "roles": ["SECURITY_ANALYST", "TENANT_ADMIN"],
    "primary_role": "SECURITY_ANALYST",
    "role_assignment_version": 3,
    "display_name": "Example Administrator",
    "email": "administrator@example.test",
    "account_status": "ACTIVE",
    "is_effective": false
  }],
  "replacement_roles": [{"code": "SECURITY_ANALYST", "name": "Security Analyst", "scope": "TENANT"}]
}
```

The example contains synthetic identifiers. OpenAPI confirms UUID formats for
the path tenant and every tenant/user/membership response field. Catalogue role
IDs are unnecessary and excluded. Names/emails are nullable.

The shared `ApiError` retains `detail`, `code`, field validation errors and
`current_version`. The UI distinguishes expired sessions (401), denied authority
(403), missing membership/tenant (404), stale/last-admin/other conflicts (409),
and safe validation messages (422). Internal or credential-like messages still
pass through the existing notification sanitizer.

## 7. Administrator discovery solution

`GET /api/platform/tenants/{tenant_id}/administrators` requires the existing
protected governance permission and verified platform context. It checks the
tenant and selects only memberships with an ACTIVE `TENANT_ADMIN` assignment
linked to an ACTIVE TENANT catalogue role, regardless of membership status.
Ordinary tenant users are excluded at the database query.

The read-only service uses bounded tenant authorization metadata scope and
existing role-resolution helpers. Effective authority additionally requires
ACTIVE membership, ACTIVE IAM account, and completed verification. Tenant
availability remains a separate tenant status; this authority flag follows the
existing effective-administrator eligibility definition.

Replacement roles come from ACTIVE, assignable TENANT catalogue entries,
excluding `TENANT_ADMIN` and `PLATFORM_ADMIN`; custom ordinary tenant roles are
supported. The mutation service revalidates every submitted role. No new tenant
operational permission or authorization catalogue administration grant is needed.

## 8. Revoke workflow

The dialog displays tenant, administrator, primary role, other roles, and optional
reason. Primary administrator assignments require an explicit ordinary role from
the returned catalogue. The blank initial choice never silently grants VIEWER.
Existing approved ordinary assignments can be selected and are labelled.
Secondary administrator assignments require no replacement.

The loaded role-set version is submitted unchanged. Stale 409 responses reload
the directory and disable confirmation. The user must review the updated
membership, reselect any required role, and explicitly submit a new request.
Background changes to status, role set, primary role, or effective authority also
block an open dialog. Governance mutations explicitly disable TanStack mutation
retries, including when a QueryClient has a retrying mutation default. The reused
BFF retains its existing conditional 401 session-refresh/resend behavior for
refreshable HCL sessions; this is not a transport-wide at-most-once guarantee.

## 9. Deactivation workflow

The separate dialog explains tenant-only access loss, preserved assignments,
unchanged global identity, and unchanged other tenant memberships. Successful
backend confirmation refreshes the row to DISABLED / not effective, preserving
roles for later governance. There is no reactivation workflow in this task and
no claim that identity-provider accounts or existing sessions were terminated.

## 10. Removal workflow

The destructive dialog names the tenant and administrator and displays the exact
membership UUID. Its explanation expressly preserves global identity and other
tenant memberships. Optional reason is a query parameter. `requestVoid` and the
existing proxy correctly accept HTTP 204 without parsing JSON. The row changes
only after confirmed success and a directory refresh; failed removal retains it.

## 11. Authorization and tenant isolation

Platform-context and resolved-permission checks gate rendering and requests.
Direct tenant-context navigation cannot fetch privileged metadata or display
controls, even with stale platform permission presentation. Read-only callers
without governance permission retain only the existing effective-admin summary.
No tenant selection/switch is performed to make governance possible.

The server remains authoritative, including actual database grants and account
verification. Phase 1 still enforces exact tenant/membership identity,
replacement assignability, last-effective-admin locks, protected tenant-admin
peer/self paths, audit rollback, and durable deletion history. No global user,
other membership, platform grant, authentication provider, or business-data
authorization mechanism was changed.

## 12. State refresh and cache invalidation

Success invalidates all `platform-summary`, `platform-tenants`, selected
`platform-tenant`, and selected `platform-tenant-administrators` query variants.
Existing membership invalidation covers affected membership/role/audit and
assignment projections. The new directory key includes tenant and current actor;
GET requests receive TanStack's abort signal.

The page and directory reset confirmations on tenant/account/platform-context
changes. Existing mutation scope guards suppress late notifications and local
state updates after navigation/logout. Successful server writes still invalidate
the original tenant's caches. If the target is the acting account,
`refreshSession({ authorizationChanged: true })` refreshes its presentation.
Other users' open browsers are not remotely refreshed by this implementation.

## 13. Automated tests and actual results

| Run in this implementation task | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Pre-change frontend baseline, 3 files | 29 | 0 | 0 |
| Final focused UI/client/page coverage, 3 files | 47 | 0 | 0 |
| Final frontend regression, 35 files | 360 | 0 | 0 |
| Explicit no-retry safeguard rerun, component suite | 27 | 0 | 0 |
| Real-auth governance, role, lifecycle, platform and OpenAPI suite | 153 | 0 | 0 |
| Additional identity/provider, creation, catalogue and UUID regressions | 235 | 0 | 0 |
| Synthetic browser scenarios, real component/shared client over HTTP | 8 scenarios | 0 | 0 |

The focused/regression frontend totals overlap; do not add them together. Prior
Phase 1 counts are historical and are not substituted for these runs. The full
unrelated repository test suites were not run.

Eight new backend cases exercise actual signed native authentication, database
grant/permission resolution, disabled secondary-role membership discovery,
ordinary-member exclusion, tenant boundaries, custom-role catalogue filtering,
401/403/404 behavior, and generated OpenAPI/public UUID serialization.

Frontend tests cover permission bootstrap, platform-context/direct navigation,
all three actions, explicit primary replacement/custom roles, no silent VIEWER,
secondary revocation, missing catalogue choices, versions, stale/background
refresh review, last-admin/401/403/404/422 errors, reasons, actual DELETE request
shape and empty response, query invalidation, failure retention, disabled rows,
keyboard/cancel/focus, double submission, late navigation responses, and self
authorization refresh. Existing cache integration fixtures now supply platform
context and the existing ToastProvider.

Database tests used a newly initialized task-owned PostgreSQL 18 cluster on
`127.0.0.1:55459`, database `sbom_phase2_test`. Only that disposable cluster was
bootstrapped/migrated and written. No deployed services or customer databases
were started, restarted, migrated, or written. The task-owned cluster and preview
services were stopped after validation.

Development failures were corrected before final results: invalid test model
field/grant status, an incorrect stale-header expectation, missing auth/toast
fixture state, garbage collection/timing assertions, and an asynchronous cache
notification assertion. Two mistyped test filenames caused collection-only
attempts with no tests executed; the corrected selections passed. These are not
pre-existing baseline failures and are not counted as successful runs.

## 14. TypeScript, lint, build and regression checks

- `tsc --noEmit --incremental false`: passed.
- Repository-wide `eslint .`: exit 0, zero errors, 49 warnings. The warning files
  outside `api.ts` are unchanged; the two `api.ts` warnings were reproduced from
  HEAD using ESLint stdin. No new lint warning is attributed to this change.
- Ruff on all seven changed Python files: passed.
- Python `compile()` on changed Python sources: passed without cache artifacts.
- Alembic heads: one head, `103_tenant_admin_governance`; no new migration.
- Git whitespace validation: passed. Generated `next-env.d.ts` path changes from
  the build were restored to the verified starting content and are excluded.
- `next build --webpack` with `NODE_OPTIONS=--dns-result-order=ipv4first`: passed
  compilation, TypeScript, all 47 static pages, tracing and final output.
- Standard Turbopack build and its IPv4-preference retry stalled during the
  existing Google Fonts network fetch and were interrupted. The Rust/Turbopack
  connection still used IPv6 despite the Node DNS preference. Default Turbopack
  build completion remains an environment-specific verification limitation;
  no font mocks, TLS bypasses, or application font/config changes were used to
  obtain the successful Webpack production build.

Representative commands (bundled Node executable was used because this host's
system Node has previously had a dependency-loading problem):

```sh
cd frontend
node node_modules/vitest/vitest.mjs run \
  src/components/admin src/app/settings/platform src/app/platform \
  src/lib/queryInvalidation.test.ts src/lib/api.tenantGovernance.test.ts \
  src/lib/api.tenantHeader.test.ts src/__tests__/mutation-invalidation.test.ts \
  src/app/api/backend src/app/api/auth src/proxy.test.ts \
  src/components/ui/PermissionButton.test.tsx --maxWorkers=1
node node_modules/typescript/bin/tsc --noEmit --incremental false
node node_modules/eslint/bin/eslint.js .
NODE_OPTIONS=--dns-result-order=ipv4first NEXT_TELEMETRY_DISABLED=1 \
  node node_modules/next/dist/bin/next build --webpack
```

Backend focused selection: `test_tenant_admin_governance`,
`test_phase9_role_assignment_api`, `test_phase9_role_assignment_security`,
`test_phase9_role_assignment_concurrency`, `test_platform_tenant_v2`,
`test_phase6_platform_status`, `test_identity_administration`, and
`test_openapi_security`, under `tests/`, with explicit disposable test URL
environment variables and `.venv/bin/python -m pytest -q --tb=short`.

Backend additional selection: `test_phase7_tenant_creation`,
`test_phase7_tenant_creation_authorization`, `test_phase7_tenant_creation_atomicity`,
`test_phase7_tenant_creation_concurrency`, `test_phase9_tenant_creation_integration`,
`test_public_resource_uuid`, `test_iam_user_public_uuid`,
`test_phase6_platform_administrators`, `test_phase8_authorization_catalog_api`,
`test_phase8_authorization_catalog_seed`, `test_native_iam_phase2`,
`test_entra_auth`, and `test_hcl_iam_auth`.

Local final logs live outside Git at `/tmp/sbom-phase2-ui-regression-final.log`,
`/tmp/sbom-phase2-backend-focused.log`, `/tmp/sbom-phase2-backend-regression.log`,
`/tmp/sbom-phase2-lint-final.log`, and `/tmp/sbom-phase2-build-webpack-final.log`.
Existing Pydantic/Alembic deprecations, synthetic test-key warnings and jsdom
pseudo-element limitations remain visible in the relevant test output.

## 15. Backend metadata changes

One additional GET route, an explicit policy, three response models, and a
read-only directory function were added. UUID schema registration extends the
existing public boundary for the new membership response. No request-selector
exception, permission catalogue/mapping, mutation handler, database model,
migration, global middleware bypass, or tenant-user permission was added.
The original tenant detail contract is additive-compatible and unchanged by
the new discovery endpoint.

## 16. Files modified

| Area | Files |
| --- | --- |
| UI | `frontend/src/components/admin/TenantAdministratorGovernance.tsx` (new), `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx`, `frontend/src/components/admin/PlatformTenantOverview.tsx` |
| Client/state | `frontend/src/lib/api.ts`, `frontend/src/lib/queryInvalidation.ts` |
| Frontend tests | `frontend/src/components/admin/__tests__/TenantAdministratorGovernance.test.tsx` (new), `frontend/src/lib/api.tenantGovernance.test.ts` (new), `frontend/src/app/settings/platform/tenants/[tenantId]/page.test.tsx`, `frontend/src/app/platform/data-sync.integration.test.tsx`, `frontend/src/lib/queryInvalidation.test.ts` |
| Metadata backend | `app/routers/platform.py`, `app/schemas_platform.py`, `app/services/tenant_admin_governance_service.py`, `app/core/route_policies.py`, `app/resource_public_api.py`, `app/iam_public_api.py` |
| Backend tests | `tests/test_tenant_admin_governance.py` |
| Report | `docs/tenant-admin-governance-phase2.md` (new) |

## 17. Remaining limitations and browser evidence

There are no known failing final selected tests. Default Turbopack completion
remains unverified as described above. Human/organizational independent review,
full application provider sign-in in a browser, live BFF-to-FastAPI workflows,
physical mobile/screen-reader testing, and deployed multi-instance acceptance
were not established by this task.

The in-app browser backend was unavailable. Bundled Playwright launched installed
Chrome in a fresh headless profile against a loopback-only temporary Vite preview
of the real component/shared API client and a Postman CLI 1.75.0 simulation.
Only authentication presentation was synthetic; no customer identities, tokens,
or tenants were used. The mock was based on current generated governance OpenAPI
and source-backed mutation semantics. This is component HTTP/browser evidence,
not a complete application or production authentication test. Typography used a
system-font fallback; application theme/Tailwind utilities were loaded.

The first preview lacked Tailwind utilities and was rejected for visual evidence.
After correcting its working directory and font fallback, all eight browser
scenarios passed again. Corrected captures were inspected at 1280×900 and
390×844, including light/dark mode, wrapping controls, dialog and focus behavior,
and no horizontal overflow. Seven privileged synthetic HTTP mutation requests
exercised success/204, stale 409, last-admin 409 and 403 feedback. No page errors
were observed in the final browser run.

Evidence outside Git: `/tmp/sbom-phase2-browser-evidence/results.json`,
`desktop-light.png`, `mobile-dark.png`, `revoke-dialog.png`, and
`mobile-remove-dialog-dark.png` in the same folder. The temporary reproduction
harness is `/tmp/sbom-phase2-preview`; its Postman request log is
`/tmp/sbom-phase2-simulation.ndjson`. These local temporary files are not durable
release artifacts and should be retained separately if needed for review.

Already-running requests and other users' open tabs are not forcibly cancelled
or refreshed. New backend requests use database-backed authority as in Phase 1.
The directory covers active administrator assignments on active catalogue roles,
including disabled/pending memberships; revoked/inactive assignments are outside
its actionable scope. No generic tenant user editor or administrator reactivation
workflow was introduced.

## 18. Phase 3 / SBO-84 acceptance requirements

After review, validate the complete deployed browser/proxy/backend path in a
controlled acceptance environment: separate Platform Admin and tenant-only
accounts; primary/secondary/custom replacement cases; last-admin concurrent
mutations; exact cross-tenant selectors; disabled discovery/removal; durable
audit/history; preserved accounts, grants and other memberships; platform
dashboard return navigation; and affected users' next authorization requests.
Exercise Native, HCL.CS and Entra sign-in with the configured providers and verify
keyboard, responsive layouts, and accessible names in the complete shell.
Resolve the standard Turbopack network build limitation in the release environment.
SBO-83 and SBO-84 were not marked Done or otherwise updated by this task.

## 19. Deployment prerequisites

Release the frontend with the new metadata backend and Phase 1 backend present.
Controlled environments must already have revision 103 and the protected
`platform:tenant_admin:manage` mapping, with production-required DATABASE
authorization/assignment modes. Verify authenticated BFF configuration, current
OpenAPI UUIDs, catalogue replacements, success/denial feedback and audit retrieval.
No Phase 2 database migration is needed. Deployment, service restarts, production
data changes and remote pushes remain outside this task.

## 20. Final status and Git working tree

Locally implemented and tested: governance UI, narrow disabled-membership
discovery, role catalogue integration, state synchronization, focused and
regression checks, and synthetic browser HTTP behavior. Preserved for review:
18 scoped modified/new files, with no staged changes and HEAD unchanged.

Not performed: Git commit, push, merge, deployment, production migration,
production verification, independent human approval, or Phase 3 implementation.
Local implementation is ready for review; full SBO-84 acceptance and default
Turbopack build verification remain outstanding. Do not describe this as
production-ready or deployed.

## 21. Final review and fresh validation — 24 October 2026

### Review scope and baseline

The final-review task verified `/Users/ferozebasha/sbom`, branch
`feat/native-user-management`, with HEAD at Phase 1 commit
`e7fa95965edbc64a77b7c8ae61792887273154eb`. Initial state matched the handoff:
14 modified tracked files, four new files, and an empty index. All 18 files in
section 16 were reviewed; no unrelated changes were found. Both implementation
reports were read in full.

Independent frontend, backend and architecture agents reviewed the changed
paths, with parent verification of their conclusions. The Codex Security diff
scan completed with no reportable findings and complete changed-file coverage:
`9e86292b-a244-4d3b-a8a9-1cf58e39ba88`. Source hashes remained unchanged during
the scan. This is agent review, not human or organizational security approval.

### Security and contract conclusions

- The directory requires database-resolved `platform:tenant_admin:manage` and
  verified platform context. The route policy, dependency and service guard
  fail closed. Direct unauthenticated and tenant-only API calls are tested.
- The requested tenant scopes membership and assignment queries. Only active
  TENANT_ADMIN assignments on active TENANT catalogue roles are returned,
  including secondary assignments and disabled memberships; ordinary members
  and revoked assignments are excluded. Public tenant/user/membership selectors
  serialize as UUIDs, not internal integer identifiers.
- Returned fields are governance metadata only. Replacement choices are active,
  assignable ordinary TENANT roles, including custom roles; platform/admin roles
  are excluded and mutation-time validation remains authoritative.
- Existing Phase 1 mutation function ASTs are identical to the committed
  baseline. Locks, last-admin checks, version checks, durable audit/history,
  membership-only deletion and account/other-tenant preservation remain intact.
- Frontend selection uses the exact membership UUID and unchanged loaded role
  version. Primary revocation requires an explicit replacement. DELETE uses a
  reason query parameter and accepts an empty 204. Error, stale-review and
  refresh behavior matches the actual API contracts; no optimistic privilege
  removal occurs.
- Actor/tenant changes remount confirmation state. Scope guards suppress late
  local effects, original-tenant invalidation remains intact, and affected
  current-account presentation refreshes. A request already accepted by the
  backend is not cancelled or rolled back by navigation.

One candidate was investigated and rejected as an authorization defect:
`is_effective` at `tenant_admin_governance_service.py:64` represents active
account/membership/verification eligibility for the administrator assignment,
independently of tenant availability. This matches section 7 and existing admin
count semantics. Actual tenant access still requires an active tenant through
the authorization resolver. No security boundary trusts this display flag.

No critical, high, medium or low reportable security findings remained. Two
informational qualifications apply: the existing BFF 401 refresh/resend remains,
and deployment must verify authentication-enabled frontend build flags rather
than assuming runtime API configuration changes compiled public flags.

### Fresh tests and checks

| Fresh final-review run | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Governance component/client/page, 3 files | 47 | 0 | 0 |
| Frontend regression, 35 files | 360 | 0 | 0 |
| Real-auth backend governance/role/platform/OpenAPI, 8 files | 153 | 0 | 0 |

The 47 frontend cases overlap the 360 regression cases and must not be added.
Backend pytest emitted 151 warnings; none failed the selected run. The previous
235 additional backend regressions and eight synthetic browser scenarios were
not rerun in this review. No fresh full-application browser evidence is claimed.

Fresh checks: TypeScript passed; ESLint exited 0 with 0 errors and 49 retained
warnings; Ruff and Python compilation passed; Alembic reported exactly one head,
`103_tenant_admin_governance`; Git whitespace passed; Gitleaks scanned all 18
scoped source/test/report files and found no leaks.

Both production build modes passed in a disposable frontend copy, without
environment files/certificates and without editing fonts, TLS or app config:

- Default `next build` (Turbopack): exit 0, 55.68 seconds.
- `next build --webpack`, with Node IPv4 DNS preference: exit 0, 60.94 seconds.

The previous Google Fonts/Turbopack stall did not recur, establishing that it
was not a reproducible build blocker in this review environment. A preliminary
build command ran before dependency-copy preparation completed and failed with
MODULE_NOT_FOUND; this was an understood review-harness sequencing error. The
properly prepared rerun and both final builds passed. No application correction
was needed.

Commands were run with the bundled Node runtime and the repository `.venv`:

```sh
node node_modules/vitest/vitest.mjs run src/components/admin/__tests__/TenantAdministratorGovernance.test.tsx src/lib/api.tenantGovernance.test.ts 'src/app/settings/platform/tenants/[tenantId]/page.test.tsx' --maxWorkers=1
node node_modules/vitest/vitest.mjs run src/components/admin src/app/settings/platform src/app/platform src/lib/queryInvalidation.test.ts src/lib/api.tenantGovernance.test.ts src/lib/api.tenantHeader.test.ts src/__tests__/mutation-invalidation.test.ts src/app/api/backend src/app/api/auth src/proxy.test.ts src/components/ui/PermissionButton.test.tsx --maxWorkers=1
node node_modules/typescript/bin/tsc --noEmit --incremental false
node node_modules/eslint/bin/eslint.js .
node node_modules/next/dist/bin/next build
NODE_OPTIONS=--dns-result-order=ipv4first node node_modules/next/dist/bin/next build --webpack
.venv/bin/python -m pytest -q --tb=short tests/test_tenant_admin_governance.py tests/test_phase9_role_assignment_api.py tests/test_phase9_role_assignment_security.py tests/test_phase9_role_assignment_concurrency.py tests/test_platform_tenant_v2.py tests/test_phase6_platform_status.py tests/test_identity_administration.py tests/test_openapi_security.py
ruff check app/core/route_policies.py app/iam_public_api.py app/resource_public_api.py app/routers/platform.py app/schemas_platform.py app/services/tenant_admin_governance_service.py tests/test_tenant_admin_governance.py
.venv/bin/python -m alembic heads
git diff --check
```

Frontend commands use the frontend directory; backend commands use the
repository root. Pytest's two test URL variables explicitly pointed to a new
task-owned PostgreSQL 18 cluster on `127.0.0.1:55469`, database
`sbom_phase2_review_test`. Only that disposable database was bootstrapped and
migrated. The service was stopped and the port verified closed after tests.
No existing application or deployed service was restarted.

Durable review logs, model, candidate disposition, source coverage and canonical
report are stored outside Git under the local Codex Security scan directory:

`/Users/ferozebasha/.codex/state/plugins/codex-security/scans/sbom/e7fa95965edbc64a77b7c8ae61792887273154eb_20261024T162422Z_dspliu8s/`

Its recorded usage is cumulative across five contributing conversation threads
(12,604,027 total tokens, including cached context); it is not a review-only cost
or newly consumed-token estimate.

### Corrections, commit gate and remaining acceptance

No source behavior was corrected during final review. This report was clarified
to distinguish TanStack retries from existing transport refresh and to add fresh
evidence. The complete staged patch must contain exactly the reviewed 18 files;
logs, database files, build outputs, preview harnesses and local scan state are
excluded. The authorized next step is one local Phase 2 commit referencing
SBO-83, with the exact SHA and final status verified from Git after creation.

Local tests and independent agent review pass the local commit gate. Human/
organizational approval, complete application/provider/BFF-to-FastAPI browser
acceptance, physical device/screen-reader checks and deployed multi-instance
acceptance remain under SBO-84. No issue is marked Done by this review.

Deployment requires the committed Phase 1 backend, revision 103 and protected
permission mappings, correct DATABASE authorization/assignment modes, verified
authentication-enabled frontend build flags and trusted BFF origin/upstream
configuration. No Phase 2 migration is added. Push, merge, deployment, production
migration and production verification remain unperformed.
