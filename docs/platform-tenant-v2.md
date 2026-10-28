# Platform / tenant privilege segregation V2

Platform grants govern the control plane, never customer data. The active
context's permissions are authoritative in both API dependencies and navigation.
An identity with Platform Admin and Olympus Viewer grants has platform authority
in platform context and **only Viewer** authority inside Olympus. Tenant entry
requires a live ACTIVE membership and an active tenant.

Migration `064_platform_tenant_v2` replaces only the PLATFORM_ADMIN mapping with
the frozen V2 allowlist. Frozen V1 and tenant role mappings are not rewritten.
Database mode fails closed when the V2 platform catalogue is incomplete or its
query fails. Cross-scope mappings are forbidden; platform:user permissions are
not granted to ordinary Platform Admins. Existing directory endpoints remain
permission-gated but are not exposed as ordinary Platform Admin capabilities.

Platform Admin retains tenant read/create/status/bootstrap/recovery, platform
administrator read/grant/revoke, authorization-catalogue administration, health,
and platform configuration. Tenant operational and arbitrary global account
lifecycle permissions are removed. Tenant Admin permissions/delegation remain
tenant-scoped and unchanged by this migration.

The accompanying scoped-configuration extension expands the unreleased V2
allowlist to 19 explicit platform permissions. Migration 065 adds seven tenant
configuration permissions to Tenant Admin without restoring Platform Admin
tenant access; see [scoped configuration](scoped-configuration.md).

`/platform` is the control-plane landing page. Platform tenant details show
counts and administrator governance, not membership editors or customer data.
Recovery adds a new eligible administrator without making the actor a member;
it does not silently change an existing non-admin/disabled membership or revoke
the old administrator. Invited initial administrators retain the existing
transactional encrypted-outbox and activation workflow.

`/settings/users` is tenant administration only. Existing-account lookup exposes
minimal eligible identity information, excludes existing members, and never
returns other tenant memberships. Membership disable/remove changes only that
membership, not the global account. Legacy user routes redirect here.

Recent audit activity requests five canonical administrative events; routine
context telemetry and paired legacy membership telemetry are excluded. The full
tenant audit page uses server pagination, search, category, outcome and date
filters. Technical identifiers are displayed only in event details.

## Deployment and rollback

Apply the migration before starting V2 application processes; refresh existing
sessions to pick up live context permissions. Existing PA-only users lose tenant
access intentionally: give explicit memberships through tenant bootstrap or
authorized tenant administration, never by synthetic membership backfill.

Automatic downgrade is intentionally refused because restoring V1 restores
customer-data superuser authority. Roll back application artifacts only with a
compatible authorization boundary, or restore a reviewed database backup under
an explicit security change process. Do not enable legacy authorization as a
rollback workaround. No customer identities/memberships are deleted by V2.

## Verification (2026-10-01)

- Backend security/foundation group: 192 passed.
- Updated platform policy/regression group: 90 passed.
- Catalogue migration, concurrency, native IAM and AI regression group: 205 passed.
  These groups overlap; the counts are not a unique-test total. The complete
  repository backend suite was not completed.
- Focused frontend authorization, dashboard, governance and audit tests:
  94 passed across 11 files.
- Full frontend suite: 1,135 passed; eight tests skipped in one failing setup
  because the environment lacks the `redis-server` executable.
- Frontend lint: zero errors, 53 existing warnings. Typecheck and production
  build passed (build used the development API URL).
- Ruff on every changed/new Python file passed. Repository-wide Ruff reports
  27 existing errors in untouched files, including old migrations; these were
  not suppressed or modified.
- `git diff --check` passed. Browser/manual acceptance was not performed.
- Verification used a dedicated disposable PostgreSQL container on port 55441;
  it was stopped after testing, retaining its test database. Existing deployed
  and development containers were not changed.

## Changed-file manifest

The authorization migration, server enforcement, active-context navigation,
control-plane dashboard/governance, tenant audit projection, and their tests
are implemented in these files. Legacy user redirects and frozen V1 snapshots
are retained unchanged.

- `app/core/permissions.py`
- `app/core/security.py`
- `app/routers/native_auth.py`
- `app/routers/platform.py`
- `app/routers/tenants.py`
- `app/services/auth_context_service.py`
- `app/services/authorization_catalog_service.py`
- `app/services/native_enrollment_service.py`
- `app/services/tenant_service.py`
- `frontend/src/app/settings/page.tsx`
- `frontend/src/app/settings/platform/page.test.tsx`
- `frontend/src/app/settings/platform/page.tsx`
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.test.tsx`
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx`
- `frontend/src/app/settings/platform/tenants/page.test.tsx`
- `frontend/src/app/settings/platform/tenants/page.tsx`
- `frontend/src/app/settings/users/page.test.tsx`
- `frontend/src/app/settings/users/page.tsx`
- `frontend/src/app/vex-investigation/page.tsx`
- `frontend/src/components/admin/IamOperations.tsx`
- `frontend/src/components/admin/TenantAuditHistory.tsx`
- `frontend/src/components/admin/UserSearchCombobox.tsx`
- `frontend/src/components/auth/AuthGuard.tsx`
- `frontend/src/components/auth/__tests__/AuthGuard.test.tsx`
- `frontend/src/components/layout/CommandPalette.tsx`
- `frontend/src/components/layout/KeyboardCheatsheet.tsx`
- `frontend/src/components/layout/Sidebar.test.tsx`
- `frontend/src/components/layout/Sidebar.tsx`
- `frontend/src/components/layout/TenantSwitcher.test.tsx`
- `frontend/src/components/layout/TenantSwitcher.tsx`
- `frontend/src/hooks/useAuth.test.tsx`
- `frontend/src/hooks/useAuth.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/lib/navigation.ts`
- `scripts/compare_authorization_catalog.py`
- `tests/conftest.py`
- `tests/test_native_tenant_provisioning.py`
- `tests/test_phase6_platform_status.py`
- `tests/test_phase6_platform_users.py`
- `tests/test_phase8_authorization_catalog_seed.py`
- `tests/test_platform_admin_default_context.py`
- `tests/test_platform_directory_regression.py`
- `alembic/versions/064_platform_tenant_segregation_v2.py`
- `app/authorization_catalog_seed_v2.py`
- `app/services/tenant_audit_service.py`
- `docs/platform-tenant-v2.md`
- `frontend/src/app/platform/page.test.tsx`
- `frontend/src/app/platform/page.tsx`
- `frontend/src/app/settings/users/audit/page.test.tsx`
- `frontend/src/app/settings/users/audit/page.tsx`
- `frontend/src/components/admin/TenantAuditHistory.test.tsx`
- `frontend/src/components/layout/ControlPlaneNavigation.test.tsx`
- `tests/test_platform_tenant_v2.py`
