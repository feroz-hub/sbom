# Platform Dashboard catalogue repair

## Confirmed runtime cause

The development database was stamped `065_scoped_configuration` but contained
only the original 12 PLATFORM_ADMIN mappings. The application expected all 19
approved V2 platform permissions. Its fail-closed completeness check therefore
returned no platform permissions. This caused the empty sidebar and dashboard
denial, although `platform:tenant:read` itself was still mapped in the database.

The seven AI/lifecycle platform grants had been added to the catalogue used by
064 after the development database had already applied that migration. Migration
065 grants tenant configuration permissions and does not remove platform read;
it did not repair the previously applied platform catalogue either.

## Repair

- Forward migration 066 adds the seven platform configuration grants without
  changing tenant mappings, memberships, or tenant permissions. Its permission
  list is frozen in the migration and its grant operations are idempotent.
- `/platform` checks both the live platform identity flag and
  `platform:tenant:read`, not `tenant:user:read` or an active tenant.
- The platform branch of `useAuth` takes permissions from
  `auth_context.platform.permissions`; selected tenant branches retain only
  tenant effective permissions. Sidebar and control-plane navigation already
  use `hasPermission` and require no additional tenant-dependent guard changes.
- Denial wording is now “Platform Administrator access is required.”
- Existing AuthGuard requires no tenant selection for a READY platform session.

Applied 066 to the development database only. Read-only runtime verification
then returned platform user 1: `is_platform_admin=true`, zero memberships, no
active tenant, 19 platform permissions, `platform:tenant:read` present and
`tenant:user:read` absent. Deployed containers/data were not modified.

## Verification

- Focused backend V2/default-context tests: 45 passed.
- Final strengthened dual-role context test: 1 passed.
- Focused dashboard/auth/sidebar/control-plane/AuthGuard tests: 57 passed.
- TypeScript `tsc --noEmit`: passed.
- Changed frontend ESLint, Python Ruff and `git diff --check`: passed.
- Production build: passed with `NEXT_PUBLIC_API_URL=https://localhost:18000`.
  Initial build without that required setting failed explicitly; no configuration
  validation was bypassed.
- Regression tests cover pure platform `/api/auth/me`, `/api/auth/context`,
  summary access, incomplete-catalogue repair, no tenant permissions, restricted
  tenant operations, independent dual-role contexts, and platform navigation.

No commit or push. Refresh the development browser or sign in again to reload
the repaired authorization context. Browser UI was not manually exercised.

Files changed for this repair: migration 066; `frontend/src/app/platform/page.tsx`
and its new test; `frontend/src/hooks/useAuth.tsx` and its test;
`tests/test_platform_tenant_v2.py`; this report. All preceding uncommitted V2
and scoped-configuration work is preserved.
