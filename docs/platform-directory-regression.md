# Platform Native Users directory regression

## Reproduction before modification

The existing Native Platform Admin (user 1) has an ACTIVE database PLATFORM_ADMIN
grant and no TenantUser membership. Development data also contains Feroze Basha
(ACTIVE Native, tenant 1 TENANT_ADMIN), Test User (tenant 1 VIEWER), and Abdul Hameed
(tenant 2 TENANT_ADMIN). No fake users were inserted into the development database.

The page's initial request is:

```text
GET /api/backend/api/platform/users?page=1&page_size=20&search=&sort_by=name
Content-Type: application/json
Cookie: authenticated opaque session (redacted)
```

The BFF forwards to `/api/platform/users` with the same query and a server-side
Bearer credential. Before this fix the page/shared helper could supply the selected
`X-Tenant-ID`, and the BFF could also derive one from the tenant preference cookie.
In All tenants mode there is no `tenant_id` query parameter.

Direct authenticated reproduction returned HTTP 422, request ID `3faf75803214`,
with `detail[0].type=string_too_short`, `loc=[query,search]`, and
`msg=String should have at least 1 character`. The same query with tenant header 2
also returned 422 (`916f38358cf0`). Removing only `search=` returned HTTP 200 and
four users (`af6b88c3bd70`). This is a client query-construction regression, not a
missing platform grant or an ORM membership inner join.

The tenant-options request (`GET /api/platform/tenants?q=&page=1&page_size=50`)
returned 200 (`18a02b74bb14`). UserLifecycle loads users and details in independent
effects. TenantSearchSelect loads options independently. Roles, provider choices,
and statuses are local supported choices; counts come from the paged user response.
There is no Promise.all collapsing these requests. Detail reads run only after
selection, and this screen does not call the user-search or tenant-role endpoints
for initial directory loading.

## Fix and security

- Omit blank/whitespace search rather than sending an invalid empty query value.
- Keep platform requests free of inherited tenant headers in UserLifecycle,
  the shared API helper, and BFF cookie derivation. Tenant routes retain headers.
- Keep directory errors separate from mutation/detail errors. A failed directory
  hides unknown counts, rows and empty-state claims and offers Retry. Only 403
  is described as a permission denial.
- Preserve independently loaded users when filter metadata fails; retry filters
  independently. All tenants clears the filter rather than serializing a sentinel.
- Display the existing platform-admin flag and zero memberships; map the platform
  role filter to the existing `is_platform_admin` API filter.
- Existing live database platform permission checks, tenant role delegation,
  tenant context and ORM guards are unchanged. IAMUser/TenantUser directory queries
  already support global identities without memberships and bounded pagination.
- Access logging now includes request scope and exception category alongside the
  existing actor, endpoint, status and request ID. No credential values are added.

## Verification

Authenticated BFF request after the fix returned HTTP 200 and all four users,
including Platform Admin with zero memberships (`e62df6fe7909`). An intentionally
stale `X-Tenant-ID: all` was removed by the BFF; tenant metadata returned 200
(`5a1773f4cca8`). The actual page HTML also returned 200. Browser rendering could
not be inspected because the in-app browser does not trust the localhost certificate;
no browser security warning was bypassed.

Focused UI/proxy/header tests cover directory success/failure/empty states,
secondary failures, zero memberships, tenant/provider/platform-role filters,
tenant headers, and invitation controls. PostgreSQL-backed API tests cover global
reads without actor membership, zero/one/multiple memberships, Native/HCL provider
filters, and tenant-admin denial of platform and cross-tenant reads. Existing
Native provisioning tests cover forbidden role assignment and modified tenant IDs.

Production webpack build runs in an isolated frontend copy so the live development
server's .next directory is not overwritten. No schema, deployment configuration,
database grants or membership records were changed for the fix.

The pre-existing logging test `test_early_body_rejection_logged` assumes the final
log record is the access event. In this environment an HTTP client log follows it;
the same failure was reproduced using the committed middleware without file edits.
Its assertion was not modified.

Final results: 50 frontend tests passed; 50 backend tests passed with the known
logging assertion excluded (one deselected). Production webpack build and TypeScript
passed. Ruff and git diff checks passed. Changed-file frontend lint reported no
errors and three warnings (two existing API unused-variable warnings and the
existing selector autofocus suppression).

## Files changed for this fix

- `frontend/src/components/admin/UserLifecycle.tsx` and its test.
- `frontend/src/components/admin/TenantSearchSelect.tsx`.
- `frontend/src/components/admin/NativeUserInviteForm.test.tsx` (open selector before search).
- `frontend/src/lib/api.ts` and `api.tenantHeader.test.ts`.
- `frontend/src/lib/auth/tenantHeader.ts` and its test.
- `frontend/src/app/api/backend/[...path]/route.ts` and its test.
- `app/middleware/request_logging.py`.
- `tests/test_platform_directory_regression.py`, `tests/test_structured_logging.py`.
- This report.

Pre-existing uncommitted edits to the native-users page, NativeUsers.module.css,
selector and directory components/tests were preserved. No commit or push performed.
