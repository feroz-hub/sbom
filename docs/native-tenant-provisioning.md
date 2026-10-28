# Native tenant and user provisioning

## Audit and implementation decisions

The pre-change implementation already separated global `IAMUser` records,
`PlatformUserRole` platform grants, unique `TenantUser` memberships, and
database-backed multiple `TenantUserRoleAssignment` roles. Authorization resolves
the principal, account status, membership, roles, and catalogue on every request.
The existing activation service provides single-use hashed tokens, Argon2id password
hashing, versioned sessions, and an encrypted transactional security mail outbox.
The platform creation service already atomically created a tenant and an existing
eligible user's administrator membership; it never automatically added the actor.

The circular dependency was the absence of an invitation option in that transaction.
Native invitations rejected an existing Native identifier, and the invitation and
global user screens exposed numeric tenant inputs. The shared role editor also
ignored its `assignableRoles` property.

| Stories | Existing behavior reused | Change |
| --- | --- | --- |
| US-01–03 | Atomic creation, generated IDs, eligible-user search, catalogue role assignment | Accept either an existing administrator or an invitation; new profile, membership, role, token and outbox are atomic |
| US-04–07 | Separate platform routes/grants and backend role delegation checks | Searchable tenant selector; current-tenant read-only field; shared role editor honors assignable roles |
| US-08–09 | Escaped case-insensitive user queries | First/last-name search, bounded pagination, tenant name/slug search, individual platform tenant resource |
| US-10–12 | Native identifier uniqueness, membership uniqueness, multiple roles | Reuse only `UserIdentity(provider_type=NATIVE)`; duplicate membership returns names/current roles and management action |
| US-13 | Existing `PENDING`, `ACTIVE`, `DISABLED` tenant statuses | Pending initial activation, guarded activation, explicit pending UI |
| US-14 | Tenant-row locking and last-effective-admin guards for role, membership and account mutations | Reuse; existing PostgreSQL concurrency tests retained |
| US-15–16 | Request-time live DB context, scoped routes, permission navigation | Retain; direct modified-request regression tests and role-aware invitation UI |

## Contracts and lifecycle

`POST /api/tenants` keeps `name`, `slug`, optional external mapping and
`initial_admin_user_id`. Alternatively it accepts `initial_admin_invitation` with
`first_name`, `last_name`, `email`, and optional `phone`. The two administrator
options are mutually exclusive. Initial role is always `TENANT_ADMIN`; the client
cannot override it. The existing-user option requires an active, verified user.

No schema change or migration is needed. For this flow, `PENDING` means awaiting an
effective administrator. The membership and role are recorded as `ACTIVE`, but
neither the pending global account nor a pending tenant can authorize requests.
Setting the initial administrator's password performs the existing activation
transition and promotes their pending tenants only when the live administrator
count is nonzero. A deliberately `DISABLED` tenant is never automatically enabled.
Platform activation also requires an effective administrator. `DISABLED` remains
the existing representation of an inactive tenant.

The tenant creation transaction includes user, membership, role, action-token,
encrypted outbox and structured audit writes. Delivery uses the existing
`security_mail.dispatch` Celery task and EmailSender. No SMTP is sent inside the
transaction. Initial-admin invitations require the security outbox to be enabled.
Failure rolls back all provisioning state; safe failure audits are separate.

Ordinary Native invitations reuse a matching Native provider identifier. Active
users receive a new membership without password activation; pending Native users
receive a replacement activation token through the existing issuer/outbox logic.
Their existing profile and other memberships are unchanged. HCL profile emails
never select or link a Native identity. Concurrent Native creation is arbitrated
by the existing unique index and returns a retryable conflict.

The Platform Admin chooses a tenant by name/slug and may assign tenant roles,
including `TENANT_ADMIN`. The Tenant Admin uses the authenticated selected tenant
and may delegate Analyst, Developer or Viewer. Request dependencies resolve live
database authority; the enrollment service checks tenant/context equality and role
delegation. Changing a URL, body ID, or JWT role claim does not change that authority.
Platform grants remain a separate workflow. No actor membership is synthesized.

Search lists are bounded: user search defaults to 20 (maximum 50), tenant search
defaults to 50 (maximum 100), with `page`/`page_size`. Global searches require platform
permission; tenant user searches remain membership-scoped. The platform tenant
detail resource avoids depending on the first page of a tenant list.

`POST /api/platform/tenants/{tenant_id}/native-users/{user_id}/resend-activation`
shares the existing resend handler and adds an explicit platform permission gate.
It lets an operator resend an initial administrator's activation in platform
context before that pending tenant can be selected for tenant access.

## Last administrator protection

The existing mutation services serialize on the tenant row, lock candidate
memberships, and count active verified users with active catalogue-backed
`TENANT_ADMIN` assignments. Removing roles/memberships or disabling the final
effective administrator is rejected. Global administrative account transitions
lock affected tenants in stable order and reuse the same guard. Security lockout
retains its existing behavior; authentication abuse protection is not bypassed.

## Verification

Focused PostgreSQL provisioning tests cover atomic rollback, outbox creation,
activation, disabled-tenant preservation, existing Native identity reuse, HCL
separation, duplicate membership, search, live revocation and modified API requests.
Existing Native foundation, activation, password/session, authorization, and
last-admin concurrency tests are included in the regression run. Frontend tests
cover both creation choices, human-readable tenant selection, locked tenant context,
role restrictions, duplicate feedback and shared administration screens.

An older `test_last_active_tenant_admin_is_protected` expects HTTP 409 for a Tenant
Admin's role-removal attempt; the existing delegation guard returns HTTP 403.
This same failure was reproduced on committed baseline `1e59a71` in a detached
worktree. The operation remains denied. The unrelated expectation is unchanged.

Operational acceptance uses isolated test PostgreSQL databases and separate
Mailpit/Redis instances. It verifies Native Platform Admin login, Olympus creation,
Celery/outbox email arrival, initial-admin activation/login, Viewer invitation and
activation, Viewer administrative denial, modified cross-tenant rejection, and
Native user reuse in MedTech with independent roles. No deployed processes or
containers are reused or changed for the acceptance application.

Browser inspection also submitted the new-admin tenant creation form, verified the
pending-administrator detail screen, signed in as the Tenant Admin and confirmed
the disabled Olympus tenant field and three permitted roles, and signed in as the
Viewer to confirm hidden administration navigation and direct-route denial. That
inspection caught and fixed a remaining unauthorized invitation disclosure heading.
Password activation was exercised through the real HTTP API, not the browser form.
The isolated API harness exposes IAM routes only, so unrelated dashboard/health
requests show unavailable; those features were outside this acceptance check.

Final verification results:

- Broad backend regression: 294 passed, one pre-existing assertion failure described above.
- Final targeted backend regression: 74 passed; subsequent provisioning/resend suite: 15 passed.
- Frontend: 120 passed across 16 files.
- Ruff on changed Python files and `git diff --check`: passed.
- Frontend TypeScript: passed. Full frontend lint: zero errors, 54 existing warnings.

Temporary acceptance API, worker, frontend, Redis and Mailpit were stopped after
verification. The isolated test databases and stopped acceptance containers remain
available for inspection; no database was dropped. The temporary baseline Git
worktree was removed. No commit or push was performed.

## Changed-file inventory

- Backend routers: `app/routers/{native_auth,platform,tenants}.py`.
- Backend schemas: `app/schemas_tenants.py`, `app/schemas_native_enrollment.py`.
- Backend services: `app/services/{native_auth_service,native_enrollment_service,platform_service,tenant_service}.py`.
- Frontend pages: `settings/native-users`, `settings/platform/tenants`, its `[tenantId]`
  detail page, and `settings/tenant` under `frontend/src/app`.
- Frontend components: `ManageRolesModal`, `NativeUserInviteForm`, `StatusBadges`,
  `TenantSearchSelect`, `UserLifecycle`, and `layout/TenantSwitcher`.
- Frontend utilities: `frontend/src/lib/{api,tenantForm}.ts`.
- Backend tests: `tests/test_native_tenant_provisioning.py`.
- Frontend tests: native-users page, platform tenant creation/detail pages,
  `NativeUserInviteForm.test.tsx`, `UserLifecycle.test.tsx`, and
  `admin/__tests__/ManageRolesModal.test.tsx`.
- This implementation/verification document. No migrations or deployment files changed.
