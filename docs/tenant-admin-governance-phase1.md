# Tenant Administrator Governance — Phase 1 implementation report

Review date: 24 October 2026. Implementation checkout: `/Users/ferozebasha/sbom`, branch
`feat/native-user-management`. The supplied `/home/hcluser1/sbom_native/sbom` path is
not present on this host. Changes were local and uncommitted at the end of the
implementation run. The final review and commit preparation are recorded below.

## 1. Executive summary

Restricted platform governance now supports revoking `TENANT_ADMIN`, disabling an
administrator membership, and removing that membership. Tenant-context callers
cannot remove administrator authority through roles, compatibility PATCH, or
membership lifecycle APIs. Ordinary user administration remains available.

The implementation uses existing identities, memberships, role assignments,
history, audit, database authorization, and tenant locking. No frontend code,
new tables, application service restarts, deployment, or deployed database
migrations are part of this change.

## 2. Root cause addressed

Role delegation already restricted Tenant Administrators from revoking or
replacing `TENANT_ADMIN`. Lifecycle endpoints checked only whether another
effective administrator remained. Consequently, deactivation/deletion could
remove authority that direct role APIs protected. Platform recovery could grant
administrator authority, but there was no matching restricted removal workflow.

## 3. Files modified

| Area | Files |
| --- | --- |
| Governance service | `app/services/tenant_admin_governance_service.py` (new) |
| Platform contract and handlers | `app/routers/platform.py`, `app/schemas_platform.py` |
| Tenant lifecycle and restrictions | `app/routers/tenants.py`, `app/services/tenant_service.py` |
| Role mutations and resolution | `app/services/tenant_role_assignment_service.py` |
| Permission catalogue and policies | `app/authorization_catalog_seed_v6.py` (new), `app/core/permissions.py`, `app/core/route_policies.py`, `app/services/authorization_catalog_service.py` |
| UUID boundary and schemas | `app/public_api.py`, `app/resource_public_api.py`, `app/iam_public_api.py` |
| Migration | `alembic/versions/103_tenant_admin_governance.py` (new) |
| Operator catalogue comparison | `scripts/compare_authorization_catalog.py` |
| Tests | `tests/test_tenant_admin_governance.py` (new), `tests/conftest.py`, `tests/test_identity_administration.py`, `tests/test_phase8_authorization_catalog_seed.py`, `tests/test_platform_tenant_v2.py` |
| Report and contract documentation | `docs/tenant-admin-governance-phase1.md` (new) |

## 4. New and updated API endpoints

Public tenant and membership selectors are UUIDv4 strings; integer keys remain
internal to persistence. FastAPI/Pydantic schemas and generated OpenAPI are the
contract source. Existing saved OpenAPI files under UAT evidence are historical
snapshots and were not overwritten.

| Method and route | Request | Success |
| --- | --- | --- |
| `POST /api/platform/tenants/{tenant_id}/administrators/{membership_id}/revoke` | Required JSON `expected_version` >= 1; optional `replacement_primary_role_code`, `reason` | 200 governance membership state |
| `POST /api/platform/tenants/{tenant_id}/administrators/{membership_id}/deactivate` | Optional JSON with optional `reason` | 200 governance membership state |
| `DELETE /api/platform/tenants/{tenant_id}/administrators/{membership_id}` | Optional query `reason` | 204, empty body |
| `GET /api/platform/tenants/{tenant_id}` (existing) | Unchanged | Current administrator entries also include `membership_id`, `role_assignment_version`, `primary_role`, `roles` |

Successful POST responses contain `tenant_id`, `membership_id`, `user_id`,
`status`, `roles`, `primary_role`, and `role_assignment_version`. The three identity
fields are UUIDs on the wire. Roles describe active catalogue assignments;
disabled membership status still prevents authorization through those roles.

Revoke example:

```json
{
  "expected_version": 3,
  "replacement_primary_role_code": "SECURITY_ANALYST",
  "reason": "Approved administrator reassignment"
}
```

When the administrator assignment is primary, explicitly select a valid ordinary
replacement, including when it is the only assignment. No implicit VIEWER grant
is made. Existing ordinary assignments are retained, and an approved replacement
can be granted or reactivated in the same transaction. Nonprimary administrator
revocation can omit the replacement and retain the existing primary assignment.
Unknown request fields on governance POST payloads are rejected.

Errors follow existing FastAPI `detail` envelopes: 401 for absent/invalid
authentication; 403 for missing governance authority or forbidden replacement;
404 for missing tenant/membership or cross-tenant mismatch; 409 for stale versions,
last-effective-admin protection, missing necessary replacement, or a nonadmin
target; 422 for invalid payloads and invalid/disabled/nonassignable replacement
catalogue roles. Structured role conflicts include `detail.code`,
`detail.message`, and `detail.current_version` when relevant.

## 5. Authorization and permission changes

New permission: `platform:tenant_admin:manage`. Existing bootstrap/recovery/status
permissions do not accurately express removal of administrator authority, so they
were not broadened. Frozen V6 catalogue constants register the new permission and
assign/protect it only on `PLATFORM_ADMIN`. Catalogue mutation rejects its
assignment to another role. Historical V1–V5 seeds remain frozen.

Each new route has an explicit authorization policy and platform permission
dependency. The service requires a platform context without an active tenant,
rechecks the actor's active database platform grant/account/verification, and
resolves the permission catalogue inside its transaction. Actor identity comes
from authentication, never payload fields.

The UUID boundary permits only these three governance routes to resolve a
membership in the already-selected tenant. Internal tenant scope is bounded to
authorization metadata. No tenant membership, operational permission,
`platform:user:*` permission, or customer business-data access is granted.

## 6. Tenant Admin protection changes

Deactivation, deletion, and compatibility PATCH check all active assignments
against active tenant catalogue roles. A secondary `TENANT_ADMIN` assignment is
protected even when the legacy primary field contains another role. Preserved
administrator assignments on disabled memberships are also protected from tenant
deletion. Configured legacy/compare modes retain their legacy-role safeguard.

The restriction applies to all tenant-context callers, including custom roles
with `tenant:user:update`, and protects peers and self equally. Role grant,
replacement, and revoke routes always use tenant delegation rules. Ordinary
membership edits, role changes, activation/deactivation, and deletion remain
available under existing permissions. Compatibility role/status changes now use
one caller-owned transaction.

## 7. Database and migration changes

Revision `103_tenant_admin_governance`, following
`102_public_membership_grant_analysis_uuid`, inserts the permission and its
protected Platform Admin mapping. It creates no tables or columns and preserves
existing grants, assignments, and other mappings. Repeating its seed does not
duplicate rows or repeatedly increment the role version. An incompatible existing
permission scope or unexpected role mapping causes a safe failure for review.

As with prior protected platform migrations, automatic downgrade is refused;
rollback requires operator review. In DATABASE/COMPARE catalogue modes, platform
resolution intentionally fails closed if the complete required platform
permission set is absent. LEGACY mode retains the existing static fallback;
staging/production configuration requires DATABASE authorization modes.

Migrations were exercised only against an isolated temporary PostgreSQL test
database. No deployed database was migrated.

## 8. Audit logging behavior

Success events are `TENANT_ADMIN_REVOKED`, `TENANT_ADMIN_DEACTIVATED`, and
`TENANT_ADMIN_REMOVED`. Each records authenticated actor, tenant, target user,
membership identity, previous/resulting state, reason, correlation identifier
where supplied, and timestamp in `AuthorizationAuditLog`.

Role revocation/replacement grant/primary selection append existing assignment
history with one membership role-set version increment. Deactivation preserves
assignments and role-set version. Removal retains the existing hard-delete
behavior. History rows survive through existing SET NULL foreign keys; the
governance audit retains the deleted membership's integer key/public UUID,
assignment snapshots, and exact surviving history IDs. It does not reference the
deleted membership through a live FK.

Mutation and successful governance audit commit together. Audit failure rolls
back the mutation. Domain denials are recorded after mutation rollback, while
platform permission denials use existing authorization audit handling. No bearer
tokens, cookies, passwords, or credential material are added to these records.

## 9. Automated tests added

`tests/test_tenant_admin_governance.py` exercises signed native JWT validation,
native login, current database platform grants, permission resolution, tenant
selection, UUID decoding, real endpoint handlers, PostgreSQL row locks, and
durable audit/history. It does not override authentication/context dependencies
or inject permissions into synthetic `CurrentContext` objects.

Coverage includes platform success; all ordinary roles/unauthenticated callers
denied; peer/self secondary-admin protection on all relevant routes; ordinary
user management; custom roles and replacement catalogue validation; explicit
single-role replacement; role reactivation; primary reassignment in either PK
order; stale versions; exact tenant/membership matching; other memberships,
identity, and platform grant preservation; ineffective backups; last-admin
protection; mixed concurrent governance mutations; audit rollback; deletion
history retention; OpenAPI UUIDs; and catalogue protection/idempotence.

Existing expectations are updated for the intentional change from last-admin
409 to governance-authority 403 on tenant-context administrator lifecycle calls.

## 10. Test execution results

| Run | Passed | Failed | Skipped | Scope |
| --- | ---: | ---: | ---: | --- |
| Pre-change baseline | 52 | 0 | 0 | Role API/security/concurrency, platform/tenant separation, platform status |
| Final focused suite | 128 | 0 | 0 | 76 new governance cases plus all 52 baseline cases |
| Broader regression | 686 | 0 | 0 | 56 identity, provider, tenant, catalogue, migration, UUID and platform test files |

The focused suite finished in 95.27 seconds; broader regressions finished in
425.32 seconds. These run totals overlap and should not be summed as unique
tests. Ruff lint on changed application/test/operator Python files, Python
compilation of changed core files and the migration, and `git diff --check` passed. Alembic
reports exactly one head: `103_tenant_admin_governance`. The frontend diff is
empty. Existing Pydantic configuration and Alembic `path_separator` deprecation
warnings remain; the Entra invalid-algorithm test also emits a test-key-length
warning. Final focused/regression commands both exited 0. No existing baseline
failures were observed in the selected suites; unrelated full-suite baseline
status was not assessed.

The initial default test attempt could not connect to its configured PostgreSQL
service. A temporary PostgreSQL 18 instance on loopback port 55449 was created
for this task. Test setup/migrations and all test writes target only
`sbom_governance_test` on that instance. An initial fresh bootstrap attempt with
a passwordless test connection was rejected by the existing local database URL
validation; the corrected test configuration then completed the baseline.

Intermediate implementation failures were corrected before the final focused
run: scope lifetime at transaction commit, stale snapshots with autoflush
disabled, and test fixture lifetime/response-envelope assumptions. They are not
reported as existing baseline failures. No failures remain in the final focused
run. The complete unrelated repository test suite was not run.

Focused command, with `TEST_DATABASE_URL` and `TEST_POSTGRES_DATABASE_URL` both
set to the task's disposable database target:

```sh
.venv/bin/python -m pytest -q --tb=short \
  tests/test_tenant_admin_governance.py \
  tests/test_phase9_role_assignment_api.py \
  tests/test_phase9_role_assignment_security.py \
  tests/test_phase9_role_assignment_concurrency.py \
  tests/test_platform_tenant_v2.py \
  tests/test_phase6_platform_status.py
```

## 11. Security considerations

All conflicting administrator reductions lock the tenant row before target
account/membership/assignment mutation. This serializes last-admin decisions with
existing role and account-status administration. Effective-admin counts retain
active membership, active user, verification eligibility, active assignment, and
active tenant catalogue role checks. Optimistic role version checks prevent
silent concurrent role-set overwrites.

Global IAM accounts, credentials/security versions, unrelated platform grants,
and memberships in other tenants are not changed. Customer SBOMs,
vulnerabilities, products, and projects remain behind existing tenant permission
and isolation checks.

## 12. Remaining limitations

Already-running requests may have resolved authority before the mutation. Open
browser sessions and cached frontend permissions are not forcibly refreshed.
Identity tokens are not regenerated or globally terminated by these operations;
new HTTP authorization requests use current database state. Background workers
that already carry a trusted internal tenant context do not gain a new session
cancellation mechanism in this phase. Provider-specific live deployments and
real browsers require deployment acceptance verification.

The existing tenant detail list shows current effective administrators. Discovery
of disabled administrator memberships for a later cleanup UI is not expanded in
this phase; the governance endpoints can act on a known exact disabled membership
with a preserved administrator assignment.

## 13. Phase 2 frontend integration requirements

Use platform tenant metadata to select the membership UUID and role-set version.
Expose these actions only under the governance permission. Require an explicit
ordinary replacement when necessary; send the loaded version and handle 409 by
reloading administrator state. Offer an administrative reason and clear
membership-specific deactivate/remove confirmations. DELETE returns no body.

Invalidate platform tenant detail/administrator metadata and refresh the affected
user's tenant authorization presentation after success. Handle the distinction
between global identity, platform grant, tenant membership status, and roles.
Design any disabled-administrator discovery UI with a narrowly scoped backend
metadata contract. No Phase 2 implementation is included here.

## 14. Deployment considerations

Review and release code and revision 103 together. Operators must apply the
migration through the normal controlled deployment process before expecting the
new runtime catalogue to authorize Platform Admin requests. Verify one Alembic
head, the protected mapping, existing ordinary role mappings, real authentication
provider flows, success/denial audit retention, tenant data denial, and concurrent
last-admin enforcement in the deployment environment.

No deployment, service restart, production-data modification, or migration of a
deployed database was performed by this task. The temporary test server is owned
by this task and is shut down after testing.

## 15. Final implementation status

**Phase 1 implemented and tested locally:** 128 focused tests and 686 broader
regressions passed, with no final failures or skips. All required Phase 1 backend
acceptance criteria are covered. The changes are ready for implementation review;
deployment acceptance remains outstanding.

| Acceptance criterion | Evidence |
| --- | --- |
| Platform Admin revoke/deactivate/remove | Signed native bearer endpoint success tests for all three operations |
| Tenant Admin cannot revoke/remove administrator roles | Direct revoke and complete replacement peer/self tests |
| Tenant Admin cannot deactivate/remove peer or self administrator memberships | Secondary-role peer/self tests for DELETE, deactivate, status PATCH and combined PATCH |
| Last effective admin protection | Last-admin, ineffective-backup, same-version and mixed concurrent mutation tests |
| Tenant isolation | Exact tenant/member selector tests; platform customer-data denial |
| Global accounts, other memberships and platform grants preserved | Cross-tenant identity/grant preservation tests with the same JWT after mutation |
| History and audit retained | Role history/primary/replacement tests, durable removal snapshots/history links, audit failure rollback |
| Real authentication/authorization integration | Signed RS256 native JWTs, native login and real database grant/permission resolver; no context/auth overrides |
| Ordinary user management preserved | Real-auth ordinary role/status/activation/removal test plus existing regressions |
| No unnecessary schema changes | Permission/mapping-only migration; existing models/tables reused |
| No frontend changes | Empty frontend Git diff |

**Implemented but not tested:** no planned Phase 1 feature is deliberately left
without automated local coverage; this does not claim exhaustive branch or live
environment testing.

**Not implemented:** Phase 2 frontend integration, browser refresh behavior, and
new background-worker/session cancellation behavior.

**Requires deployment verification:** controlled revision-103 upgrade, deployed
provider configuration, real browser behavior, multi-instance acceptance and
operator audit retrieval. No deployment or production migration has been run.

## 16. Final source review and local commit preparation

Review performed on 24 October 2026 for SBO-81 and SBO-82, on
`feat/native-user-management`, starting at
`cc98ee5f90be7c56109aba0838ab535808f3efc2`. The initial working tree contained
exactly the 21 Phase 1 files in the inventory above (16 tracked modifications and
five new files), with nothing staged and no unrelated files identified.

The final source/security review found no reportable security findings in the
patch. All 15 changed production/operator/migration source files were reviewed,
along with the six changed test/report files and the necessary existing
authentication, isolation, membership, history and audit controls. A separate
fresh-context agent performed the bounded architecture review; this is not
independent human or organizational security approval. No application source
corrections were required. The mode-dependent catalogue statement above was
clarified as a documentation-only consistency correction.

Codex Security scan ID: `16f27473-be0e-4876-b269-cd6089996e4b` (complete, zero
findings; scoped static diff review). Its retained report and SARIF remain in the
local Codex Security artifact store, outside the Git commit. The scan tool
reports cumulative rollout usage of 6,957,764 tokens, including 6,718,208 cached
input tokens across three threads; these counters are not isolated review-only
usage or a billing estimate.

Fresh review validation:

| Check | Actual result during final review |
| --- | --- |
| Python compilation | Passed all 20 changed Python files using `compile()` without writing cache artifacts |
| Ruff | Passed all 19 changed application/test/operator Python files |
| Alembic heads | One head: `103_tenant_admin_governance` (no database migration executed) |
| Git whitespace | `git -c core.fsmonitor=false diff --check` passed |
| Existing staged changes | None before explicit Phase 1 staging |
| Sensitive/generated files | No private keys/token literals/environment files/logs/dumps or frontend changes in the reviewed scope; the test passphrase is an intentional synthetic fixture |
| Focused database test rerun | Not run: `pg_isready` reported no response on both loopback test ports 55449 and 55439 |
| Previous test evidence | Existing local logs match 128 passing focused and 686 passing regression tests; these are prior implementation results, not new final-review test executions |

No services or databases were started or modified during this final review.
Git file-monitor daemon errors were avoided with per-command
`-c core.fsmonitor=false`; repository/user configuration was not changed.

The reviewed files are prepared for one local commit with the requested
`feat(iam): implement restricted tenant admin governance` message and
`Refs: SBO-81, SBO-82`. The exact commit identity is recorded in Git and the final
delivery report after commit creation. No push, merge, deployment, production
migration, or production verification is authorized or claimed. Fresh database
test reruns, independent human review, Phase 2 integration (SBO-83), and deployed
end-to-end acceptance (SBO-84) remain follow-up work.
