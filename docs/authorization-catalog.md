# Authorization catalogue operations

Phase 8 makes PostgreSQL the authoritative source for the global SBOM role and
permission catalogue. Tenant and platform user assignments remain in their
existing tables; assignment redesign is intentionally deferred to Phase 9.

## Resolver modes

- `AUTHORIZATION_CATALOG_MODE=DATABASE` is the secure default. Only active
  database roles, active permissions, and current mappings grant access.
- `COMPARE` returns the frozen legacy decision and writes an authorization
  audit warning when the database result differs. Use only while validating a
  deployment before cutover.
- `LEGACY` is an emergency compatibility mode. It should be time-bounded and
  accompanied by an incident/change record.
- `AUTHORIZATION_CATALOG_FAIL_CLOSED=true` returns no permissions if database
  resolution fails. Turning this off permits a legacy fallback and should only
  be used as a documented emergency measure.

There is no authorization-decision cache. A committed mapping or permission
status change affects the next request on every instance.

## Migration and fresh installation

Revision `048_authorization_catalog` creates and seeds the catalogue in one
transaction, validates existing role assignments, and widens
`alembic_version.version_num` to 128 characters. The frozen seed is
`app/authorization_catalog_seed_v1.py`; do not edit it after deployment.

Historical revision 001 used live SQLAlchemy metadata and is not a stable
fresh-install contract. Bootstrap a new, empty PostgreSQL database with:

```bash
python scripts/bootstrap_fresh_database.py \
  --database-url postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE \
  --confirm-empty-database DATABASE
```

The command refuses non-PostgreSQL databases, mismatched confirmation, and any
target containing public tables. It restores the frozen revision-047 schema,
records that baseline, upgrades through revision 048, and verifies the head.
Secrets belong in a secret manager or process environment; do not put real
credentials in repository files or shell history.

## Protected mappings and scope

The platform-administrator safety floor includes catalogue management and the
existing platform administration capabilities. The tenant-administrator floor
includes tenant user read/invite/update and tenant settings update. Replacement
requests that omit a protected mapping are rejected atomically.

Roles and permissions normally must have the same scope. `PLATFORM_ADMIN` is
the explicit compatibility exception: its legacy mapping includes tenant
permissions for the separately audited platform cross-tenant override.

All five seeded roles are system roles. Their labels, descriptions, and
assignability metadata may be updated with optimistic version checks, but a
system role cannot be disabled. Phase 8 does not expose role creation or role
assignment APIs.

## Platform API

All routes require current database platform authority:

- `GET /api/platform/authorization/roles`
- `GET /api/platform/authorization/roles/{role_id}`
- `GET /api/platform/authorization/permissions`
- `GET /api/platform/authorization/matrix`
- `PATCH /api/platform/authorization/roles/{role_id}`
- `PUT /api/platform/authorization/roles/{role_id}/permissions`

Reads require `platform:authorization:read`; writes require
`platform:authorization:manage`. Mutations include `expected_version` and are
audited in the same transaction as the catalogue change.

## Rollback

Before changing away from `DATABASE`, export the three catalogue tables and
record the current matrix. For emergency application rollback, switch to
`COMPARE`, verify the reported differences, then use `LEGACY` only if required.
An Alembic downgrade removes the three Phase 8 tables but deliberately does not
narrow the Alembic version column. Do not downgrade while application instances
still run in `DATABASE` mode.
