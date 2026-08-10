# Tenant role assignments

Phase 9 stores tenant roles in `tenant_user_role_assignments`. Every active
membership has one or more active assignments and exactly one primary
assignment. All active assignments contribute permissions. The existing
`tenant_users.role` column remains the compatibility primary-role code; it is
not authoritative in `DATABASE` mode.

## Resolver modes

`TENANT_ROLE_ASSIGNMENT_MODE` accepts `LEGACY`, `COMPARE`, or `DATABASE` and
defaults to `DATABASE`. `COMPARE` evaluates both stores, audits differences,
and enforces the legacy result. `DATABASE` evaluates only active assignments,
active TENANT catalogue roles, and active TENANT permissions. Missing or
invalid assignment data returns no tenant permissions when
`TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED=true`.

## Lifecycle and concurrency

Grant, replacement, revocation, reactivation, and primary-role changes require
the membership's `role_assignment_version`. A stale value returns
`IAM_TENANT_ROLE_VERSION_CONFLICT`. Normal revocation retains the assignment
row with `REVOKED` status. Every successful lifecycle change writes append-only
assignment history and an authorization audit event in the same transaction.
The last effective Tenant Administrator and the final role of an active
membership cannot be removed.

The legacy membership PATCH endpoint replaces a single role only when the
membership has at most one active assignment. Callers must send
`replace_all_roles=true` before that endpoint may collapse a multi-role set.
New clients should use the `/api/tenants/{tenant_id}/users/{user_id}/roles`
endpoints.

## Operations

Compare stores without changing data:

```bash
DATABASE_URL=postgresql+psycopg://... \
python scripts/compare_tenant_role_assignments.py \
  --format text --fail-on-mismatch
```

Before downgrade, first run:

```bash
DATABASE_URL=postgresql+psycopg://... \
python scripts/prepare_phase9_downgrade.py --dry-run
```

Downgrade refuses any membership that does not have exactly one active primary
legacy-compatible role. Consolidation is destructive and therefore requires
the explicit operator choice:

```bash
DATABASE_URL=postgresql+psycopg://... \
python scripts/prepare_phase9_downgrade.py --apply --primary-only
alembic downgrade 048_authorization_catalog
```

Review and retain audit/history exports before consolidation. Never run these
commands against an unverified database target.
