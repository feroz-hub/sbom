# Database bootstrap and upgrade

Existing databases upgrade normally:

```bash
alembic upgrade head
```

New empty PostgreSQL databases must use the frozen revision-047 snapshot:

```bash
python scripts/bootstrap_fresh_database.py \
  --database-url postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE \
  --confirm-empty-database DATABASE
```

The command refuses a non-empty or partially initialized target, never drops
objects, creates `alembic_version.version_num` as `VARCHAR(128)`, stamps
revision 047, upgrades through revisions 048 and 049, and verifies the
resulting `049_tenant_multi_role_assignments` head.

Revision 049 validates every legacy membership role against an active,
assignable TENANT catalogue role, then creates one primary assignment and one
`MIGRATED` history row per membership. Unknown legacy role codes abort the
transaction instead of being mapped to a lower-privilege role.

See [TENANT_ROLE_ASSIGNMENTS.md](TENANT_ROLE_ASSIGNMENTS.md) before downgrading;
the downgrade intentionally refuses to discard multiple active roles.

Do not use historical revision 001 as a fresh-install path: it creates tables
from live runtime metadata and therefore is not a frozen historical schema.
Do not place real database credentials in checked-in configuration.
