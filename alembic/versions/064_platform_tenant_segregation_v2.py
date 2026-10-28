"""Install the V2 Platform Admin control-plane catalogue atomically.

Revision ID: 064_platform_tenant_v2
Revises: 063_microsoft_entra_identity
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from app.authorization_catalog_seed_v2 import PLATFORM_ADMIN_PERMISSIONS_V2

revision = "064_platform_tenant_v2"
down_revision = "063_microsoft_entra_identity"
branch_labels = None
depends_on = None


def upgrade():
    _seed(op.get_bind())


def _seed(bind):
    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    role_id = bind.execute(
        sa.select(roles.c.id).where(roles.c.code == "PLATFORM_ADMIN", roles.c.scope == "PLATFORM")
    ).scalar_one()
    now = datetime.now(UTC)
    permission_ids = dict(bind.execute(sa.select(permissions.c.code, permissions.c.id)).all())
    for code in sorted(PLATFORM_ADMIN_PERMISSIONS_V2):
        if code not in permission_ids:
            resource, action = code.rsplit(":", 1)
            permission_ids[code] = bind.execute(
                permissions.insert()
                .values(
                    code=code,
                    name=code.replace(":", " ").title(),
                    scope="PLATFORM",
                    resource=resource,
                    action=action,
                    status="ACTIVE",
                    is_system=True,
                    created_at=now,
                    updated_at=now,
                )
                .returning(permissions.c.id)
            ).scalar_one()
        else:
            bind.execute(
                permissions.update()
                .where(permissions.c.id == permission_ids[code])
                .values(scope="PLATFORM", status="ACTIVE")
            )
    # Replace only PLATFORM_ADMIN; never re-seed customer tenant roles.
    bind.execute(mappings.delete().where(mappings.c.role_id == role_id))
    for code in sorted(PLATFORM_ADMIN_PERMISSIONS_V2):
        bind.execute(
            mappings.insert().values(
                role_id=role_id, permission_id=permission_ids[code], is_protected=True, created_at=now, updated_at=now
            )
        )
    bind.execute(roles.update().where(roles.c.id == role_id).values(version=roles.c.version + 1, updated_at=now))


def downgrade():
    # Restoring V1 implicitly restores customer-data superuser privileges.
    # Deliberately require an operator-reviewed recovery instead of silently
    # weakening authorization during an application rollback.
    raise RuntimeError("V2 privilege segregation cannot be downgraded automatically; see docs/platform-tenant-v2.md")
