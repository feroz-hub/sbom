"""Complete platform configuration grants for already-upgraded V2 databases.

Revision ID: 066_platform_config_permissions
Revises: 065_scoped_configuration
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "066_platform_config_permissions"
down_revision = "065_scoped_configuration"
branch_labels = None
depends_on = None

# Frozen here: later catalogue changes must not change this migration's replay.
PERMISSIONS = (
    "platform:ai:read", "platform:ai:update", "platform:ai:test",
    "platform:lifecycle-provider:read", "platform:lifecycle-provider:update",
    "platform:lifecycle-provider:test", "platform:lifecycle-provider:sync",
)


def upgrade():
    _seed(op.get_bind())


def _seed(bind):
    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    role_id = bind.execute(sa.select(roles.c.id).where(
        roles.c.code == "PLATFORM_ADMIN", roles.c.scope == "PLATFORM",
    )).scalar_one()
    now = datetime.now(UTC)
    for code in PERMISSIONS:
        pid = bind.scalar(sa.select(permissions.c.id).where(permissions.c.code == code))
        if pid is None:
            resource, action = code.rsplit(":", 1)
            pid = bind.execute(permissions.insert().values(
                code=code, name=code.replace(":", " ").title(), scope="PLATFORM",
                resource=resource, action=action, status="ACTIVE", is_system=True,
                created_at=now, updated_at=now,
            ).returning(permissions.c.id)).scalar_one()
        else:
            bind.execute(permissions.update().where(permissions.c.id == pid).values(
                scope="PLATFORM", status="ACTIVE",
            ))
        if bind.scalar(sa.select(mappings.c.id).where(
            mappings.c.role_id == role_id, mappings.c.permission_id == pid,
        )) is None:
            bind.execute(mappings.insert().values(
                role_id=role_id, permission_id=pid, is_protected=True,
                created_at=now, updated_at=now,
            ))
    bind.execute(roles.update().where(roles.c.id == role_id).values(
        version=roles.c.version + 1, updated_at=now,
    ))


def downgrade():
    raise RuntimeError("Removing required V2 platform permissions needs an operator-reviewed rollback")
