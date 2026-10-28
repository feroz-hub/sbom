"""Grant Platform Admin access to versioned Component Advisor defaults.

Revision ID: 075_platform_advisor_policies
Revises: 074_sbom_repair_jobs
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "075_platform_advisor_policies"
down_revision = "074_sbom_repair_jobs"
branch_labels = None
depends_on = None

# Frozen here: later catalogue changes must not change this migration's replay.
PERMISSIONS = ("platform:advisor-policy:read", "platform:advisor-policy:update")


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
    raise RuntimeError("Removing protected platform advisor permissions needs an operator-reviewed rollback")
