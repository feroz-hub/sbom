"""Add restricted Tenant Administrator governance permission.

Revision ID: 103_tenant_admin_governance
Revises: 102_public_membership_grant_analysis_uuid
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "103_tenant_admin_governance"
down_revision = "102_public_membership_grant_analysis_uuid"
branch_labels = None
depends_on = None

# Frozen for deterministic replay; do not import the live catalogue.
PERMISSION = "platform:tenant_admin:manage"


def _seed(bind):
    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    role_id = bind.execute(
        sa.select(roles.c.id).where(
            roles.c.code == "PLATFORM_ADMIN",
            roles.c.scope == "PLATFORM",
        )
    ).scalar_one()
    now = datetime.now(UTC)
    permission_id = bind.scalar(sa.select(permissions.c.id).where(permissions.c.code == PERMISSION))
    if permission_id is None:
        permission_id = bind.execute(
            permissions.insert()
            .values(
                code=PERMISSION,
                name="Manage Tenant Administrators",
                scope="PLATFORM",
                resource="platform:tenant_admin",
                action="manage",
                status="ACTIVE",
                is_system=True,
                created_at=now,
                updated_at=now,
            )
            .returning(permissions.c.id)
        ).scalar_one()
    else:
        # Refuse a pre-existing incompatible definition rather than broadening it.
        scope = bind.scalar(sa.select(permissions.c.scope).where(permissions.c.id == permission_id))
        if scope != "PLATFORM":
            raise RuntimeError("Tenant admin governance permission must be platform scoped")
    unexpected = bind.scalar(
        sa.select(mappings.c.id).where(
            mappings.c.permission_id == permission_id,
            mappings.c.role_id != role_id,
        )
    )
    if unexpected is not None:
        raise RuntimeError("Tenant admin governance permission has an unexpected role mapping")
    mapping_id = bind.scalar(
        sa.select(mappings.c.id).where(
            mappings.c.role_id == role_id,
            mappings.c.permission_id == permission_id,
        )
    )
    if mapping_id is None:
        bind.execute(
            mappings.insert().values(
                role_id=role_id,
                permission_id=permission_id,
                is_protected=True,
                created_at=now,
                updated_at=now,
            )
        )
        bind.execute(
            roles.update()
            .where(roles.c.id == role_id)
            .values(
                version=roles.c.version + 1,
                updated_at=now,
            )
        )
    else:
        bind.execute(mappings.update().where(mappings.c.id == mapping_id).values(is_protected=True))


def upgrade():
    _seed(op.get_bind())


def downgrade():
    raise RuntimeError("Removing protected governance authority requires an operator-reviewed rollback")
