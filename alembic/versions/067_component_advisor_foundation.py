"""Secure Component Advisor foundation: identity indexes and permissions.

FR-SCA-001 / NFR-SCA-005 / NFR-SCA-006: tenant-scoped indexes for grouping
component occurrences by unique version and by component family.
FR-SCA-023: ``component_advisor:*`` tenant permissions (spec section 9).

Additive only. Downgrade drops the indexes and removes the permissions and
their role mappings, which nothing else references yet.

Revision ID: 067_component_advisor_foundation
Revises: 066_platform_config_permissions
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "067_component_advisor_foundation"
down_revision = "066_platform_config_permissions"
branch_labels = None
depends_on = None

INDEXES = (
    ("ix_sbom_component_tenant_canonical", ("tenant_id", "dedupe_canonical_id")),
    ("ix_sbom_component_tenant_package_key", ("tenant_id", "normalized_package_key")),
)

# Frozen here: later catalogue changes must not change this migration's replay.
ROLE_PERMISSIONS = {
    "TENANT_ADMIN": (
        "component_advisor:read",
        "component_advisor:recommendation:create",
        "component_advisor:recommendation:review",
        "component_advisor:recommendation:accept",
        "component_advisor:audit:read",
    ),
    "SECURITY_ANALYST": (
        "component_advisor:read",
        "component_advisor:recommendation:create",
        "component_advisor:recommendation:review",
        "component_advisor:audit:read",
    ),
    "DEVELOPER": (
        "component_advisor:read",
        "component_advisor:recommendation:create",
    ),
    "VIEWER": ("component_advisor:read",),
}


def _index_exists(bind, name):
    return any(index["name"] == name for index in sa.inspect(bind).get_indexes("sbom_component"))


def upgrade():
    bind = op.get_bind()
    for name, columns in INDEXES:
        if not _index_exists(bind, name):
            op.create_index(name, "sbom_component", list(columns))
    _seed(bind)


def _seed(bind):
    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    now = datetime.now(UTC)
    for role_code, codes in ROLE_PERMISSIONS.items():
        role_id = bind.scalar(sa.select(roles.c.id).where(roles.c.code == role_code, roles.c.scope == "TENANT"))
        if role_id is None:
            continue
        for code in codes:
            pid = bind.scalar(sa.select(permissions.c.id).where(permissions.c.code == code))
            if pid is None:
                resource, action = code.rsplit(":", 1)
                pid = bind.execute(
                    permissions.insert()
                    .values(
                        code=code,
                        name=code.replace(":", " ").replace("_", " ").title(),
                        scope="TENANT",
                        resource=resource,
                        action=action,
                        status="ACTIVE",
                        is_system=True,
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(permissions.c.id)
                ).scalar_one()
            if bind.scalar(
                sa.select(mappings.c.id).where(mappings.c.role_id == role_id, mappings.c.permission_id == pid)
            ) is None:
                bind.execute(
                    mappings.insert().values(
                        role_id=role_id, permission_id=pid, is_protected=False, created_at=now, updated_at=now
                    )
                )
        bind.execute(roles.update().where(roles.c.id == role_id).values(version=roles.c.version + 1, updated_at=now))


def downgrade():
    bind = op.get_bind()
    metadata = sa.MetaData()
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    codes = sorted({code for values in ROLE_PERMISSIONS.values() for code in values})
    ids = [pid for (pid,) in bind.execute(sa.select(permissions.c.id).where(permissions.c.code.in_(codes)))]
    if ids:
        bind.execute(mappings.delete().where(mappings.c.permission_id.in_(ids)))
        bind.execute(permissions.delete().where(permissions.c.id.in_(ids)))
    for name, _columns in INDEXES:
        if _index_exists(bind, name):
            op.drop_index(name, table_name="sbom_component")
