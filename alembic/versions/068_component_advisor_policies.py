"""Secure Component Advisor policies and purpose metadata.

FR-SCA-004/005/017: ``advisor_policy`` slots (platform default = NULL tenant,
tenant override) with append-only ``advisor_policy_version`` rows.
FR-SCA-009: ``component_purpose_metadata`` and ``sbom_component.description``.
FR-SCA-023: ``tenant:advisor-policy:read/update`` permissions.

Additive. ``sbom_component.description`` starts empty for existing rows; the
backfill is ``scripts/backfill_component_descriptions.py``, which re-reads each
SBOM's stored document. It runs outside the migration so a large estate does
not hold a migration transaction open. Downgrade drops the new tables, the
column and the permissions; policy history is lost, so take a backup first.

Revision ID: 068_component_advisor_policies
Revises: 067_component_advisor_foundation
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "068_component_advisor_policies"
down_revision = "067_component_advisor_foundation"
branch_labels = None
depends_on = None

# Frozen here: later catalogue changes must not change this migration's replay.
ROLE_PERMISSIONS = {
    "TENANT_ADMIN": ("tenant:advisor-policy:read", "tenant:advisor-policy:update"),
    "SECURITY_ANALYST": ("tenant:advisor-policy:read",),
}


def _tables(bind):
    return set(sa.inspect(bind).get_table_names())


def upgrade():
    bind = op.get_bind()
    tables = _tables(bind)
    tz = sa.DateTime(timezone=True)

    if "advisor_policy" not in tables:
        op.create_table(
            "advisor_policy",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
            sa.Column("kind", sa.String(32), nullable=False),
            sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_at", tz, nullable=False),
            sa.Column("updated_at", tz, nullable=False),
            sa.Column("created_by", sa.String(128), nullable=True),
            sa.Column("updated_by", sa.String(128), nullable=True),
            sa.UniqueConstraint("tenant_id", "kind", name="uq_advisor_policy_tenant_kind"),
        )
        op.create_index("ix_advisor_policy_tenant_id", "advisor_policy", ["tenant_id"])
        op.create_index(
            "uq_advisor_policy_platform_kind", "advisor_policy", ["kind"], unique=True,
            postgresql_where=sa.text("tenant_id IS NULL"), sqlite_where=sa.text("tenant_id IS NULL"),
        )

    if "advisor_policy_version" not in tables:
        op.create_table(
            "advisor_policy_version",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("policy_id", sa.Integer(), sa.ForeignKey("advisor_policy.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
            sa.Column("kind", sa.String(32), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("rules_json", sa.JSON(), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("created_at", tz, nullable=False),
            sa.Column("created_by", sa.String(128), nullable=True),
            sa.Column("correlation_id", sa.String(128), nullable=True),
            sa.UniqueConstraint("policy_id", "version", name="uq_advisor_policy_version_number"),
        )
        op.create_index("ix_advisor_policy_version_policy_id", "advisor_policy_version", ["policy_id"])
        op.create_index("ix_advisor_policy_version_tenant_id", "advisor_policy_version", ["tenant_id"])

    if "component_purpose_metadata" not in tables:
        op.create_table(
            "component_purpose_metadata",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
            sa.Column("family_key", sa.String(512), nullable=False),
            sa.Column("source", sa.String(16), nullable=False),
            sa.Column("purpose", sa.Text(), nullable=True),
            sa.Column("primary_use_case", sa.String(255), nullable=True),
            sa.Column("category", sa.String(128), nullable=True),
            sa.Column("confidence", sa.String(16), nullable=False),
            sa.Column("provenance_json", sa.JSON(), nullable=True),
            sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_at", tz, nullable=False),
            sa.Column("updated_at", tz, nullable=False),
            sa.Column("created_by", sa.String(128), nullable=True),
            sa.Column("updated_by", sa.String(128), nullable=True),
            sa.UniqueConstraint("tenant_id", "family_key", "source", name="uq_component_purpose_tenant_family_source"),
        )
        op.create_index("ix_component_purpose_metadata_tenant_id", "component_purpose_metadata", ["tenant_id"])
        op.create_index("ix_component_purpose_metadata_family_key", "component_purpose_metadata", ["family_key"])
        op.create_index("ix_component_purpose_metadata_category", "component_purpose_metadata", ["category"])
        op.create_index(
            "uq_component_purpose_platform_family_source", "component_purpose_metadata", ["family_key", "source"],
            unique=True, postgresql_where=sa.text("tenant_id IS NULL"), sqlite_where=sa.text("tenant_id IS NULL"),
        )

    columns = {column["name"] for column in sa.inspect(bind).get_columns("sbom_component")}
    if "description" not in columns:
        with op.batch_alter_table("sbom_component") as batch:
            batch.add_column(sa.Column("description", sa.Text(), nullable=True))

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
                        code=code, name=code.replace(":", " ").replace("-", " ").title(), scope="TENANT",
                        resource=resource, action=action, status="ACTIVE", is_system=True,
                        created_at=now, updated_at=now,
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
    columns = {column["name"] for column in sa.inspect(bind).get_columns("sbom_component")}
    if "description" in columns:
        with op.batch_alter_table("sbom_component") as batch:
            batch.drop_column("description")
    tables = _tables(bind)
    for table in ("component_purpose_metadata", "advisor_policy_version", "advisor_policy"):
        if table in tables:
            op.drop_table(table)
