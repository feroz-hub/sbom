"""Preserve global defaults and add isolated configuration overrides.

Revision ID: 065_scoped_configuration
Revises: 064_platform_tenant_v2
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "065_scoped_configuration"
down_revision = "064_platform_tenant_v2"
branch_labels = None
depends_on = None

TENANT_CONFIG_PERMISSIONS = (
    "tenant:ai:read",
    "tenant:ai:update",
    "tenant:ai:test",
    "tenant:lifecycle-provider:read",
    "tenant:lifecycle-provider:update",
    "tenant:lifecycle-provider:test",
    "tenant:lifecycle-provider:sync",
)


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    scopes = {
        "ai_provider_credential": ("provider_name", "label"),
        "ai_settings": (),
        "ai_credential_audit_log": None,
        "lifecycle_provider_configs": ("provider_key",),
        "lifecycle_provider_secrets": ("provider_key", "secret_name"),
    }
    for table, slot in scopes.items():
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                f"fk_{table}_configuration_tenant",
                "tenants",
                ["tenant_id"],
                ["id"],
                ondelete="CASCADE" if slot is not None else "SET NULL",
            )
            if slot:
                for constraint in inspector.get_unique_constraints(table):
                    if tuple(constraint["column_names"]) == slot:
                        batch.drop_constraint(constraint["name"], type_="unique")
                for index in inspector.get_indexes(table):
                    if (
                        index["unique"]
                        and tuple(index["column_names"]) == slot
                        and not index.get("duplicates_constraint")
                    ):
                        batch.drop_index(index["name"])
                batch.create_unique_constraint(f"uq_{table}_tenant_slot", ["tenant_id", *slot])
            elif table == "ai_settings":
                batch.drop_constraint("ck_ai_settings_singleton", type_="check")
                batch.create_unique_constraint("uq_ai_settings_tenant", ["tenant_id"])
                batch.alter_column("id", server_default=None)
        if slot is not None:
            op.create_index(
                f"uq_{table}_platform_slot",
                table,
                list(slot) or [sa.text("(1)")],
                unique=True,
                postgresql_where=sa.text("tenant_id IS NULL"),
                sqlite_where=sa.text("tenant_id IS NULL"),
            )
        op.create_index(f"ix_{table}_configuration_tenant", table, ["tenant_id"])
    if bind.dialect.name == "postgresql":
        op.execute("CREATE SEQUENCE IF NOT EXISTS ai_settings_scope_id_seq OWNED BY ai_settings.id")
        op.execute(
            "SELECT setval('ai_settings_scope_id_seq', COALESCE((SELECT MAX(id) FROM ai_settings), 0) + 1, false)"
        )
        op.execute("ALTER TABLE ai_settings ALTER COLUMN id SET DEFAULT nextval('ai_settings_scope_id_seq')")
    # Presence-only UI replaces plaintext key fragments retained by legacy UI.
    op.execute("UPDATE lifecycle_provider_secrets SET value_preview = NULL")
    _permissions(bind)
    for flag, suffix in (("is_default", "default"), ("is_fallback", "fallback")):
        op.drop_index(f"ix_ai_only_one_{suffix}", table_name="ai_provider_credential")
        op.create_index(
            f"ix_ai_only_one_{suffix}",
            "ai_provider_credential",
            [flag],
            unique=True,
            postgresql_where=sa.text(f"{flag} = TRUE AND tenant_id IS NULL"),
            sqlite_where=sa.text(f"{flag} = 1 AND tenant_id IS NULL"),
        )
        op.create_index(
            f"ix_ai_tenant_{suffix}",
            "ai_provider_credential",
            ["tenant_id"],
            unique=True,
            postgresql_where=sa.text(f"{flag} = TRUE AND tenant_id IS NOT NULL"),
            sqlite_where=sa.text(f"{flag} = 1 AND tenant_id IS NOT NULL"),
        )
    with op.batch_alter_table("component_lifecycle_cache") as batch:
        batch.add_column(sa.Column("configuration_namespace", sa.String(128), nullable=False, server_default="legacy"))
        batch.drop_constraint("uq_component_lifecycle_cache_identity", type_="unique")
        batch.create_unique_constraint(
            "uq_component_lifecycle_cache_identity",
            ["configuration_namespace", "normalized_name", "normalized_version", "ecosystem", "purl"],
        )


def _permissions(bind):
    metadata = sa.MetaData()
    roles = sa.Table("authorization_roles", metadata, autoload_with=bind)
    permissions = sa.Table("authorization_permissions", metadata, autoload_with=bind)
    mappings = sa.Table("authorization_role_permissions", metadata, autoload_with=bind)
    role_id = bind.scalar(sa.select(roles.c.id).where(roles.c.code == "TENANT_ADMIN", roles.c.scope == "TENANT"))
    now = datetime.now(UTC)
    for code in TENANT_CONFIG_PERMISSIONS:
        pid = bind.scalar(sa.select(permissions.c.id).where(permissions.c.code == code))
        if pid is None:
            resource, action = code.rsplit(":", 1)
            pid = bind.execute(
                permissions.insert()
                .values(
                    code=code,
                    name=code.replace(":", " ").title(),
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
        if (
            bind.scalar(sa.select(mappings.c.id).where(mappings.c.role_id == role_id, mappings.c.permission_id == pid))
            is None
        ):
            bind.execute(
                mappings.insert().values(
                    role_id=role_id, permission_id=pid, is_protected=False, created_at=now, updated_at=now
                )
            )
    bind.execute(roles.update().where(roles.c.id == role_id).values(version=roles.c.version + 1, updated_at=now))


def downgrade():
    raise RuntimeError(
        "Scoped configuration cannot be flattened safely; preserve overrides and restore a reviewed backup"
    )
