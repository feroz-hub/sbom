"""Add lifecycle provider admin configuration.

Revision ID: 034_lifecycle_provider_admin
Revises: 033_hcl_iam_multitenancy
Create Date: 2026-06-27
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

revision = "034_lifecycle_provider_admin"
down_revision = "033_hcl_iam_multitenancy"
branch_labels = None
depends_on = None


DEFAULT_PROVIDER_CONFIGS = (
    ("redhat_lifecycle", "Red Hat Lifecycle", "official_vendor", True, 10, None, None, None, 5),
    ("official_vendor_lifecycle", "Official Vendor Lifecycle", "official_vendor", True, 10, None, None, None, 5),
    ("endoflife_date", "endoflife.date", "endoflife_date", True, 30, "https://endoflife.date/api", None, None, 5),
    ("package_registry", "Package Registry", "package_registry", True, 50, None, None, None, 5),
    ("deps_dev", "deps.dev", "deps_dev", True, 60, None, None, None, 5),
    ("osv", "OSV", "osv", True, 70, None, None, None, 5),
    ("repository_health", "Repository Health", "repository_health", True, 80, None, None, None, 5),
    ("custom_vendor_records", "Custom Vendor Records", "custom_vendor", False, 5, None, None, None, 5),
    ("openeox", "OpenEoX", "openeox", False, 20, None, [], None, 10),
    ("xeol_api", "Xeol API", "xeol_api", False, 40, "https://edb-prod.xeol.io/eol/check", None, None, 5),
    ("xeol_db", "Local Xeol DB", "xeol_db", False, 40, None, None, {"db_path": None}, 5),
)


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _indexes(bind, table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes(table)}


def _create_tables(bind) -> None:
    tables = _tables(bind)
    if "lifecycle_provider_configs" not in tables:
        op.create_table(
            "lifecycle_provider_configs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("provider_key", sa.String(64), nullable=False),
            sa.Column("display_name", sa.String(128), nullable=False),
            sa.Column("provider_type", sa.String(64), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("base_url", sa.String(512), nullable=True),
            sa.Column("feed_urls_json", sa.JSON(), nullable=True),
            sa.Column("config_json", sa.JSON(), nullable=True),
            sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="5"),
            sa.Column("max_retries", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("circuit_breaker_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("cache_ttl_known_days", sa.Integer(), nullable=True),
            sa.Column("cache_ttl_unknown_hours", sa.Integer(), nullable=True),
            sa.Column("cache_ttl_failure_minutes", sa.Integer(), nullable=True),
            sa.Column("cache_ttl_deprecated_days", sa.Integer(), nullable=True),
            sa.Column("last_success_at", sa.String(), nullable=True),
            sa.Column("last_failure_at", sa.String(), nullable=True),
            sa.Column("last_failure_message", sa.Text(), nullable=True),
            sa.Column("health_status", sa.String(32), nullable=False, server_default="unknown"),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("provider_key", name="uq_lifecycle_provider_configs_provider_key"),
            sa.CheckConstraint("priority BETWEEN 1 AND 1000", name="ck_lifecycle_provider_config_priority"),
            sa.CheckConstraint("timeout_seconds BETWEEN 1 AND 60", name="ck_lifecycle_provider_config_timeout"),
            sa.CheckConstraint("max_retries BETWEEN 0 AND 10", name="ck_lifecycle_provider_config_retries"),
            sa.CheckConstraint(
                "health_status IN ('healthy','degraded','disabled','unknown')",
                name="ck_lifecycle_provider_config_health",
            ),
        )
    if "lifecycle_provider_secrets" not in tables:
        op.create_table(
            "lifecycle_provider_secrets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("provider_key", sa.String(64), nullable=False),
            sa.Column("secret_name", sa.String(64), nullable=False),
            sa.Column("encrypted_value", sa.Text(), nullable=False),
            sa.Column("value_preview", sa.String(64), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("provider_key", "secret_name", name="uq_lifecycle_provider_secret_provider_name"),
        )
    if "lifecycle_vendor_records" not in tables:
        op.create_table(
            "lifecycle_vendor_records",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("vendor_name", sa.String(128), nullable=False),
            sa.Column("product_name", sa.String(255), nullable=False),
            sa.Column("product_aliases_json", sa.JSON(), nullable=True),
            sa.Column("ecosystem", sa.String(64), nullable=True),
            sa.Column("version_pattern", sa.String(128), nullable=True),
            sa.Column("version_start", sa.String(64), nullable=True),
            sa.Column("version_end", sa.String(64), nullable=True),
            sa.Column("lifecycle_status", sa.String(64), nullable=False),
            sa.Column("maintenance_status", sa.String(128), nullable=True),
            sa.Column("eol_date", sa.String(), nullable=True),
            sa.Column("eos_date", sa.String(), nullable=True),
            sa.Column("eof_date", sa.String(), nullable=True),
            sa.Column("deprecated", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("unsupported", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("latest_supported_version", sa.String(128), nullable=True),
            sa.Column("recommended_version", sa.String(128), nullable=True),
            sa.Column("evidence_url", sa.String(512), nullable=True),
            sa.Column("evidence_json", sa.JSON(), nullable=True),
            sa.Column("confidence", sa.String(32), nullable=False, server_default="High"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
        )


def _create_indexes(bind) -> None:
    for table, indexes in {
        "lifecycle_provider_configs": (
            ("ix_lifecycle_provider_configs_provider_key", ["provider_key"], True),
            ("ix_lifecycle_provider_configs_provider_type", ["provider_type"], False),
            ("ix_lifecycle_provider_configs_health_status", ["health_status"], False),
            ("ix_lifecycle_provider_configs_enabled_priority", ["enabled", "priority"], False),
        ),
        "lifecycle_provider_secrets": (
            ("ix_lifecycle_provider_secrets_provider_key", ["provider_key"], False),
            ("ix_lifecycle_provider_secrets_provider", ["provider_key"], False),
        ),
        "lifecycle_vendor_records": (
            ("ix_lifecycle_vendor_records_vendor_name", ["vendor_name"], False),
            ("ix_lifecycle_vendor_records_product_name", ["product_name"], False),
            ("ix_lifecycle_vendor_records_ecosystem", ["ecosystem"], False),
            ("ix_lifecycle_vendor_records_enabled", ["enabled"], False),
            ("ix_lifecycle_vendor_records_lookup", ["enabled", "ecosystem", "product_name"], False),
        ),
    }.items():
        existing = _indexes(bind, table)
        for name, columns, unique in indexes:
            if name not in existing:
                op.create_index(name, table, columns, unique=unique)


def _seed_defaults(bind) -> None:
    provider_configs = sa.table(
        "lifecycle_provider_configs",
        sa.column("provider_key", sa.String()),
        sa.column("display_name", sa.String()),
        sa.column("provider_type", sa.String()),
        sa.column("enabled", sa.Boolean()),
        sa.column("priority", sa.Integer()),
        sa.column("base_url", sa.String()),
        sa.column("feed_urls_json", sa.JSON()),
        sa.column("config_json", sa.JSON()),
        sa.column("timeout_seconds", sa.Integer()),
        sa.column("max_retries", sa.Integer()),
        sa.column("circuit_breaker_enabled", sa.Boolean()),
        sa.column("health_status", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )

    now = datetime.now(UTC)
    for key, name, provider_type, enabled, priority, base_url, feed_urls, config, timeout in DEFAULT_PROVIDER_CONFIGS:
        row = {
            "provider_key": key,
            "display_name": name,
            "provider_type": provider_type,
            "enabled": enabled,
            "priority": priority,
            "base_url": base_url,
            "feed_urls_json": feed_urls,
            "config_json": config,
            "timeout_seconds": timeout,
            "max_retries": 0,
            "circuit_breaker_enabled": True,
            "health_status": "unknown" if enabled else "disabled",
            "created_at": now,
            "updated_at": now,
        }

        if bind.dialect.name == "postgresql":
            stmt = pg_insert(provider_configs).values(row)
            stmt = stmt.on_conflict_do_nothing(index_elements=["provider_key"])
            bind.execute(stmt)
        elif bind.dialect.name == "sqlite":
            stmt = sqlite_insert(provider_configs).values(row)
            stmt = stmt.on_conflict_do_nothing(index_elements=["provider_key"])
            bind.execute(stmt)
        else:
            exists = bind.execute(
                sa.text("SELECT 1 FROM lifecycle_provider_configs WHERE provider_key = :provider_key"),
                {"provider_key": row["provider_key"]},
            ).first()
            if not exists:
                bind.execute(provider_configs.insert().values(row))


def upgrade() -> None:
    bind = op.get_bind()
    _create_tables(bind)
    _create_indexes(bind)
    _seed_defaults(bind)


def downgrade() -> None:
    for table in ("lifecycle_vendor_records", "lifecycle_provider_secrets", "lifecycle_provider_configs"):
        if table in _tables(op.get_bind()):
            op.drop_table(table)
