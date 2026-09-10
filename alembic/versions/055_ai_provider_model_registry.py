"""Persist dynamically discovered AI provider models.

Revision ID: 055_ai_model_registry
Revises: 054_hierarchical_scheduler
Create Date: 2026-09-09

Existing ``default_model`` values are preserved as selected, unverified
registry rows. A later successful discovery refresh changes availability but
never changes the selection automatically.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "055_ai_model_registry"
down_revision = "054_hierarchical_scheduler"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {item["name"] for item in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()
    for table, column, old_length, nullable in (
        ("ai_usage_log", "model", 96, False),
        ("ai_provider_config", "default_model", 96, True),
        ("ai_fix_cache", "model_used", 96, False),
        ("ai_provider_credential", "default_model", 128, True),
    ):
        if _table_exists(bind, table):
            with op.batch_alter_table(table) as batch:
                batch.alter_column(
                    column,
                    existing_type=sa.String(length=old_length),
                    type_=sa.String(length=256),
                    existing_nullable=nullable,
                )
    if not _table_exists(bind, "ai_provider_model"):
        op.create_table(
            "ai_provider_model",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "provider_credential_id",
                sa.Integer(),
                sa.ForeignKey("ai_provider_credential.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("provider_name", sa.String(length=32), nullable=False),
            sa.Column("provider_model_id", sa.String(length=256), nullable=False),
            sa.Column("runtime_model_id", sa.String(length=256), nullable=False),
            sa.Column("display_name", sa.String(length=256), nullable=True),
            sa.Column("is_available", sa.Boolean(), nullable=True),
            sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("is_selected", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("supports_chat", sa.Boolean(), nullable=True),
            sa.Column("supports_structured_output", sa.Boolean(), nullable=True),
            sa.Column("supports_streaming", sa.Boolean(), nullable=True),
            sa.Column("supports_tools", sa.Boolean(), nullable=True),
            sa.Column("context_window", sa.Integer(), nullable=True),
            sa.Column("max_output_tokens", sa.Integer(), nullable=True),
            sa.Column("discovery_source", sa.String(length=24), nullable=False, server_default="live"),
            sa.Column("first_discovered_at", sa.String(), nullable=True),
            sa.Column("last_discovered_at", sa.String(), nullable=True),
            sa.Column("last_verified_at", sa.String(), nullable=True),
            sa.Column("last_test_success", sa.Boolean(), nullable=True),
            sa.Column("last_test_error", sa.String(length=240), nullable=True),
            sa.Column("raw_metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.UniqueConstraint(
                "provider_credential_id",
                "provider_model_id",
                name="uq_ai_provider_model_credential_provider_model",
            ),
        )

    if not _index_exists(bind, "ai_provider_model", "ix_ai_provider_model_provider_credential_id"):
        op.create_index(
            "ix_ai_provider_model_provider_credential_id",
            "ai_provider_model",
            ["provider_credential_id"],
        )
    if not _index_exists(bind, "ai_provider_model", "ix_ai_provider_model_provider_name"):
        op.create_index("ix_ai_provider_model_provider_name", "ai_provider_model", ["provider_name"])
    if not _index_exists(bind, "ai_provider_model", "ix_ai_provider_model_credential_available"):
        op.create_index(
            "ix_ai_provider_model_credential_available",
            "ai_provider_model",
            ["provider_credential_id", "is_available"],
        )
    if not _index_exists(bind, "ai_provider_model", "ix_ai_provider_model_only_one_selected"):
        op.create_index(
            "ix_ai_provider_model_only_one_selected",
            "ai_provider_model",
            ["provider_credential_id"],
            unique=True,
            sqlite_where=sa.text("is_selected = 1"),
            postgresql_where=sa.text("is_selected = TRUE"),
        )

    # Backward compatibility: preserve every configured legacy model without
    # claiming it was returned by live discovery.
    op.execute(
        sa.text(
            """
            INSERT INTO ai_provider_model (
                provider_credential_id, provider_name, provider_model_id,
                runtime_model_id, display_name, is_available, is_enabled,
                is_selected, discovery_source, first_discovered_at,
                last_discovered_at, created_at, updated_at
            )
            SELECT id, provider_name, default_model, default_model, NULL, NULL,
                   TRUE, TRUE, 'legacy', NULL, NULL, created_at, updated_at
            FROM ai_provider_credential
            WHERE default_model IS NOT NULL AND length(trim(default_model)) > 0
              AND NOT EXISTS (
                  SELECT 1 FROM ai_provider_model model
                  WHERE model.provider_credential_id = ai_provider_credential.id
                    AND model.provider_model_id = ai_provider_credential.default_model
              )
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "ai_provider_model"):
        op.drop_table("ai_provider_model")
    for table, column, old_length, nullable in (
        ("ai_usage_log", "model", 96, False),
        ("ai_provider_config", "default_model", 96, True),
        ("ai_fix_cache", "model_used", 96, False),
        ("ai_provider_credential", "default_model", 128, True),
    ):
        if _table_exists(bind, table):
            with op.batch_alter_table(table) as batch:
                batch.alter_column(
                    column,
                    existing_type=sa.String(length=256),
                    type_=sa.String(length=old_length),
                    existing_nullable=nullable,
                )
