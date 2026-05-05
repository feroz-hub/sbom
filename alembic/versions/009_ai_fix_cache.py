"""ai_fix_cache — Cached AI fix bundles (Phase 2).

Revision ID: 009_ai_fix_cache
Revises: 008_ai_usage_log
Create Date: 2026-05-03

Stores generated :class:`~app.ai.schemas.AiFixBundle` payloads keyed on
``sha256(vuln_id|component|version|prompt_version)``. Tenant-shared by
design — see ``app/ai/cache.py`` for the rationale.

TTL is enforced by ``app/ai/cache.py`` at upsert time:
  * KEV-listed CVE → 7 days
  * Non-KEV        → 30 days
  * Negative cache → 1 hour

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006 / 007 / 008.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "009_ai_fix_cache"
down_revision = "008_ai_usage_log"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, "ai_fix_cache"):
        op.create_table(
            "ai_fix_cache",
            sa.Column("cache_key", sa.String(length=64), primary_key=True),
            sa.Column("vuln_id", sa.String(length=64), nullable=False),
            sa.Column("component_name", sa.String(length=255), nullable=False),
            sa.Column("component_version", sa.String(length=128), nullable=False),
            sa.Column("prompt_version", sa.String(length=32), nullable=False),
            sa.Column(
                "schema_version",
                sa.SmallInteger(),
                nullable=False,
                server_default=sa.text("1"),
            ),
            # Portable JSON: maps to JSONB on Postgres, TEXT on SQLite.
            sa.Column("remediation_prose", sa.JSON(), nullable=False),
            sa.Column("upgrade_command", sa.JSON(), nullable=False),
            sa.Column("decision_recommendation", sa.JSON(), nullable=False),
            sa.Column("provider_used", sa.String(length=32), nullable=False),
            sa.Column("model_used", sa.String(length=96), nullable=False),
            sa.Column(
                "total_cost_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("generated_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column("last_accessed_at", sa.String(), nullable=False),
        )

    if not _index_exists(bind, "ai_fix_cache", "ix_ai_fix_cache_vuln_id"):
        op.create_index("ix_ai_fix_cache_vuln_id", "ai_fix_cache", ["vuln_id"])
    if not _index_exists(bind, "ai_fix_cache", "ix_ai_fix_cache_expires_at"):
        op.create_index("ix_ai_fix_cache_expires_at", "ai_fix_cache", ["expires_at"])
    if not _index_exists(bind, "ai_fix_cache", "ix_ai_fix_cache_vuln_component"):
        op.create_index(
            "ix_ai_fix_cache_vuln_component",
            "ai_fix_cache",
            ["vuln_id", "component_name", "component_version"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "ai_fix_cache"):
        for ix in (
            "ix_ai_fix_cache_vuln_id",
            "ix_ai_fix_cache_expires_at",
            "ix_ai_fix_cache_vuln_component",
        ):
            if _index_exists(bind, "ai_fix_cache", ix):
                op.drop_index(ix, table_name="ai_fix_cache")
        op.drop_table("ai_fix_cache")
