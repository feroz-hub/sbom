"""ai_usage_log + ai_provider_config — AI fix generator foundation tables.

Revision ID: 008_ai_usage_log
Revises: 007_compare_cache
Create Date: 2026-05-03

Adds the two tables that back Phase 1 of the AI-driven remediation
feature:

* ``ai_usage_log`` — append-only ledger of every LLM call (cache hit,
  miss, or failure). Powers the cost dashboard and per-day budget
  enforcement. Indexed for time-range and per-purpose aggregation.

* ``ai_provider_config`` — per-provider runtime overrides (model,
  enabled flag, base URL, concurrency). Env vars in ``Settings`` provide
  the safe defaults; rows here let an admin tweak without a redeploy.
  Secrets stay in env / vault — never in this table.

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006 / 007.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "008_ai_usage_log"
down_revision = "007_compare_cache"
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

    # ------------------------------------------------------------------ ai_usage_log
    if not _table_exists(bind, "ai_usage_log"):
        op.create_table(
            "ai_usage_log",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("model", sa.String(length=96), nullable=False),
            sa.Column("purpose", sa.String(length=48), nullable=False),
            sa.Column("finding_cache_key", sa.String(length=64), nullable=True),
            sa.Column("input_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("output_tokens", sa.Integer(), nullable=False, server_default=sa.text("0")),
            # NUMERIC(10, 6) on Postgres → cents-precise; SQLite stores as REAL.
            sa.Column("cost_usd", sa.Numeric(10, 6), nullable=False, server_default=sa.text("0")),
            sa.Column("latency_ms", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column(
                "cache_hit",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
        )

    # Time-range scans dominate read traffic (today's spend, this-month trend).
    if not _index_exists(bind, "ai_usage_log", "ix_ai_usage_log_created_at"):
        op.create_index(
            "ix_ai_usage_log_created_at",
            "ai_usage_log",
            ["created_at"],
        )
    # Per-purpose breakdown on the cost dashboard.
    if not _index_exists(bind, "ai_usage_log", "ix_ai_usage_log_purpose_created"):
        op.create_index(
            "ix_ai_usage_log_purpose_created",
            "ai_usage_log",
            ["purpose", "created_at"],
        )
    # Per-provider breakdown ("which provider is cheapest for this org?").
    if not _index_exists(bind, "ai_usage_log", "ix_ai_usage_log_provider_created"):
        op.create_index(
            "ix_ai_usage_log_provider_created",
            "ai_usage_log",
            ["provider", "created_at"],
        )

    # ---------------------------------------------------------- ai_provider_config
    if not _table_exists(bind, "ai_provider_config"):
        op.create_table(
            "ai_provider_config",
            sa.Column("provider_name", sa.String(length=32), primary_key=True),
            sa.Column("enabled", sa.Boolean(), nullable=True),
            sa.Column("default_model", sa.String(length=96), nullable=True),
            sa.Column("base_url", sa.String(length=256), nullable=True),
            sa.Column("max_concurrent", sa.Integer(), nullable=True),
            sa.Column("rate_per_minute", sa.Float(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.String(), nullable=True),
            sa.Column("updated_by", sa.String(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "ai_usage_log"):
        for ix in (
            "ix_ai_usage_log_created_at",
            "ix_ai_usage_log_purpose_created",
            "ix_ai_usage_log_provider_created",
        ):
            if _index_exists(bind, "ai_usage_log", ix):
                op.drop_index(ix, table_name="ai_usage_log")
        op.drop_table("ai_usage_log")

    if _table_exists(bind, "ai_provider_config"):
        op.drop_table("ai_provider_config")
