"""compare_cache — Compare Runs v2 result cache (ADR-0008).

Revision ID: 007_compare_cache
Revises: 006_cve_cache
Create Date: 2026-05-01

Adds the ``compare_cache`` table that backs ``POST /api/v1/compare``. Each
row holds the full ``CompareResult`` JSON for a deterministic
``(run_a_id, run_b_id)`` ordered pair.

Cache key is ``sha256(f"{min(a,b)}:{max(a,b)}")`` so swapping A and B does
not produce a duplicate row.

TTL is enforced by ``CompareService`` at upsert time (24h default; tunable
via ``Settings.compare_cache_ttl_seconds``). The Celery completion hook
also invalidates rows referencing a reanalysed run, so rows can be deleted
before ``expires_at`` if either side is rebuilt.

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "007_compare_cache"
down_revision = "006_cve_cache"
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

    if not _table_exists(bind, "compare_cache"):
        op.create_table(
            "compare_cache",
            sa.Column("cache_key", sa.String(length=64), primary_key=True),
            sa.Column("run_a_id", sa.Integer(), nullable=False),
            sa.Column("run_b_id", sa.Integer(), nullable=False),
            # Portable JSON: maps to JSONB on Postgres, TEXT on SQLite.
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("computed_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column(
                "schema_version",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
            ),
        )

    # Both run-id indices support O(1) cache invalidation when a run is
    # reanalysed (Celery hook deletes WHERE run_a_id = :id OR run_b_id = :id).
    if not _index_exists(bind, "compare_cache", "ix_compare_cache_run_a_id"):
        op.create_index(
            "ix_compare_cache_run_a_id",
            "compare_cache",
            ["run_a_id"],
        )
    if not _index_exists(bind, "compare_cache", "ix_compare_cache_run_b_id"):
        op.create_index(
            "ix_compare_cache_run_b_id",
            "compare_cache",
            ["run_b_id"],
        )
    if not _index_exists(bind, "compare_cache", "ix_compare_cache_expires_at"):
        op.create_index(
            "ix_compare_cache_expires_at",
            "compare_cache",
            ["expires_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "compare_cache"):
        for ix in (
            "ix_compare_cache_expires_at",
            "ix_compare_cache_run_b_id",
            "ix_compare_cache_run_a_id",
        ):
            if _index_exists(bind, "compare_cache", ix):
                op.drop_index(ix, table_name="compare_cache")
        op.drop_table("compare_cache")
