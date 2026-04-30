"""cve_cache — merged CVE detail payload cache.

Revision ID: 006_cve_cache
Revises: 005_rename_run_status
Create Date: 2026-04-30

Adds the ``cve_cache`` table that backs the in-app CVE detail modal. Each
row holds the merged ``CveDetail`` payload (OSV + GHSA + NVD + EPSS + KEV)
keyed by canonical ``CVE-YYYY-NNNN+`` identifier.

TTL policy is enforced by the service layer at upsert time:
  * KEV-listed CVE        →  6h
  * Recent CVE (<90d)     → 24h
  * Older CVE             →  7d
  * Fetch-error row       → 15m  (negative cache; ``fetch_error`` non-null)

Idempotency: existence-checked, mirrors 002 / 003 / 004.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006_cve_cache"
down_revision = "005_rename_run_status"
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

    if not _table_exists(bind, "cve_cache"):
        op.create_table(
            "cve_cache",
            sa.Column("cve_id", sa.String(length=32), primary_key=True, index=True),
            # Portable JSON: maps to JSONB on Postgres, TEXT on SQLite.
            sa.Column("payload", sa.JSON(), nullable=False),
            # Comma-joined source list (kept as a plain string for portability;
            # the service deserializes on read). e.g. "osv,ghsa,nvd,epss,kev".
            sa.Column("sources_used", sa.String(length=128), nullable=False),
            sa.Column("fetched_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False, index=True),
            sa.Column("fetch_error", sa.Text(), nullable=True),
            sa.Column(
                "schema_version",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
            ),
        )

    if not _index_exists(bind, "cve_cache", "ix_cve_cache_expires_at"):
        op.create_index(
            "ix_cve_cache_expires_at",
            "cve_cache",
            ["expires_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "cve_cache"):
        if _index_exists(bind, "cve_cache", "ix_cve_cache_expires_at"):
            op.drop_index("ix_cve_cache_expires_at", table_name="cve_cache")
        op.drop_table("cve_cache")
