"""``source_response_cache`` — per-(source, component) raw response cache.

Revision ID: 018_source_response_cache
Revises: 017_analysis_finding_confidence_and_strategy
Create Date: 2026-06-03

Why this exists
---------------
Roadmap #2 (PR-A): cache each vulnerability source's RAW response per
component so re-scans skip re-hitting OSV / GHSA / VulDB / (and
possibly NVD — see PR-B's decision) when nothing changed. The
existing ``cve_cache`` table caches per-CVE-ID detail payloads —
different concern, different key space.

Key shape: composite primary key ``(source, component_key)`` where
``component_key`` is the canonical PURL string. Same component
across SBOMs ⇒ same cache row, so PURL-based reuse cuts repeated
upstream calls for identical packages.

TTL semantics mirror ``cve_cache`` exactly:
  * ``fetched_at`` / ``expires_at`` are ISO-format strings (portable
    Postgres + SQLite).
  * Read-time staleness check (``now >= expires_at`` → miss).
  * Write is ``db.merge()`` — last-write-wins on PK collision.
  * ``ix_source_response_cache_expires_at`` supports a future
    periodic sweep job to drop expired rows; today's reader just
    treats expired rows as misses.

Idempotency: existence-checked, mirrors 006 / 014 / 015 / 016 / 017.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "018_source_response_cache"
down_revision = "017_analysis_finding_confidence_and_strategy"
branch_labels = None
depends_on = None


TABLE = "source_response_cache"
EXPIRES_INDEX = "ix_source_response_cache_expires_at"


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        op.create_table(
            TABLE,
            # Source name: NVD / OSV / GITHUB / VULNDB — uppercase by
            # codebase convention. 32 chars is comfortably above the
            # longest existing label.
            sa.Column("source", sa.String(length=32), primary_key=True),
            # Canonical PURL. Real-world PURLs can reach ~250 chars
            # (npm scoped + Maven groups + percent-encoding); 512 is
            # safe headroom without forcing the key through a hash.
            sa.Column("component_key", sa.String(length=512), primary_key=True),
            # Portable JSON: JSONB on Postgres, TEXT on SQLite.
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("fetched_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
        )

    if not _index_exists(bind, TABLE, EXPIRES_INDEX):
        op.create_index(
            EXPIRES_INDEX,
            TABLE,
            ["expires_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, TABLE):
        if _index_exists(bind, TABLE, EXPIRES_INDEX):
            op.drop_index(EXPIRES_INDEX, table_name=TABLE)
        op.drop_table(TABLE)
