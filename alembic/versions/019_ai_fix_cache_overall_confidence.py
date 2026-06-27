"""Add ``overall_confidence`` to ``ai_fix_cache``.

Revision ID: 019_ai_fix_cache_overall_confidence
Revises: 018_source_response_cache
Create Date: 2026-06-09

Why this exists
---------------
The AI fix bundle (:class:`app.ai.schemas.AiFixBundle`) gained a top-level
``overall_confidence`` field — the model's self-assessed confidence in the
*whole* response, surfaced prominently at the top of the AI-fix UI. The
existing two ``confidence`` fields live inside the ``remediation_prose`` /
``decision_recommendation`` JSON blobs and scope only their own section;
``overall_confidence`` is a new top-level scalar and therefore needs its own
column — the cache reconstructs the bundle from individual columns, so a
value with nowhere to land would silently reset to the default on every hit.

Nullable, no default, no backfill — historical rows persist as ``NULL`` and
``app.ai.cache.read_cache`` coerces ``NULL`` to the neutral ``"medium"``
default (matching the Pydantic default). New rows are written non-null.
That keeps this migration safe against existing data with no dependency on
deploy order.

Why no cache invalidation here
------------------------------
This column is backward-compatible (default applies on read), so
``SCHEMA_VERSION`` is intentionally NOT bumped. Regeneration of cached
bundles so the model actually populates the field is driven by the
``PROMPT_VERSION`` bump (v2 → v3) in ``app/ai/prompts/__init__.py``: that
changes the cache key, so post-deploy lookups miss the old v2 rows and
generate fresh v3 bundles that carry a real ``overall_confidence``. Old
rows expire naturally (7d KEV / 30d default).

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-018.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "019_ai_fix_cache_overall_confidence"
down_revision = "018_source_response_cache"
branch_labels = None
depends_on = None


TABLE = "ai_fix_cache"
COLUMN = "overall_confidence"


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        # Fresh install paths where ``Base.metadata.create_all`` has not run
        # yet skip silently — the model-driven CREATE TABLE carries the
        # column natively.
        return

    if not _column_exists(bind, TABLE, COLUMN):
        op.add_column(
            TABLE,
            sa.Column(COLUMN, sa.String(length=16), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        return

    if _column_exists(bind, TABLE, COLUMN):
        op.drop_column(TABLE, COLUMN)
