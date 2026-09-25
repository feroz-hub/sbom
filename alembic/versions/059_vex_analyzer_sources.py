"""Record which analyser sources contributed to each VEX context.

Revision ID: 059_vex_analyzer_sources
Revises: 058_vex_source_format
Create Date: 2026-09-25

VEX-REC-003 collapses NVD/OSV/GHSA hits for aliases of one vulnerability into
a single context, and requires that every contributing source still be
recorded. The reconciliation engine collected them but had nowhere to put
them, so ``GET /api/vex/investigations`` returned an empty
``analyzer_sources`` for every row and the section 27 column was always blank.

Additive and reversible. No backfill: the contributing sources for an existing
context cannot be reconstructed from the context alone, and inventing them
would be worse than a NULL. The next reconciliation run fills them in.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "059_vex_analyzer_sources"
down_revision = "058_vex_source_format"
branch_labels = None
depends_on = None

TABLE = "vex_investigation"
COLUMN = "analyzer_sources_json"


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    try:
        return {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return set()


def upgrade() -> None:
    bind = op.get_bind()
    if TABLE in sa.inspect(bind).get_table_names() and COLUMN not in _columns(bind, TABLE):
        op.add_column(TABLE, sa.Column(COLUMN, sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if TABLE in sa.inspect(bind).get_table_names() and COLUMN in _columns(bind, TABLE):
        op.drop_column(TABLE, COLUMN)
