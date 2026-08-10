"""Add ``match_reason`` and ``matched_range`` to ``analysis_finding``.

Revision ID: 016_analysis_finding_match_reason
Revises: 015_audit_log_table
Create Date: 2026-05-27

Why this exists
---------------
PR1 of the roadmap-#1 (version-range matching) work introduced
``app.sources.version_range.MatchVerdict``: a structured verdict with
``reason: MatchReason`` (seven-value ``Literal``) and ``matched_range``
(human-readable bound string such as ``">= 2.0.0, < 2.17.0"``). PR3
will wire the verdict into ``app/sources/nvd.py`` at the emit step,
which means the per-finding row needs two new columns so the verdict
can be persisted and surfaced in the finding-detail UI (roadmap #6).

Both columns are NULLABLE with no default and no backfill — historical
rows persist as ``NULL`` and PR3 populates new rows going forward.
That keeps this migration safe to run against existing data and
removes any dependency on the order in which PR2 / PR3 deploy.

Why no CHECK constraint
-----------------------
The ``MatchReason`` literal is the source of truth in Python. Locking
the seven values at the DB layer would turn roadmap #6's planned
additions (``cpe_name`` / ``virtual_match_string`` / ``keyword_search``
/ ``purl_direct`` / ``ghsa_alias``) into a migration instead of a
single-file code change. The narrow ``VARCHAR(32)`` width is the only
guardrail at the DB layer — sufficient to catch obvious bugs without
freezing the reason vocabulary.

Why an index on ``match_reason``
--------------------------------
Roadmap #6 will let analysts filter the findings list by reason
(e.g. "show me everything kept under ``and_node_ambiguous`` so I can
audit the AND-node fallthrough"). Triage queries should not table-scan
``analysis_finding`` — the table is the largest row-count in the
schema after ``sbom_component``. A B-tree on a low-cardinality
column is cheap to maintain and slashes the worst-case query plan.
No index on ``matched_range`` because nothing filters on it (it is
display-only).

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-015.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "016_analysis_finding_match_reason"
down_revision = "015_audit_log_table"
branch_labels = None
depends_on = None


TABLE = "analysis_finding"
INDEX_NAME = "ix_analysis_finding_match_reason"


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        # Fresh install paths where ``Base.metadata.create_all`` has not
        # run yet skip silently — the model-driven CREATE TABLE in PR2
        # carries the columns natively.
        return

    if not _column_exists(bind, TABLE, "match_reason"):
        op.add_column(
            TABLE,
            sa.Column("match_reason", sa.String(length=32), nullable=True),
        )

    if not _column_exists(bind, TABLE, "matched_range"):
        op.add_column(
            TABLE,
            sa.Column("matched_range", sa.String(length=128), nullable=True),
        )

    if not _index_exists(bind, TABLE, INDEX_NAME):
        op.create_index(INDEX_NAME, TABLE, ["match_reason"])


def downgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        return

    if _index_exists(bind, TABLE, INDEX_NAME):
        op.drop_index(INDEX_NAME, table_name=TABLE)

    for col in ("matched_range", "match_reason"):
        if _column_exists(bind, TABLE, col):
            op.drop_column(TABLE, col)
