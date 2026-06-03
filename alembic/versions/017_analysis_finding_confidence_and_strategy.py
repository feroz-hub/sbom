"""Add ``match_confidence`` and ``match_strategy`` to ``analysis_finding``.

Revision ID: 017_analysis_finding_confidence_and_strategy
Revises: 016_analysis_finding_match_reason
Create Date: 2026-06-02

Why this exists
---------------
Roadmap features #3 (match-confidence scoring) and #6 (match-strategy
telemetry) need their own per-finding columns. The audit's
cross-cutting flag A established that sharing column space with
roadmap #1's ``match_reason`` (migration 016) was the wrong call:
``match_reason`` is set ONLY on the NVD flag-on path, whereas
``match_confidence`` is always computed and ``match_strategy`` is
always known at query time. Three orthogonal axes, three columns.

Both columns are NULLABLE with no default and no backfill so the
migration is safe against existing data and against any source not yet
emitting the field. PR-C will populate them on the production emit
step (per source). Old rows stay NULL.

Design choices, deliberately consistent with 016
------------------------------------------------
* **No CHECK constraint on ``match_confidence``.** The brief allowed one
  (the ``[0.0, 1.0]`` bound is permanent), but two practical issues
  argue against it here:
    - SQLite has no ``ALTER TABLE DROP CONSTRAINT``; removing a CHECK
      on downgrade requires a full table rebuild, breaking the simple
      drop-column pattern 016 established.
    - Migration 016 deliberately left the Python ``MatchReason``
      Literal as the source of truth; the scorer in PR-B is the
      natural place to enforce ``0.0 ≤ x ≤ 1.0`` with a unit test
      rather than a DB constraint. Same posture across the three new
      finding-tag columns keeps the contract uniform.
  If a future operational need ever wants DB-level defence (e.g. a
  third-party writer bypassing the scorer), it lands as its own
  Postgres-only migration with an explicit "skip on SQLite" branch.
* **No CHECK constraint on ``match_strategy``.** The Python Literal
  is the source of truth for the same reasons 016 cited; roadmap #6
  adding new strategy values must remain a single-file code change.
* **VARCHAR(32) on ``match_strategy``.** Comfortably fits every
  value the brief enumerates: ``cpe_name`` (8), ``virtual_match_string``
  (21), ``keyword_search`` (14), ``purl_direct`` (11), ``ghsa_alias``
  (10). The longest, ``virtual_match_string``, is 21 chars.
* **Index on ``match_strategy``.** Triage queries will filter on it
  ("show every finding produced by keyword-search") and the column
  is low-cardinality — five values today, modest growth in #6.
  Mirrors the index on ``match_reason``.
* **No index on ``match_confidence``.** Confidence is a continuous
  float; range scans and threshold filters would benefit from an
  index, but the workload (filter ≥ threshold, sort, paginate) is
  better served by a composite index added on demand once the UI
  filter ships in PR-D and we know the threshold's hot-path shape.

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-016.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "017_analysis_finding_confidence_and_strategy"
down_revision = "016_analysis_finding_match_reason"
branch_labels = None
depends_on = None


TABLE = "analysis_finding"
STRATEGY_INDEX_NAME = "ix_analysis_finding_match_strategy"


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
        # run yet skip silently — the model-driven CREATE TABLE carries
        # the columns natively.
        return

    if not _column_exists(bind, TABLE, "match_confidence"):
        op.add_column(
            TABLE,
            sa.Column("match_confidence", sa.Float(), nullable=True),
        )

    if not _column_exists(bind, TABLE, "match_strategy"):
        op.add_column(
            TABLE,
            sa.Column("match_strategy", sa.String(length=32), nullable=True),
        )

    if not _index_exists(bind, TABLE, STRATEGY_INDEX_NAME):
        op.create_index(STRATEGY_INDEX_NAME, TABLE, ["match_strategy"])


def downgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, TABLE):
        return

    if _index_exists(bind, TABLE, STRATEGY_INDEX_NAME):
        op.drop_index(STRATEGY_INDEX_NAME, table_name=TABLE)

    for col in ("match_strategy", "match_confidence"):
        if _column_exists(bind, TABLE, col):
            op.drop_column(TABLE, col)
