"""Add soft-delete columns to user-owned tables.

Revision ID: 014_add_soft_delete_columns
Revises: 013_reclassify_unvalidated_sbom_source
Create Date: 2026-05-07

Why this exists
---------------
PR 2 of 3 in the soft-delete refactor. ``Phase 1`` audit
(``docs/soft-delete-audit.md``) identified eight tables in the ownership
tree that need the ``SoftDeleteMixin`` columns:

  * ``projects``
  * ``sbom_source``
  * ``sbom_analysis_report``
  * ``sbom_component``
  * ``analysis_run``
  * ``analysis_finding``
  * ``analysis_schedule``
  * ``ai_fix_batch``

This migration adds the three columns the mixin declares:

  * ``is_active``       — ``BOOLEAN NOT NULL DEFAULT true``. Existing
                          rows pick up the default at backfill time so
                          no data is lost.
  * ``deactivated_at``  — ``TIMESTAMPTZ NULL``. When the row was
                          tombstoned.
  * ``deactivated_by``  — ``VARCHAR(128) NULL``. String to match the
                          existing ``created_by`` / ``modified_by``
                          identity model — there is no ``user`` table
                          today.

A partial index on ``WHERE is_active = false`` is created per table so
admin "show deleted" queries stay cheap as the live-row count grows.
The hot path (``WHERE is_active = true``) stays sequential; it's the
default state and most rows live there, so a partial index keyed on
the rare value is the right choice.

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-013.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.sql import expression

revision = "014_add_soft_delete_columns"
down_revision = "013_reclassify_unvalidated_sbom_source"
branch_labels = None
depends_on = None


# Tables that get the SoftDeleteMixin. Order doesn't matter for column
# adds, but we keep it parent-first for readability.
SOFT_DELETE_TABLES = (
    "projects",
    "sbom_source",
    "sbom_analysis_report",
    "sbom_component",
    "analysis_run",
    "analysis_finding",
    "analysis_schedule",
    "ai_fix_batch",
)


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


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()

    for table in SOFT_DELETE_TABLES:
        if not _table_exists(bind, table):
            # Fresh install paths where ``Base.metadata.create_all`` has
            # not run yet (or this table does not exist for a partial
            # deploy) skip silently. The mixin-driven CREATE TABLE will
            # carry the columns natively.
            continue

        if not _column_exists(bind, table, "is_active"):
            op.add_column(
                table,
                sa.Column(
                    "is_active",
                    sa.Boolean(),
                    nullable=False,
                    server_default=expression.true(),
                ),
            )

        if not _column_exists(bind, table, "deactivated_at"):
            op.add_column(
                table,
                sa.Column(
                    "deactivated_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                ),
            )

        if not _column_exists(bind, table, "deactivated_by"):
            op.add_column(
                table,
                sa.Column(
                    "deactivated_by",
                    sa.String(length=128),
                    nullable=True,
                ),
            )

        # Partial index on tombstones — the rare case. Keeps "show
        # deleted records" admin queries fast without bloating writes
        # to the hot path.
        index_name = f"ix_{table}_deactivated"
        if not _index_exists(bind, table, index_name):
            op.create_index(
                index_name,
                table,
                ["is_active"],
                postgresql_where=sa.text("is_active = false"),
                sqlite_where=sa.text("is_active = 0"),
            )


def downgrade() -> None:
    bind = op.get_bind()

    for table in SOFT_DELETE_TABLES:
        if not _table_exists(bind, table):
            continue

        index_name = f"ix_{table}_deactivated"
        if _index_exists(bind, table, index_name):
            op.drop_index(index_name, table_name=table)

        for col in ("deactivated_by", "deactivated_at", "is_active"):
            if _column_exists(bind, table, col):
                op.drop_column(table, col)
