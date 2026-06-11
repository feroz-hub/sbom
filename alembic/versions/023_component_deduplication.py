"""Add component deduplication support.

Revision ID: 023_component_deduplication
Revises: 022_component_lifecycle_enrichment
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "023_component_deduplication"
down_revision = "022_component_lifecycle_enrichment"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {i["name"] for i in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def _create_index_if_missing(index_name: str, table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    if _table_exists(bind, table) and not _index_exists(bind, table, index_name):
        op.create_index(index_name, table, columns)


def upgrade() -> None:
    bind = op.get_bind()

    # Add column to sbom_source
    if not _column_exists(bind, "sbom_source", "dedupe_report_json"):
        with op.batch_alter_table("sbom_source") as batch_op:
            batch_op.add_column(sa.Column("dedupe_report_json", sa.JSON(), nullable=True))

    # Add columns to sbom_component
    with op.batch_alter_table("sbom_component") as batch_op:
        if not _column_exists(bind, "sbom_component", "normalized_component_key"):
            batch_op.add_column(sa.Column("normalized_component_key", sa.String(), nullable=True))
        if not _column_exists(bind, "sbom_component", "is_duplicate"):
            batch_op.add_column(
                sa.Column("is_duplicate", sa.Boolean(), nullable=False, server_default=sa.false())
            )
        if not _column_exists(bind, "sbom_component", "duplicate_of_component_id"):
            batch_op.add_column(
                sa.Column(
                    "duplicate_of_component_id",
                    sa.Integer(),
                    sa.ForeignKey("sbom_component.id", ondelete="CASCADE"),
                    nullable=True,
                )
            )

    # Create index on normalized_component_key and duplicate_of_component_id
    _create_index_if_missing("ix_sbom_component_normalized_component_key", "sbom_component", ["normalized_component_key"])
    _create_index_if_missing("ix_sbom_component_duplicate_of_component_id", "sbom_component", ["duplicate_of_component_id"])


def downgrade() -> None:
    bind = op.get_bind()

    # Drop indexes
    for index_name in (
        "ix_sbom_component_duplicate_of_component_id",
        "ix_sbom_component_normalized_component_key",
    ):
        if _table_exists(bind, "sbom_component") and _index_exists(bind, "sbom_component", index_name):
            op.drop_index(index_name, table_name="sbom_component")

    # Drop columns from sbom_component
    with op.batch_alter_table("sbom_component") as batch_op:
        if _column_exists(bind, "sbom_component", "duplicate_of_component_id"):
            batch_op.drop_column("duplicate_of_component_id")
        if _column_exists(bind, "sbom_component", "is_duplicate"):
            batch_op.drop_column("is_duplicate")
        if _column_exists(bind, "sbom_component", "normalized_component_key"):
            batch_op.drop_column("normalized_component_key")

    # Drop column from sbom_source
    if _column_exists(bind, "sbom_source", "dedupe_report_json"):
        with op.batch_alter_table("sbom_source") as batch_op:
            batch_op.drop_column("dedupe_report_json")
