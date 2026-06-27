"""Add SBOM component extraction reconciliation status.

Revision ID: 036_component_extraction_status
Revises: 035_widen_audit_log_fields
Create Date: 2026-06-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "036_component_extraction_status"
down_revision = "035_widen_audit_log_fields"
branch_labels = None
depends_on = None


def _column_exists(bind, table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(bind)
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _index_exists(bind, table_name: str, index_name: str) -> bool:
    inspector = sa.inspect(bind)
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _add_column_if_missing(table_name: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if not _column_exists(bind, table_name, column.name):
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.add_column(column)


def upgrade() -> None:
    _add_column_if_missing("sbom_source", sa.Column("component_extraction_status", sa.String(length=32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("component_extraction_error", sa.Text(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("component_extraction_attempted_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("component_extraction_completed_at", sa.String(), nullable=True))

    bind = op.get_bind()
    if not _index_exists(bind, "sbom_source", "ix_sbom_source_component_extraction_status"):
        op.create_index(
            "ix_sbom_source_component_extraction_status",
            "sbom_source",
            ["component_extraction_status"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _index_exists(bind, "sbom_source", "ix_sbom_source_component_extraction_status"):
        op.drop_index("ix_sbom_source_component_extraction_status", table_name="sbom_source")

    for column_name in (
        "component_extraction_completed_at",
        "component_extraction_attempted_at",
        "component_extraction_error",
        "component_extraction_status",
    ):
        if _column_exists(bind, "sbom_source", column_name):
            with op.batch_alter_table("sbom_source") as batch_op:
                batch_op.drop_column(column_name)
