"""Add SPDX to CycloneDX conversion tracking columns on sbom_source.

Revision ID: 029_sbom_spdx_cyclonedx_conversion
Revises: 028_add_sbom_product_name_description
Create Date: 2026-06-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "029_sbom_spdx_cyclonedx_conversion"
down_revision = "028_add_sbom_product_name_description"
branch_labels = None
depends_on = None


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {col["name"] for col in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if not _column_exists(bind, table, column.name):
        op.add_column(table, column)


def upgrade() -> None:
    _add_column_if_missing("sbom_source", sa.Column("original_format", sa.String(32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("current_format", sa.String(32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("converted_from_format", sa.String(32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("source_sbom_id", sa.Integer(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("converted_sbom_id", sa.Integer(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_status", sa.String(32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_warnings_json", sa.JSON(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_report_json", sa.JSON(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("converted_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("converted_by", sa.String(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    for column in (
        "converted_by",
        "converted_at",
        "conversion_report_json",
        "conversion_warnings_json",
        "conversion_status",
        "converted_sbom_id",
        "source_sbom_id",
        "converted_from_format",
        "current_format",
        "original_format",
    ):
        if _column_exists(bind, "sbom_source", column):
            op.drop_column("sbom_source", column)
