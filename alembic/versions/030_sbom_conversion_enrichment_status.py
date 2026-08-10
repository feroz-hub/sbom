"""Add enrichment status tracking for SPDX to CycloneDX conversion.

Revision ID: 030_sbom_conversion_enrichment_status
Revises: 029_sbom_spdx_cyclonedx_conversion
Create Date: 2026-06-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "030_sbom_conversion_enrichment_status"
down_revision = "029_sbom_spdx_cyclonedx_conversion"
branch_labels = None
depends_on = None


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {col["name"] for col in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _index_exists(bind: sa.engine.Connection, table: str, index_name: str) -> bool:
    try:
        return index_name in {idx["name"] for idx in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if not _column_exists(bind, table, column.name):
        op.add_column(table, column)


def _create_index_if_missing(name: str, table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    if not _index_exists(bind, table, name):
        op.create_index(name, table, columns, unique=False)


def upgrade() -> None:
    _add_column_if_missing("sbom_source", sa.Column("enrichment_status", sa.String(32), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_started_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_completed_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("enrichment_started_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("enrichment_completed_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("conversion_error", sa.Text(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("enrichment_error", sa.Text(), nullable=True))

    _create_index_if_missing("ix_sbom_source_enrichment_status", "sbom_source", ["enrichment_status"])
    _create_index_if_missing("ix_sbom_source_parent_id", "sbom_source", ["parent_id"])
    _create_index_if_missing("ix_sbom_source_sbom_type", "sbom_source", ["sbom_type"])
    _create_index_if_missing("ix_sbom_source_converted_from_format", "sbom_source", ["converted_from_format"])
    _create_index_if_missing("ix_sbom_component_bom_ref", "sbom_component", ["bom_ref"])


def downgrade() -> None:
    bind = op.get_bind()
    for index_name, table in (
        ("ix_sbom_component_bom_ref", "sbom_component"),
        ("ix_sbom_source_converted_from_format", "sbom_source"),
        ("ix_sbom_source_sbom_type", "sbom_source"),
        ("ix_sbom_source_parent_id", "sbom_source"),
        ("ix_sbom_source_enrichment_status", "sbom_source"),
    ):
        if _index_exists(bind, table, index_name):
            op.drop_index(index_name, table_name=table)

    for column in (
        "enrichment_error",
        "conversion_error",
        "enrichment_completed_at",
        "enrichment_started_at",
        "conversion_completed_at",
        "conversion_started_at",
        "enrichment_status",
    ):
        if _column_exists(bind, "sbom_source", column):
            op.drop_column("sbom_source", column)
