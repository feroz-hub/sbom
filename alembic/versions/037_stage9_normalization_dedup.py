"""Add Stage 9 normalization and deduplication fields.

Revision ID: 037_stage9_normalization_dedup
Revises: 036_component_extraction_status
Create Date: 2026-06-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "037_stage9_normalization_dedup"
down_revision = "036_component_extraction_status"
branch_labels = None
depends_on = None


def _column_exists(bind, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in sa.inspect(bind).get_columns(table_name))


def _index_exists(bind, table_name: str, index_name: str) -> bool:
    return any(index["name"] == index_name for index in sa.inspect(bind).get_indexes(table_name))


def _add_column_if_missing(bind, table_name: str, column: sa.Column) -> None:
    if not _column_exists(bind, table_name, column.name):
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.add_column(column)


def _create_index_if_missing(bind, name: str, table_name: str, columns: list[str]) -> None:
    if not _index_exists(bind, table_name, name):
        op.create_index(name, table_name, columns)


def upgrade() -> None:
    bind = op.get_bind()
    for column in (
        sa.Column("original_name", sa.String(), nullable=True),
        sa.Column("normalized_name", sa.String(), nullable=True),
        sa.Column("original_version", sa.String(), nullable=True),
        sa.Column("normalized_version", sa.String(), nullable=True),
        sa.Column("normalized_ecosystem", sa.String(), nullable=True),
        sa.Column("original_purl", sa.String(), nullable=True),
        sa.Column("normalized_purl", sa.String(), nullable=True),
        sa.Column("purl_type", sa.String(), nullable=True),
        sa.Column("purl_namespace", sa.String(), nullable=True),
        sa.Column("purl_name", sa.String(), nullable=True),
        sa.Column("purl_version", sa.String(), nullable=True),
        sa.Column("purl_qualifiers_json", sa.JSON(), nullable=True),
        sa.Column("purl_subpath", sa.String(), nullable=True),
        sa.Column("normalized_cpes", sa.JSON(), nullable=True),
        sa.Column("primary_cpe", sa.String(), nullable=True),
        sa.Column("cpe_evidence_json", sa.JSON(), nullable=True),
        sa.Column("normalized_supplier", sa.String(), nullable=True),
        sa.Column("normalized_package_key", sa.String(), nullable=True),
        sa.Column("canonical_identity_confidence", sa.String(), nullable=True),
        sa.Column("dedupe_canonical_id", sa.String(), nullable=True),
        sa.Column("dedupe_group_id", sa.String(), nullable=True),
        sa.Column("dedupe_reason", sa.String(), nullable=True),
        sa.Column("dedupe_confidence", sa.String(), nullable=True),
        sa.Column("normalization_notes_json", sa.JSON(), nullable=True),
        sa.Column("dedupe_evidence_json", sa.JSON(), nullable=True),
    ):
        _add_column_if_missing(bind, "sbom_component", column)

    for name, columns in (
        ("ix_sbom_component_normalized_name", ["normalized_name"]),
        ("ix_sbom_component_normalized_version", ["normalized_version"]),
        ("ix_sbom_component_normalized_ecosystem", ["normalized_ecosystem"]),
        ("ix_sbom_component_normalized_purl", ["normalized_purl"]),
        ("ix_sbom_component_primary_cpe", ["primary_cpe"]),
        ("ix_sbom_component_normalized_package_key", ["normalized_package_key"]),
        ("ix_sbom_component_dedupe_canonical_id", ["dedupe_canonical_id"]),
        ("ix_sbom_component_dedupe_group_id", ["dedupe_group_id"]),
        ("ix_sbom_component_sbom_normalized_key", ["sbom_id", "normalized_component_key"]),
        ("ix_sbom_component_sbom_is_duplicate", ["sbom_id", "is_duplicate"]),
        (
            "ix_sbom_component_normalized_identity",
            ["normalized_ecosystem", "normalized_name", "normalized_version"],
        ),
    ):
        _create_index_if_missing(bind, name, "sbom_component", columns)


def downgrade() -> None:
    bind = op.get_bind()
    for name in (
        "ix_sbom_component_normalized_identity",
        "ix_sbom_component_sbom_is_duplicate",
        "ix_sbom_component_sbom_normalized_key",
        "ix_sbom_component_dedupe_group_id",
        "ix_sbom_component_dedupe_canonical_id",
        "ix_sbom_component_normalized_package_key",
        "ix_sbom_component_primary_cpe",
        "ix_sbom_component_normalized_purl",
        "ix_sbom_component_normalized_ecosystem",
        "ix_sbom_component_normalized_version",
        "ix_sbom_component_normalized_name",
    ):
        if _index_exists(bind, "sbom_component", name):
            op.drop_index(name, table_name="sbom_component")
    for column_name in (
        "dedupe_evidence_json",
        "normalization_notes_json",
        "dedupe_confidence",
        "dedupe_reason",
        "dedupe_group_id",
        "dedupe_canonical_id",
        "canonical_identity_confidence",
        "normalized_package_key",
        "normalized_supplier",
        "cpe_evidence_json",
        "primary_cpe",
        "normalized_cpes",
        "purl_subpath",
        "purl_qualifiers_json",
        "purl_version",
        "purl_name",
        "purl_namespace",
        "purl_type",
        "normalized_purl",
        "original_purl",
        "normalized_ecosystem",
        "normalized_version",
        "original_version",
        "normalized_name",
        "original_name",
    ):
        if _column_exists(bind, "sbom_component", column_name):
            with op.batch_alter_table("sbom_component") as batch_op:
                batch_op.drop_column(column_name)
