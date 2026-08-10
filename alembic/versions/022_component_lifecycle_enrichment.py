"""Add provider-based component lifecycle enrichment fields.

Revision ID: 022_component_lifecycle_enrichment
Revises: 021_remediation_audit_history
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "022_component_lifecycle_enrichment"
down_revision = "021_remediation_audit_history"
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


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if _table_exists(bind, table) and not _column_exists(bind, table, column.name):
        op.add_column(table, column)


def _create_index_if_missing(index_name: str, table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    if _table_exists(bind, table) and not _index_exists(bind, table, index_name):
        op.create_index(index_name, table, columns)


def upgrade() -> None:
    bind = op.get_bind()

    _add_column_if_missing("sbom_component", sa.Column("ecosystem", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("eof_date", sa.String(), nullable=True))
    _add_column_if_missing(
        "sbom_component",
        sa.Column("deprecated", sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    _add_column_if_missing("sbom_component", sa.Column("latest_supported_version", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("recommended_version", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_recommendation", sa.Text(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_source", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_source_url", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_confidence", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_checked_at", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_evidence_json", sa.JSON(), nullable=True))
    _add_column_if_missing(
        "sbom_component",
        sa.Column("lifecycle_is_stale", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    _add_column_if_missing(
        "sbom_component",
        sa.Column("lifecycle_manual_override", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    _create_index_if_missing("ix_sbom_component_ecosystem", "sbom_component", ["ecosystem"])
    _create_index_if_missing("ix_sbom_component_lifecycle_checked_at", "sbom_component", ["lifecycle_checked_at"])
    _create_index_if_missing(
        "ix_sbom_component_lifecycle",
        "sbom_component",
        ["lifecycle_status", "ecosystem"],
    )

    if not _table_exists(bind, "component_lifecycle_cache"):
        op.create_table(
            "component_lifecycle_cache",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("normalized_name", sa.String(), nullable=False),
            sa.Column("normalized_version", sa.String(), nullable=True),
            sa.Column("ecosystem", sa.String(), nullable=True),
            sa.Column("purl", sa.String(), nullable=True),
            sa.Column("lifecycle_status", sa.String(), nullable=True),
            sa.Column("eos_date", sa.String(), nullable=True),
            sa.Column("eol_date", sa.String(), nullable=True),
            sa.Column("eof_date", sa.String(), nullable=True),
            sa.Column("deprecated", sa.Boolean(), nullable=True, server_default=sa.false()),
            sa.Column("maintenance_status", sa.String(), nullable=True),
            sa.Column("latest_supported_version", sa.String(), nullable=True),
            sa.Column("recommended_version", sa.String(), nullable=True),
            sa.Column("recommendation", sa.Text(), nullable=True),
            sa.Column("source_name", sa.String(), nullable=True),
            sa.Column("source_url", sa.String(), nullable=True),
            sa.Column("evidence_json", sa.JSON(), nullable=True),
            sa.Column("confidence", sa.String(), nullable=True),
            sa.Column("checked_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.UniqueConstraint(
                "normalized_name",
                "normalized_version",
                "ecosystem",
                "purl",
                name="uq_component_lifecycle_cache_identity",
            ),
        )
        op.create_index(
            "ix_component_lifecycle_cache_lookup",
            "component_lifecycle_cache",
            ["ecosystem", "normalized_name", "normalized_version"],
        )
        op.create_index("ix_component_lifecycle_cache_normalized_name", "component_lifecycle_cache", ["normalized_name"])
        op.create_index(
            "ix_component_lifecycle_cache_normalized_version",
            "component_lifecycle_cache",
            ["normalized_version"],
        )
        op.create_index("ix_component_lifecycle_cache_ecosystem", "component_lifecycle_cache", ["ecosystem"])
        op.create_index("ix_component_lifecycle_cache_purl", "component_lifecycle_cache", ["purl"])
        op.create_index("ix_component_lifecycle_cache_checked_at", "component_lifecycle_cache", ["checked_at"])
        op.create_index("ix_component_lifecycle_cache_expires_at", "component_lifecycle_cache", ["expires_at"])


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "component_lifecycle_cache"):
        op.drop_index("ix_component_lifecycle_cache_expires_at", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_checked_at", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_purl", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_ecosystem", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_normalized_version", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_normalized_name", table_name="component_lifecycle_cache")
        op.drop_index("ix_component_lifecycle_cache_lookup", table_name="component_lifecycle_cache")
        op.drop_table("component_lifecycle_cache")

    for index_name in (
        "ix_sbom_component_lifecycle",
        "ix_sbom_component_lifecycle_checked_at",
        "ix_sbom_component_ecosystem",
    ):
        if _table_exists(bind, "sbom_component") and _index_exists(bind, "sbom_component", index_name):
            op.drop_index(index_name, table_name="sbom_component")

    for column in (
        "lifecycle_manual_override",
        "lifecycle_is_stale",
        "lifecycle_evidence_json",
        "lifecycle_checked_at",
        "lifecycle_confidence",
        "lifecycle_source_url",
        "lifecycle_source",
        "lifecycle_recommendation",
        "recommended_version",
        "latest_supported_version",
        "deprecated",
        "eof_date",
        "ecosystem",
    ):
        if _table_exists(bind, "sbom_component") and _column_exists(bind, "sbom_component", column):
            op.drop_column("sbom_component", column)
