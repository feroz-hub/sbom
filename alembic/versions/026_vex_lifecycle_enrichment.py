"""Add VEX enrichment and override audit tables.

Revision ID: 026_vex_lifecycle_enrichment
Revises: 025_lifecycle_advanced_fields
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "026_vex_lifecycle_enrichment"
down_revision = "025_lifecycle_advanced_fields"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


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
    if not _table_exists(bind, "vex_documents"):
        op.create_table(
            "vex_documents",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source_type", sa.String(), nullable=False),
            sa.Column("format", sa.String(), nullable=True),
            sa.Column("author", sa.String(), nullable=True),
            sa.Column("uploaded_by", sa.String(), nullable=True),
            sa.Column("uploaded_at", sa.String(), nullable=False),
            sa.Column("raw_document_json", sa.JSON(), nullable=True),
            sa.Column("validation_status", sa.String(), nullable=False),
        )
    if not _table_exists(bind, "vex_statements"):
        op.create_table(
            "vex_statements",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("vex_document_id", sa.Integer(), sa.ForeignKey("vex_documents.id", ondelete="CASCADE"), nullable=True),
            sa.Column("sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=False),
            sa.Column("component_id", sa.Integer(), sa.ForeignKey("sbom_component.id", ondelete="SET NULL"), nullable=True),
            sa.Column("vulnerability_id", sa.String(), nullable=False),
            sa.Column("cve_id", sa.String(), nullable=True),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("justification", sa.Text(), nullable=True),
            sa.Column("impact_statement", sa.Text(), nullable=True),
            sa.Column("action_statement", sa.Text(), nullable=True),
            sa.Column("fixed_version", sa.String(), nullable=True),
            sa.Column("mitigation", sa.Text(), nullable=True),
            sa.Column("source_name", sa.String(), nullable=True),
            sa.Column("source_url", sa.String(), nullable=True),
            sa.Column("confidence", sa.String(), nullable=True),
            sa.Column("evidence_json", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
        )
    if not _table_exists(bind, "component_lifecycle_override_audit"):
        op.create_table(
            "component_lifecycle_override_audit",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("component_id", sa.Integer(), sa.ForeignKey("sbom_component.id", ondelete="CASCADE"), nullable=False),
            sa.Column("old_value_json", sa.JSON(), nullable=True),
            sa.Column("new_value_json", sa.JSON(), nullable=True),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("evidence_url", sa.String(), nullable=True),
            sa.Column("changed_by", sa.String(), nullable=True),
            sa.Column("changed_at", sa.String(), nullable=False),
        )
    if not _table_exists(bind, "vex_override_audit"):
        op.create_table(
            "vex_override_audit",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("component_id", sa.Integer(), sa.ForeignKey("sbom_component.id", ondelete="CASCADE"), nullable=False),
            sa.Column("vulnerability_id", sa.String(), nullable=False),
            sa.Column("old_value_json", sa.JSON(), nullable=True),
            sa.Column("new_value_json", sa.JSON(), nullable=True),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("evidence_url", sa.String(), nullable=True),
            sa.Column("changed_by", sa.String(), nullable=True),
            sa.Column("changed_at", sa.String(), nullable=False),
        )

    for table, columns in {
        "vex_documents": ["sbom_id", "source_type", "format", "uploaded_by", "uploaded_at", "validation_status"],
        "vex_statements": ["vex_document_id", "sbom_id", "component_id", "vulnerability_id", "cve_id", "status", "created_at"],
        "component_lifecycle_override_audit": ["component_id", "changed_by", "changed_at"],
        "vex_override_audit": ["component_id", "vulnerability_id", "changed_by", "changed_at"],
    }.items():
        for column in columns:
            _create_index_if_missing(f"ix_{table}_{column}", table, [column])

    _create_index_if_missing("ix_vex_statement_sbom_status", "vex_statements", ["sbom_id", "status"])
    _create_index_if_missing("ix_vex_statement_component_vuln", "vex_statements", ["component_id", "vulnerability_id"])


def downgrade() -> None:
    bind = op.get_bind()
    for table in (
        "vex_override_audit",
        "component_lifecycle_override_audit",
        "vex_statements",
        "vex_documents",
    ):
        if _table_exists(bind, table):
            op.drop_table(table)
