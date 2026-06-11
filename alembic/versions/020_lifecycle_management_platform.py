"""Add SBOM lifecycle, completeness, versioning, and remediation schema.

Revision ID: 020_lifecycle_management_platform
Revises: 019_ai_fix_cache_overall_confidence
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "020_lifecycle_management_platform"
down_revision = "019_ai_fix_cache_overall_confidence"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if _table_exists(bind, table) and not _column_exists(bind, table, column.name):
        op.add_column(table, column)


def upgrade() -> None:
    bind = op.get_bind()

    _add_column_if_missing("sbom_source", sa.Column("parent_id", sa.Integer(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("change_summary", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("completeness_score", sa.Float(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("completeness_report", sa.JSON(), nullable=True))

    _add_column_if_missing("sbom_component", sa.Column("license", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("hashes", sa.Text(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("lifecycle_status", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("eos_date", sa.String(), nullable=True))
    _add_column_if_missing("sbom_component", sa.Column("eol_date", sa.String(), nullable=True))
    _add_column_if_missing(
        "sbom_component",
        sa.Column("is_deprecated", sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    _add_column_if_missing("sbom_component", sa.Column("maintenance_status", sa.String(), nullable=True))

    if not _table_exists(bind, "vulnerability_remediation"):
        op.create_table(
            "vulnerability_remediation",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("vuln_id", sa.String(), nullable=False),
            sa.Column("component_name", sa.String(), nullable=False),
            sa.Column("component_version", sa.String(), nullable=False),
            sa.Column("fixed_version", sa.String(), nullable=True),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("owner", sa.String(), nullable=True),
            sa.Column("due_date", sa.String(), nullable=True),
            sa.Column("resolution_date", sa.String(), nullable=True),
            sa.Column("fix_notes", sa.Text(), nullable=True),
            sa.Column("created_on", sa.String(), nullable=False),
            sa.Column("updated_on", sa.String(), nullable=False),
        )
        op.create_index("ix_vulnerability_remediation_project_id", "vulnerability_remediation", ["project_id"])
        op.create_index("ix_vulnerability_remediation_vuln_id", "vulnerability_remediation", ["vuln_id"])
        op.create_index(
            "ix_vulnerability_remediation_component_name",
            "vulnerability_remediation",
            ["component_name"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "vulnerability_remediation"):
        op.drop_index("ix_vulnerability_remediation_component_name", table_name="vulnerability_remediation")
        op.drop_index("ix_vulnerability_remediation_vuln_id", table_name="vulnerability_remediation")
        op.drop_index("ix_vulnerability_remediation_project_id", table_name="vulnerability_remediation")
        op.drop_table("vulnerability_remediation")

    for column in (
        "maintenance_status",
        "is_deprecated",
        "eol_date",
        "eos_date",
        "lifecycle_status",
        "hashes",
        "license",
    ):
        if _table_exists(bind, "sbom_component") and _column_exists(bind, "sbom_component", column):
            op.drop_column("sbom_component", column)

    for column in (
        "completeness_report",
        "completeness_score",
        "change_summary",
        "parent_id",
    ):
        if _table_exists(bind, "sbom_source") and _column_exists(bind, "sbom_source", column):
            op.drop_column("sbom_source", column)
