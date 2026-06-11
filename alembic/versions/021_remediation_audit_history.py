"""Add remediation audit history.

Revision ID: 021_remediation_audit_history
Revises: 020_lifecycle_management_platform
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "021_remediation_audit_history"
down_revision = "020_lifecycle_management_platform"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "vulnerability_remediation_audit"):
        return

    op.create_table(
        "vulnerability_remediation_audit",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "remediation_id",
            sa.Integer(),
            sa.ForeignKey("vulnerability_remediation.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vuln_id", sa.String(), nullable=False),
        sa.Column("component_name", sa.String(), nullable=False),
        sa.Column("component_version", sa.String(), nullable=False),
        sa.Column("old_status", sa.String(), nullable=True),
        sa.Column("new_status", sa.String(), nullable=False),
        sa.Column("changed_by", sa.String(length=128), nullable=True),
        sa.Column("changed_at", sa.String(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_vulnerability_remediation_audit_remediation_id",
        "vulnerability_remediation_audit",
        ["remediation_id"],
    )
    op.create_index(
        "ix_vulnerability_remediation_audit_project_id",
        "vulnerability_remediation_audit",
        ["project_id"],
    )
    op.create_index(
        "ix_vulnerability_remediation_audit_vuln_id",
        "vulnerability_remediation_audit",
        ["vuln_id"],
    )
    op.create_index(
        "ix_vulnerability_remediation_audit_component_name",
        "vulnerability_remediation_audit",
        ["component_name"],
    )
    op.create_index(
        "ix_vulnerability_remediation_audit_changed_at",
        "vulnerability_remediation_audit",
        ["changed_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "vulnerability_remediation_audit"):
        return

    op.drop_index("ix_vulnerability_remediation_audit_changed_at", table_name="vulnerability_remediation_audit")
    op.drop_index("ix_vulnerability_remediation_audit_component_name", table_name="vulnerability_remediation_audit")
    op.drop_index("ix_vulnerability_remediation_audit_vuln_id", table_name="vulnerability_remediation_audit")
    op.drop_index("ix_vulnerability_remediation_audit_project_id", table_name="vulnerability_remediation_audit")
    op.drop_index("ix_vulnerability_remediation_audit_remediation_id", table_name="vulnerability_remediation_audit")
    op.drop_table("vulnerability_remediation_audit")
