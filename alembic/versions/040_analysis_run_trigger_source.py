"""Add analysis run trigger source.

Revision ID: 040_analysis_run_trigger_source
Revises: 039_validation_workspace_large_file
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "040_analysis_run_trigger_source"
down_revision = "039_validation_workspace_large_file"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    if not _table_exists(bind, table):
        return set()
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "analysis_run"):
        return
    if "trigger_source" not in _columns(bind, "analysis_run"):
        op.add_column(
            "analysis_run",
            sa.Column("trigger_source", sa.String(length=32), nullable=False, server_default="unknown"),
        )
        op.create_index("ix_analysis_run_trigger_source", "analysis_run", ["trigger_source"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "analysis_run"):
        return
    if "trigger_source" in _columns(bind, "analysis_run"):
        op.drop_index("ix_analysis_run_trigger_source", table_name="analysis_run")
        op.drop_column("analysis_run", "trigger_source")
