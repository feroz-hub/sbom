"""Add document-level VEX discovery metadata.

Revision ID: 027_vex_discovery_metadata
Revises: 026_vex_lifecycle_enrichment
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "027_vex_discovery_metadata"
down_revision = "026_vex_lifecycle_enrichment"
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
    _add_column_if_missing("vex_documents", sa.Column("source_url", sa.String(), nullable=True))
    _add_column_if_missing("vex_documents", sa.Column("discovery_evidence_json", sa.JSON(), nullable=True))
    _add_column_if_missing("vex_documents", sa.Column("last_refresh_status", sa.String(), nullable=True))
    _add_column_if_missing("vex_documents", sa.Column("provider_errors_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    for column in ("provider_errors_json", "last_refresh_status", "discovery_evidence_json", "source_url"):
        if _column_exists(bind, "vex_documents", column):
            op.drop_column("vex_documents", column)
