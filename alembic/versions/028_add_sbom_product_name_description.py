"""Add product_name and description to sbom_source.

Revision ID: 028_add_sbom_product_name_description
Revises: 027_vex_discovery_metadata
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "028_add_sbom_product_name_description"
down_revision = "027_vex_discovery_metadata"
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
    _add_column_if_missing("sbom_source", sa.Column("product_name", sa.String(), nullable=True))
    _add_column_if_missing("sbom_source", sa.Column("description", sa.String(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if _column_exists(bind, "sbom_source", "product_name"):
        op.drop_column("sbom_source", "product_name")
    if _column_exists(bind, "sbom_source", "description"):
        op.drop_column("sbom_source", "description")
