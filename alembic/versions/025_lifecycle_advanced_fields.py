"""Add advanced lifecycle enrichment fields.

Revision ID: 025_lifecycle_advanced_fields
Revises: 024_validation_repair_sessions
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "025_lifecycle_advanced_fields"
down_revision = "024_validation_repair_sessions"
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
    _add_column_if_missing("sbom_component", sa.Column("unsupported", sa.Boolean(), nullable=True, server_default=sa.false()))
    _add_column_if_missing("sbom_component", sa.Column("latest_version", sa.String(), nullable=True))

    _add_column_if_missing("component_lifecycle_cache", sa.Column("lookup_key", sa.String(), nullable=True))
    _add_column_if_missing("component_lifecycle_cache", sa.Column("cpe", sa.String(), nullable=True))
    _add_column_if_missing(
        "component_lifecycle_cache",
        sa.Column("unsupported", sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    _add_column_if_missing("component_lifecycle_cache", sa.Column("latest_version", sa.String(), nullable=True))
    _add_column_if_missing(
        "component_lifecycle_cache",
        sa.Column("is_stale", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    _create_index_if_missing("ix_component_lifecycle_cache_lookup_key", "component_lifecycle_cache", ["lookup_key"])
    _create_index_if_missing("ix_component_lifecycle_cache_cpe", "component_lifecycle_cache", ["cpe"])


def downgrade() -> None:
    bind = op.get_bind()
    for index_name in ("ix_component_lifecycle_cache_cpe", "ix_component_lifecycle_cache_lookup_key"):
        if _table_exists(bind, "component_lifecycle_cache") and _index_exists(bind, "component_lifecycle_cache", index_name):
            op.drop_index(index_name, table_name="component_lifecycle_cache")

    for table, columns in (
        ("component_lifecycle_cache", ("is_stale", "latest_version", "unsupported", "cpe", "lookup_key")),
        ("sbom_component", ("latest_version", "unsupported")),
    ):
        for column in columns:
            if _table_exists(bind, table) and _column_exists(bind, table, column):
                op.drop_column(table, column)
