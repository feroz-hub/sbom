"""Add large-file workspace metadata.

Revision ID: 039_validation_workspace_large_file
Revises: 038_validation_session_full_content
Create Date: 2026-06-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "039_validation_workspace_large_file"
down_revision = "038_validation_session_full_content"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    if not _table_exists(bind, table):
        return set()
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if column.name not in _columns(bind, table):
        op.add_column(table, column)


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "sbom_validation_sessions"):
        return

    for column in (
        sa.Column("storage_backend", sa.String(length=32), nullable=True),
        sa.Column("detection_confidence", sa.Float(), nullable=True),
        sa.Column("detection_evidence_json", sa.JSON(), nullable=True),
        sa.Column("is_large_file", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("full_editor_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
    ):
        _add_column_if_missing("sbom_validation_sessions", column)

    bind.execute(
        sa.text(
            """
            UPDATE sbom_validation_sessions
            SET
                storage_backend = COALESCE(storage_backend, CASE WHEN raw_storage_path IS NULL THEN 'db' ELSE 'filesystem' END),
                is_large_file = COALESCE(is_large_file, FALSE),
                full_editor_allowed = COALESCE(full_editor_allowed, TRUE)
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "sbom_validation_sessions"):
        return
    for column in (
        "full_editor_allowed",
        "is_large_file",
        "detection_evidence_json",
        "detection_confidence",
        "storage_backend",
    ):
        if column in _columns(bind, "sbom_validation_sessions"):
            op.drop_column("sbom_validation_sessions", column)
