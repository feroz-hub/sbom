"""Store full invalid SBOM repair content with integrity metadata.

Revision ID: 038_validation_session_full_content
Revises: 037_stage9_normalization_dedup
Create Date: 2026-06-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "038_validation_session_full_content"
down_revision = "037_stage9_normalization_dedup"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    if not _table_exists(bind, table):
        return set()
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _indexes(bind: sa.engine.Connection, table: str) -> set[str]:
    if not _table_exists(bind, table):
        return set()
    return {index["name"] for index in sa.inspect(bind).get_indexes(table)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    bind = op.get_bind()
    if column.name not in _columns(bind, table):
        op.add_column(table, column)


def _create_index_if_missing(index_name: str, table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    if _table_exists(bind, table) and index_name not in _indexes(bind, table):
        op.create_index(index_name, table, columns)


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "sbom_validation_sessions"):
        return

    for column in (
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("original_size_bytes", sa.Integer(), nullable=True),
        sa.Column("original_sha256", sa.String(length=64), nullable=True),
        sa.Column("stored_size_bytes", sa.Integer(), nullable=True),
        sa.Column("stored_sha256", sa.String(length=64), nullable=True),
        sa.Column("raw_content_text", sa.Text(), nullable=True),
        sa.Column("raw_content_blob", sa.LargeBinary(), nullable=True),
        sa.Column("raw_storage_path", sa.String(length=1024), nullable=True),
        sa.Column("repair_content_text", sa.Text(), nullable=True),
        sa.Column("repair_content_blob", sa.LargeBinary(), nullable=True),
        sa.Column("repair_storage_path", sa.String(length=1024), nullable=True),
        sa.Column("validation_errors_json", sa.JSON(), nullable=True),
        sa.Column("stage_results_json", sa.JSON(), nullable=True),
        sa.Column("total_lines", sa.Integer(), nullable=True),
    ):
        _add_column_if_missing("sbom_validation_sessions", column)

    bind.execute(
        sa.text(
            """
            UPDATE sbom_validation_sessions
            SET
                raw_content_text = COALESCE(raw_content_text, sanitized_content, current_content),
                repair_content_text = COALESCE(repair_content_text, current_content, sanitized_content),
                validation_errors_json = COALESCE(validation_errors_json, latest_error_report_json),
                stage_results_json = COALESCE(stage_results_json, latest_error_report_json),
                sha256 = COALESCE(sha256, content_sha256),
                original_sha256 = COALESCE(original_sha256, content_sha256),
                stored_sha256 = COALESCE(stored_sha256, content_sha256)
            """
        )
    )

    for name, columns in (
        ("ix_sbom_validation_sessions_sha256", ["sha256"]),
        ("ix_sbom_validation_sessions_original_sha256", ["original_sha256"]),
        ("ix_sbom_validation_sessions_stored_sha256", ["stored_sha256"]),
    ):
        _create_index_if_missing(name, "sbom_validation_sessions", columns)


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "sbom_validation_sessions"):
        return
    for name in (
        "ix_sbom_validation_sessions_stored_sha256",
        "ix_sbom_validation_sessions_original_sha256",
        "ix_sbom_validation_sessions_sha256",
    ):
        if name in _indexes(bind, "sbom_validation_sessions"):
            op.drop_index(name, table_name="sbom_validation_sessions")
    for column in (
        "total_lines",
        "stage_results_json",
        "validation_errors_json",
        "repair_storage_path",
        "repair_content_blob",
        "repair_content_text",
        "raw_storage_path",
        "raw_content_blob",
        "raw_content_text",
        "stored_sha256",
        "stored_size_bytes",
        "original_sha256",
        "original_size_bytes",
        "sha256",
        "file_size_bytes",
        "content_type",
    ):
        if column in _columns(bind, "sbom_validation_sessions"):
            op.drop_column("sbom_validation_sessions", column)
