"""Add SBOM validation repair session tables.

Revision ID: 024_validation_repair_sessions
Revises: 023_component_deduplication
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "024_validation_repair_sessions"
down_revision = "023_component_deduplication"
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

    if not _table_exists(bind, "sbom_validation_sessions"):
        op.create_table(
            "sbom_validation_sessions",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=True),
            sa.Column("user_id", sa.String(length=128), nullable=True),
            sa.Column("original_filename", sa.String(length=255), nullable=True),
            sa.Column("sbom_name", sa.String(length=255), nullable=True),
            sa.Column("sbom_type", sa.Integer(), sa.ForeignKey("sbom_type.id"), nullable=True),
            sa.Column("detected_format", sa.String(length=64), nullable=True),
            sa.Column("detected_version", sa.String(length=64), nullable=True),
            sa.Column("sanitized_content", sa.Text(), nullable=True),
            sa.Column("current_content", sa.Text(), nullable=True),
            sa.Column("validation_status", sa.String(length=32), nullable=False, server_default="failed"),
            sa.Column("latest_error_report_json", sa.JSON(), nullable=True),
            sa.Column("can_edit", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("can_ai_fix", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("security_blocked_reason", sa.Text(), nullable=True),
            sa.Column("content_sha256", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column("imported_sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id"), nullable=True),
        )

    if not _table_exists(bind, "sbom_validation_session_events"):
        op.create_table(
            "sbom_validation_session_events",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "session_id",
                sa.String(length=36),
                sa.ForeignKey("sbom_validation_sessions.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("actor_user_id", sa.String(length=128), nullable=True),
            sa.Column("timestamp", sa.String(), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("before_hash", sa.String(length=64), nullable=True),
            sa.Column("after_hash", sa.String(length=64), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=True),
        )

    for name, table, columns in (
        ("ix_sbom_validation_sessions_project_id", "sbom_validation_sessions", ["project_id"]),
        ("ix_sbom_validation_sessions_user_id", "sbom_validation_sessions", ["user_id"]),
        ("ix_sbom_validation_sessions_validation_status", "sbom_validation_sessions", ["validation_status"]),
        ("ix_sbom_validation_sessions_content_sha256", "sbom_validation_sessions", ["content_sha256"]),
        ("ix_sbom_validation_sessions_created_at", "sbom_validation_sessions", ["created_at"]),
        ("ix_sbom_validation_sessions_expires_at", "sbom_validation_sessions", ["expires_at"]),
        ("ix_sbom_validation_sessions_imported_sbom_id", "sbom_validation_sessions", ["imported_sbom_id"]),
        ("ix_sbom_validation_session_events_session_id", "sbom_validation_session_events", ["session_id"]),
        ("ix_sbom_validation_session_events_event_type", "sbom_validation_session_events", ["event_type"]),
        ("ix_sbom_validation_session_events_actor_user_id", "sbom_validation_session_events", ["actor_user_id"]),
        ("ix_sbom_validation_session_events_timestamp", "sbom_validation_session_events", ["timestamp"]),
    ):
        _create_index_if_missing(name, table, columns)


def downgrade() -> None:
    bind = op.get_bind()
    for name, table in (
        ("ix_sbom_validation_session_events_timestamp", "sbom_validation_session_events"),
        ("ix_sbom_validation_session_events_actor_user_id", "sbom_validation_session_events"),
        ("ix_sbom_validation_session_events_event_type", "sbom_validation_session_events"),
        ("ix_sbom_validation_session_events_session_id", "sbom_validation_session_events"),
        ("ix_sbom_validation_sessions_imported_sbom_id", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_expires_at", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_created_at", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_content_sha256", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_validation_status", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_user_id", "sbom_validation_sessions"),
        ("ix_sbom_validation_sessions_project_id", "sbom_validation_sessions"),
    ):
        if _table_exists(bind, table) and _index_exists(bind, table, name):
            op.drop_index(name, table_name=table)
    if _table_exists(bind, "sbom_validation_session_events"):
        op.drop_table("sbom_validation_session_events")
    if _table_exists(bind, "sbom_validation_sessions"):
        op.drop_table("sbom_validation_sessions")
