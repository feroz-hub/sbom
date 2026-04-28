"""nvd mirror tables — Phase 2 schema additions.

Revision ID: 002_nvd_mirror_tables
Revises: 001_initial_schema
Create Date: 2026-04-28

Adds three new tables (`nvd_settings`, `cves`, `nvd_sync_runs`) plus the
PostgreSQL-only GIN index on `cves.cpe_match`.

Idempotency: this migration is safe to apply against a fresh database
where `001_initial_schema` already ran `Base.metadata.create_all` (which,
after env.py was updated to register the mirror models, creates these
tables itself). Each `op.create_table` call is guarded by an inspector
existence check.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "002_nvd_mirror_tables"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


# JSON column type — JSONB on PostgreSQL, plain JSON on SQLite.
def _json_type() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {
            ix["name"] for ix in sa.inspect(bind).get_indexes(table)
        }
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    # ---------------- nvd_settings ----------------
    if not _table_exists(bind, "nvd_settings"):
        op.create_table(
            "nvd_settings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column(
                "api_endpoint",
                sa.Text(),
                nullable=False,
                server_default=sa.text(
                    "'https://services.nvd.nist.gov/rest/json/cves/2.0'"
                ),
            ),
            sa.Column("api_key_ciphertext", sa.LargeBinary(), nullable=True),
            sa.Column(
                "download_feeds_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column(
                "page_size", sa.Integer(), nullable=False, server_default=sa.text("2000")
            ),
            sa.Column(
                "window_days", sa.Integer(), nullable=False, server_default=sa.text("119")
            ),
            sa.Column(
                "min_freshness_hours",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("24"),
            ),
            sa.Column("last_modified_utc", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "last_successful_sync_at", sa.DateTime(timezone=True), nullable=True
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.CheckConstraint("id = 1", name="ck_nvd_settings_singleton"),
            sa.CheckConstraint(
                "page_size BETWEEN 1 AND 2000",
                name="ck_nvd_settings_page_size_range",
            ),
            sa.CheckConstraint(
                "window_days BETWEEN 1 AND 119",
                name="ck_nvd_settings_window_days_range",
            ),
            sa.CheckConstraint(
                "min_freshness_hours >= 0",
                name="ck_nvd_settings_min_freshness_nonneg",
            ),
        )

    # ---------------- cves ----------------
    if not _table_exists(bind, "cves"):
        op.create_table(
            "cves",
            sa.Column("cve_id", sa.Text(), primary_key=True),
            sa.Column("last_modified", sa.DateTime(timezone=True), nullable=False),
            sa.Column("published", sa.DateTime(timezone=True), nullable=False),
            sa.Column("vuln_status", sa.Text(), nullable=False),
            sa.Column("description_en", sa.Text(), nullable=True),
            sa.Column("score_v40", sa.Float(), nullable=True),
            sa.Column("score_v31", sa.Float(), nullable=True),
            sa.Column("score_v2", sa.Float(), nullable=True),
            sa.Column("severity_text", sa.String(length=32), nullable=True),
            sa.Column("vector_string", sa.Text(), nullable=True),
            sa.Column("aliases", _json_type(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column(
                "cpe_match", _json_type(), nullable=False, server_default=sa.text("'[]'")
            ),
            sa.Column(
                "references", _json_type(), nullable=False, server_default=sa.text("'[]'")
            ),
            sa.Column("data", _json_type(), nullable=False),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_cves_last_modified", "cves", ["last_modified"], unique=False)
        op.create_index("ix_cves_vuln_status", "cves", ["vuln_status"], unique=False)
    else:
        # Tables created by Base.metadata.create_all (e.g. via main.py
        # startup) already include the BTREE indexes declared on the ORM
        # model. Guard against double-create regardless.
        if not _index_exists(bind, "cves", "ix_cves_last_modified"):
            op.create_index("ix_cves_last_modified", "cves", ["last_modified"], unique=False)
        if not _index_exists(bind, "cves", "ix_cves_vuln_status"):
            op.create_index("ix_cves_vuln_status", "cves", ["vuln_status"], unique=False)

    # PostgreSQL-only: GIN index on cpe_match (JSONB) for criteria_stem
    # candidate selection. SQLite has no equivalent and would crash here.
    if bind.dialect.name == "postgresql" and not _index_exists(
        bind, "cves", "ix_cves_cpe_match_gin"
    ):
        op.create_index(
            "ix_cves_cpe_match_gin",
            "cves",
            ["cpe_match"],
            unique=False,
            postgresql_using="gin",
            postgresql_ops={"cpe_match": "jsonb_path_ops"},
        )

    # ---------------- nvd_sync_runs ----------------
    if not _table_exists(bind, "nvd_sync_runs"):
        op.create_table(
            "nvd_sync_runs",
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("run_kind", sa.String(length=16), nullable=False),
            sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "started_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "status",
                sa.String(length=16),
                nullable=False,
                server_default=sa.text("'running'"),
            ),
            sa.Column(
                "upserted_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.CheckConstraint(
                "run_kind IN ('bootstrap','incremental')",
                name="ck_nvd_sync_runs_kind",
            ),
            sa.CheckConstraint(
                "status IN ('running','success','failed','aborted')",
                name="ck_nvd_sync_runs_status",
            ),
        )
        op.create_index(
            "ix_nvd_sync_runs_started_at", "nvd_sync_runs", ["started_at"], unique=False
        )
    else:
        if not _index_exists(bind, "nvd_sync_runs", "ix_nvd_sync_runs_started_at"):
            op.create_index(
                "ix_nvd_sync_runs_started_at",
                "nvd_sync_runs",
                ["started_at"],
                unique=False,
            )


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql" and _index_exists(
        bind, "cves", "ix_cves_cpe_match_gin"
    ):
        op.drop_index("ix_cves_cpe_match_gin", table_name="cves")

    if _table_exists(bind, "nvd_sync_runs"):
        op.drop_table("nvd_sync_runs")
    if _table_exists(bind, "cves"):
        op.drop_table("cves")
    if _table_exists(bind, "nvd_settings"):
        op.drop_table("nvd_settings")
