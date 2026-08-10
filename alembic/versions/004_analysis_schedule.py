"""analysis_schedule — periodic analysis scheduling.

Revision ID: 004_analysis_schedule
Revises: 003_kev_epss_cache
Create Date: 2026-04-29

Adds the ``analysis_schedule`` table that backs the new periodic-analysis
feature (rescan an SBOM, or every SBOM in a project, on a fixed cadence —
daily / weekly / bi-weekly / monthly / quarterly / custom-cron).

Design (see Plan):
  * One row per scope target (PROJECT or SBOM); SBOM-level overrides cascade
    over the project-level default at resolve time.
  * The Celery beat fires a single tick task every 15 minutes that scans
    ``WHERE enabled = true AND next_run_at <= now()``; the scheduler does
    not need a beat entry per row, so adding/editing a schedule is a plain
    DB write — no worker restart.

Idempotency: existence-checked, mirrors the pattern in 002 / 003.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "004_analysis_schedule"
down_revision = "003_kev_epss_cache"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, "analysis_schedule"):
        op.create_table(
            "analysis_schedule",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column("scope", sa.String(length=16), nullable=False),
            sa.Column(
                "project_id",
                sa.Integer(),
                sa.ForeignKey("projects.id", ondelete="CASCADE"),
                nullable=True,
                index=True,
            ),
            sa.Column(
                "sbom_id",
                sa.Integer(),
                sa.ForeignKey("sbom_source.id", ondelete="CASCADE"),
                nullable=True,
                index=True,
            ),
            sa.Column("cadence", sa.String(length=16), nullable=False),
            sa.Column("cron_expression", sa.String(length=128), nullable=True),
            sa.Column("day_of_week", sa.Integer(), nullable=True),
            sa.Column("day_of_month", sa.Integer(), nullable=True),
            sa.Column(
                "hour_utc",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("2"),
            ),
            sa.Column(
                "timezone",
                sa.String(length=64),
                nullable=False,
                server_default=sa.text("'UTC'"),
            ),
            sa.Column(
                "enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
            sa.Column("next_run_at", sa.String(), nullable=True, index=True),
            sa.Column("last_run_at", sa.String(), nullable=True),
            sa.Column("last_run_status", sa.String(length=16), nullable=True),
            sa.Column(
                "last_run_id",
                sa.Integer(),
                sa.ForeignKey("analysis_run.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "consecutive_failures",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "min_gap_minutes",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("60"),
            ),
            sa.Column("created_on", sa.String(), nullable=True),
            sa.Column("created_by", sa.String(), nullable=True),
            sa.Column("modified_on", sa.String(), nullable=True),
            sa.Column("modified_by", sa.String(), nullable=True),
            sa.CheckConstraint(
                "scope IN ('PROJECT','SBOM')",
                name="ck_analysis_schedule_scope",
            ),
            sa.CheckConstraint(
                "cadence IN ('DAILY','WEEKLY','BIWEEKLY','MONTHLY','QUARTERLY','CUSTOM')",
                name="ck_analysis_schedule_cadence",
            ),
            sa.CheckConstraint(
                "(scope = 'PROJECT' AND project_id IS NOT NULL AND sbom_id IS NULL) "
                "OR (scope = 'SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL)",
                name="ck_analysis_schedule_target",
            ),
            sa.CheckConstraint(
                "hour_utc BETWEEN 0 AND 23",
                name="ck_analysis_schedule_hour_range",
            ),
            sa.CheckConstraint(
                "day_of_week IS NULL OR day_of_week BETWEEN 0 AND 6",
                name="ck_analysis_schedule_dow_range",
            ),
            sa.CheckConstraint(
                "day_of_month IS NULL OR day_of_month BETWEEN 1 AND 28",
                name="ck_analysis_schedule_dom_range",
            ),
        )

        # One schedule per (scope, target) — partial unique indexes
        # because SQLite + PG both treat NULLs as distinct in regular
        # UNIQUE constraints, which would let duplicates through.
        op.create_index(
            "uq_analysis_schedule_project",
            "analysis_schedule",
            ["project_id"],
            unique=True,
            sqlite_where=sa.text("scope = 'PROJECT'"),
            postgresql_where=sa.text("scope = 'PROJECT'"),
        )
        op.create_index(
            "uq_analysis_schedule_sbom",
            "analysis_schedule",
            ["sbom_id"],
            unique=True,
            sqlite_where=sa.text("scope = 'SBOM'"),
            postgresql_where=sa.text("scope = 'SBOM'"),
        )
        op.create_index(
            "ix_analysis_schedule_due",
            "analysis_schedule",
            ["enabled", "next_run_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "analysis_schedule"):
        if _index_exists(bind, "analysis_schedule", "ix_analysis_schedule_due"):
            op.drop_index("ix_analysis_schedule_due", table_name="analysis_schedule")
        if _index_exists(bind, "analysis_schedule", "uq_analysis_schedule_sbom"):
            op.drop_index("uq_analysis_schedule_sbom", table_name="analysis_schedule")
        if _index_exists(bind, "analysis_schedule", "uq_analysis_schedule_project"):
            op.drop_index("uq_analysis_schedule_project", table_name="analysis_schedule")
        op.drop_table("analysis_schedule")
