"""rename run_status: FAIL -> FINDINGS, PASS -> OK

Revision ID: 005_rename_run_status
Revises: 004_analysis_schedule
Create Date: 2026-04-30

Background
----------
``compute_report_status`` historically returned ``"FAIL"`` whenever a run
produced one or more findings — i.e. *successful* analysis with security
output. The label collapsed two unrelated meanings ("the analyzer broke"
vs. "the analyzer succeeded and found CVEs") into a single string that
paints red everywhere it appears, which led the home dashboard to claim a
"FAIL · FAIL" run history that was never actually a pipeline outage.

ADR-0001 renames the run-status enum:

    PASS -> OK
    FAIL -> FINDINGS

``ERROR`` keeps its meaning (real technical failure). All other values
(PARTIAL / RUNNING / PENDING / NO_DATA) are unchanged.

This migration is idempotent: it only updates rows whose value still
matches the legacy spelling.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005_rename_run_status"
down_revision = "004_analysis_schedule"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "analysis_run"):
        bind.execute(
            sa.text("UPDATE analysis_run SET run_status = 'FINDINGS' WHERE run_status = 'FAIL'")
        )
        bind.execute(
            sa.text("UPDATE analysis_run SET run_status = 'OK' WHERE run_status = 'PASS'")
        )

    if _table_exists(bind, "analysis_schedule"):
        bind.execute(
            sa.text(
                "UPDATE analysis_schedule SET last_run_status = 'FINDINGS' "
                "WHERE last_run_status = 'FAIL'"
            )
        )
        bind.execute(
            sa.text(
                "UPDATE analysis_schedule SET last_run_status = 'OK' "
                "WHERE last_run_status = 'PASS'"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "analysis_run"):
        bind.execute(
            sa.text("UPDATE analysis_run SET run_status = 'FAIL' WHERE run_status = 'FINDINGS'")
        )
        bind.execute(
            sa.text("UPDATE analysis_run SET run_status = 'PASS' WHERE run_status = 'OK'")
        )

    if _table_exists(bind, "analysis_schedule"):
        bind.execute(
            sa.text(
                "UPDATE analysis_schedule SET last_run_status = 'FAIL' "
                "WHERE last_run_status = 'FINDINGS'"
            )
        )
        bind.execute(
            sa.text(
                "UPDATE analysis_schedule SET last_run_status = 'PASS' "
                "WHERE last_run_status = 'OK'"
            )
        )
