"""Backfill analysis_run.sbom_name from sbom_source for legacy rows.

Revision ID: 040_backfill_analysis_run_sbom_names
Revises: 039_validation_workspace_large_file
Create Date: 2026-07-01

Why this exists
---------------
``analysis_run.sbom_name`` is a denormalised copy of the owning SBOM's name,
set at row-creation time by ``create_auto_report`` / the analyze routes. Rows
created before that column was populated carry NULL. This was previously
patched by a startup helper (``app.main._update_sbom_names``) that re-ran an
un-scoped ``UPDATE`` on *every* boot; that per-boot data write is retired in
favour of this one-time, idempotent migration (DB Schema Management Phase 4).

Idempotent & safe
-----------------
Only rows whose ``sbom_name`` is NULL and whose ``sbom_id`` resolves to a
``sbom_source`` with a non-NULL name are touched, so:
  * re-running is a no-op (already-filled rows are skipped),
  * orphaned rows are never set to NULL,
  * an empty ``analysis_run`` table updates 0 rows.
The correlated-subquery ``UPDATE`` is portable across SQLite and PostgreSQL.

No downgrade
------------
Backfilling a denormalised label is not meaningfully reversible; ``downgrade``
is an intentional no-op.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "040_backfill_analysis_run_sbom_names"
down_revision = "039_validation_workspace_large_file"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()
    if not (_table_exists(bind, "analysis_run") and _table_exists(bind, "sbom_source")):
        return
    bind.execute(
        sa.text(
            """
            UPDATE analysis_run
            SET sbom_name = (
                SELECT sbom_source.sbom_name
                FROM sbom_source
                WHERE sbom_source.id = analysis_run.sbom_id
            )
            WHERE sbom_name IS NULL
              AND EXISTS (
                  SELECT 1 FROM sbom_source
                  WHERE sbom_source.id = analysis_run.sbom_id
                    AND sbom_source.sbom_name IS NOT NULL
              )
            """
        )
    )


def downgrade() -> None:
    # Intentional no-op — backfilling a denormalised label is not reversible.
    pass
