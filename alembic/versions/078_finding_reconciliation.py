"""Retain structured provider evidence and enforce new canonical finding keys.

Nullable keys leave historical duplicate rows readable without a backfill.
No production records are modified. Review/deploy separately from development.
"""
import sqlalchemy as sa
from alembic import op

revision = "078_finding_reconciliation"
down_revision = "077_sbom_selection_mode"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("analysis_finding") as batch:
        batch.add_column(sa.Column("evidence_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("reconciliation_key", sa.String(64), nullable=True))
        batch.drop_constraint("uq_analysis_finding_run_vuln_cpe", type_="unique")
        batch.create_unique_constraint("uq_analysis_finding_run_reconciliation", ["analysis_run_id", "reconciliation_key"])


def downgrade():
    # Fail rather than discard findings if the old CPE constraint cannot hold.
    with op.batch_alter_table("analysis_finding") as batch:
        batch.create_unique_constraint("uq_analysis_finding_run_vuln_cpe", ["analysis_run_id", "vuln_id", "cpe"])
        batch.drop_constraint("uq_analysis_finding_run_reconciliation", type_="unique")
        batch.drop_column("reconciliation_key")
        batch.drop_column("evidence_json")
