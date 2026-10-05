"""Separate operational SBOM lifecycle from soft deletion; preserve all history.

Revision ID: 073_sbom_operational_lifecycle
Revises: 072_component_recommendation_review
"""
import sqlalchemy as sa
from alembic import op

revision = "073_sbom_operational_lifecycle"
down_revision = "072_component_recommendation_review"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("sbom_source") as batch:
        batch.add_column(sa.Column("lifecycle_status", sa.String(8), nullable=False, server_default="ACTIVE"))
        batch.add_column(sa.Column("lifecycle_revision", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("analysis_requires_reanalysis", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.create_index("ix_sbom_source_lifecycle_status", ["lifecycle_status"])
        batch.create_check_constraint("sbom_operational_lifecycle", "lifecycle_status IN ('ACTIVE','INACTIVE')")
    with op.batch_alter_table("analysis_run") as batch:
        batch.add_column(sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("analysis_input_fingerprint", sa.JSON(), nullable=True))
        batch.create_index("ix_analysis_run_is_current", ["is_current"])


def downgrade():
    with op.batch_alter_table("analysis_run") as batch:
        batch.drop_index("ix_analysis_run_is_current")
        batch.drop_column("analysis_input_fingerprint")
        batch.drop_column("is_current")
    with op.batch_alter_table("sbom_source") as batch:
        batch.drop_constraint("sbom_operational_lifecycle", type_="check")
        batch.drop_index("ix_sbom_source_lifecycle_status")
        batch.drop_column("analysis_requires_reanalysis")
        batch.drop_column("lifecycle_revision")
        batch.drop_column("lifecycle_status")
