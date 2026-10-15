"""Preserve structured lifecycle verification; invalidate historical fake health.

Revision ID: 079_lifecycle_provider_verification
Revises: 078_finding_reconciliation
"""
from alembic import op
import sqlalchemy as sa

revision = "079_lifecycle_provider_verification"
down_revision = "078_finding_reconciliation"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("lifecycle_provider_configs") as batch:
        batch.add_column(sa.Column("last_probe_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("last_lookup_at", sa.String(), nullable=True))
    # Preserve dates, config, secrets and audit history. Earlier success did not
    # prove a connection; require new verification under the structured contract.
    op.execute("UPDATE lifecycle_provider_configs SET health_status = CASE WHEN enabled THEN 'unknown' ELSE 'disabled' END")


def downgrade():
    with op.batch_alter_table("lifecycle_provider_configs") as batch:
        batch.drop_column("last_lookup_at")
        batch.drop_column("last_probe_json")
