"""Persist AUTO versus administrator pin; preserve ambiguous legacy choices."""
import sqlalchemy as sa
from alembic import op

revision = "077_sbom_selection_mode"
down_revision = "076_logical_sbom_versions"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("products", sa.Column("current_sbom_mode", sa.String(16), nullable=False, server_default="AUTO"))
    op.execute("UPDATE products SET current_sbom_mode = 'MANUAL_PIN' WHERE current_sbom_id IS NOT NULL")
    with op.batch_alter_table("products") as batch:
        batch.create_check_constraint("ck_products_current_sbom_mode", "current_sbom_mode IN ('AUTO','MANUAL_PIN')")
    op.create_table(
        "vex_investigation_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=False),
        sa.Column("analysis_run_id", sa.Integer(), sa.ForeignKey("analysis_run.id", ondelete="CASCADE"), nullable=False),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("vex_investigation.id", ondelete="CASCADE"), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("captured_at", sa.String(), nullable=False),
        sa.UniqueConstraint("analysis_run_id", "investigation_id", name="uq_vex_run_context_snapshot"),
    )
    for column in ("tenant_id", "sbom_id", "analysis_run_id"):
        op.create_index(f"ix_vex_investigation_snapshot_{column}", "vex_investigation_snapshot", [column])


def downgrade():
    op.drop_table("vex_investigation_snapshot")
    with op.batch_alter_table("products") as batch:
        batch.drop_constraint("ck_products_current_sbom_mode", type_="check")
        batch.drop_column("current_sbom_mode")
