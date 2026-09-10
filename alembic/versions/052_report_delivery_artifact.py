"""Durable report outbox and retained private artifacts."""

import sqlalchemy as sa
from alembic import op

revision = "052_report_delivery_artifact"
down_revision = "051_report_subscription"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "report_delivery",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "subscription_id", sa.Integer, sa.ForeignKey("report_subscription.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("cycle_start", sa.String, nullable=False),
        sa.Column("cycle_end", sa.String, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("recipient_email", sa.String(320)),
        sa.Column("sbom_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("run_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("artifact_ids", sa.JSON, nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("attempts", sa.JSON, nullable=False),
        sa.Column("next_attempt_at", sa.String),
        sa.Column("claimed_at", sa.String),
        sa.Column("dispatch_started_at", sa.String),
        sa.Column("sent_at", sa.String),
        sa.Column("created_on", sa.String, nullable=False),
        sa.UniqueConstraint("subscription_id", "cycle_start", "cycle_end", name="uq_report_delivery_cycle"),
        sa.CheckConstraint(
            "status IN ('PENDING','SENT','FAILED','SKIPPED','SUPPRESSED')", name="report_delivery_status"
        ),
    )
    for col in ["tenant_id", "subscription_id", "status"]:
        op.create_index(f"ix_report_delivery_{col}", "report_delivery", [col])
    op.create_index("ix_report_delivery_tenant_dispatch", "report_delivery", ["tenant_id", "dispatch_started_at"])
    op.create_table(
        "report_artifact",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("delivery_id", sa.Integer, sa.ForeignKey("report_delivery.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("storage_path", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.String, nullable=False),
        sa.Column("created_on", sa.String, nullable=False),
        sa.CheckConstraint("kind IN ('PDF','XLSX','JSON')", name="report_artifact_kind"),
    )
    for col in ["tenant_id", "delivery_id", "expires_at"]:
        op.create_index(f"ix_report_artifact_{col}", "report_artifact", [col])


def downgrade():
    op.drop_table("report_artifact")
    op.drop_table("report_delivery")
