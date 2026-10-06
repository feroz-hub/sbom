"""Retain immutable deterministic candidates separately from mutable drafts.

Revision ID: 074_sbom_repair_jobs
Revises: 073_sbom_operational_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "074_sbom_repair_jobs"
down_revision = "073_sbom_operational_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sbom_repair_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sbom_validation_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("original_sha256", sa.String(64), nullable=False),
        sa.Column("source_sbom_sha256", sa.String(64)),
        sa.Column("source_sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id")),
        sa.Column("candidate_sha256", sa.String(64), nullable=False),
        sa.Column("candidate_content", sa.Text(), nullable=False),
        sa.Column("report_json", sa.JSON(), nullable=False),
        sa.Column("validation_options_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("approval_status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("decided_at", sa.String()),
        sa.Column("actor_user_id", sa.String(128)),
        sa.Column("decided_by", sa.String(128)),
        sa.Column("imported_sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id")),
    )
    op.create_index("ix_sbom_repair_jobs_tenant_id", "sbom_repair_jobs", ["tenant_id"])
    op.create_index("ix_sbom_repair_jobs_session_id", "sbom_repair_jobs", ["session_id"])


def downgrade():
    op.drop_table("sbom_repair_jobs")
