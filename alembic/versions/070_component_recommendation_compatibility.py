"""Secure Component Advisor candidate compatibility checks.

FR-SCA-014 / FR-SCA-015: one row per check type per candidate, with result
(PASS / FAIL / REVIEW_REQUIRED / UNKNOWN), evidence, reason, limitation,
blocking flag and evaluation time. Additive; nothing to backfill. Downgrade
drops the table.

Revision ID: 070_component_recommendation_compatibility
Revises: 069_component_recommendations
"""

import sqlalchemy as sa
from alembic import op

revision = "070_component_recommendation_compatibility"
down_revision = "069_component_recommendations"
branch_labels = None
depends_on = None

TABLE = "component_recommendation_compatibility_check"


def upgrade():
    if TABLE in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "candidate_id", sa.Integer(),
            sa.ForeignKey("component_recommendation_candidate.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("check_type", sa.String(32), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("blocking", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("limitation", sa.String(64), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(f"ix_{TABLE}_tenant_id", TABLE, ["tenant_id"])
    op.create_index(f"ix_{TABLE}_candidate_id", TABLE, ["candidate_id"])
    op.create_index(f"ix_{TABLE}_tenant_identity", TABLE, ["tenant_id", "id"])


def downgrade():
    if TABLE in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table(TABLE)
