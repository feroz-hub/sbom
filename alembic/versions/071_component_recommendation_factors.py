"""Secure Component Advisor candidate scoring factors.

FR-SCA-017: one row per scoring factor per candidate with policy version,
raw / normalized value, weight, contribution, missing-data treatment,
evidence source and time. Additive; nothing to backfill (existing
candidates are re-scored on their next evaluation). Downgrade drops the table.

Revision ID: 071_component_recommendation_factors
Revises: 070_component_recommendation_compatibility
"""

import sqlalchemy as sa
from alembic import op

revision = "071_component_recommendation_factors"
down_revision = "070_component_recommendation_compatibility"
branch_labels = None
depends_on = None

TABLE = "component_recommendation_factor"


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
        sa.Column("factor", sa.String(32), nullable=False),
        sa.Column("raw_value_json", sa.JSON(), nullable=True),
        sa.Column("normalized_value", sa.Float(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("contribution", sa.Float(), nullable=False),
        sa.Column("missing_data_treatment", sa.String(16), nullable=True),
        sa.Column("evidence_source", sa.String(128), nullable=False),
        sa.Column("evidence_at", sa.String(64), nullable=True),
        sa.Column("policy_version_id", sa.Integer(), sa.ForeignKey("advisor_policy_version.id"), nullable=True),
        sa.Column("policy_version_label", sa.String(64), nullable=False),
    )
    op.create_index(f"ix_{TABLE}_tenant_id", TABLE, ["tenant_id"])
    op.create_index(f"ix_{TABLE}_candidate_id", TABLE, ["candidate_id"])
    op.create_index(f"ix_{TABLE}_tenant_identity", TABLE, ["tenant_id", "id"])


def downgrade():
    if TABLE in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table(TABLE)
