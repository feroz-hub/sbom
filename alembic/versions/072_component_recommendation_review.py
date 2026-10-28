"""Secure Component Advisor human review and append-only audit events.

FR-SCA-021 / FR-SCA-022 / NFR-SCA-007: ``component_recommendation_event``
(append-only; ORM guard rejects update/delete) and review-state columns on
``component_recommendation``. Additive; existing items get NULL review state
(nothing decided yet). Downgrade drops the table and columns — audit history
is lost, so back up first.

Revision ID: 072_component_recommendation_review
Revises: 071_component_recommendation_factors
"""

import sqlalchemy as sa
from alembic import op

revision = "072_component_recommendation_review"
down_revision = "071_component_recommendation_factors"
branch_labels = None
depends_on = None

TABLE = "component_recommendation_event"
COLUMNS = (
    ("recommended_candidate_id", sa.Integer()),
    ("accepted_candidate_id", sa.Integer()),
    ("last_decision", sa.String(32)),
    ("last_decision_reason", sa.Text()),
    ("decided_by", sa.String(128)),
    ("decided_at", sa.DateTime(timezone=True)),
)


def upgrade():
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("component_recommendation")}
    with op.batch_alter_table("component_recommendation") as batch:
        for name, type_ in COLUMNS:
            if name not in existing:
                batch.add_column(sa.Column(name, type_, nullable=True))
    if TABLE in set(sa.inspect(bind).get_table_names()):
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("recommendation_id", sa.Integer(), sa.ForeignKey("component_recommendation.id"), nullable=True),
        sa.Column("candidate_id", sa.Integer(), nullable=True),
        sa.Column("candidate_json", sa.JSON(), nullable=True),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("decision", sa.String(32), nullable=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("old_status", sa.String(32), nullable=True),
        sa.Column("new_status", sa.String(32), nullable=True),
        sa.Column("policy_versions_json", sa.JSON(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("confidence", sa.String(32), nullable=True),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("tenant_id", "recommendation_id", "action", "correlation_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index(f"ix_{TABLE}_tenant_identity", TABLE, ["tenant_id", "id"])
    op.create_index(f"ix_{TABLE}_tenant_created", TABLE, ["tenant_id", "created_at"])


def downgrade():
    bind = op.get_bind()
    if TABLE in set(sa.inspect(bind).get_table_names()):
        op.drop_table(TABLE)
    existing = {c["name"] for c in sa.inspect(bind).get_columns("component_recommendation")}
    with op.batch_alter_table("component_recommendation") as batch:
        for name, _type in COLUMNS:
            if name in existing:
                batch.drop_column(name)
