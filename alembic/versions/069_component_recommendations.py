"""Secure Component Advisor recommendation work items and candidates.

FR-SCA-011 / FR-SCA-013. ``component_recommendation`` (tenant-owned work
item with a partial unique index that allows one open item per context) and
``component_recommendation_candidate``. Factor, compatibility-check and
decision-event tables arrive with Steps 6–8 in later migrations.

Additive; nothing to backfill. Downgrade drops both tables (recommendation
history is lost — back up first).

Revision ID: 069_component_recommendations
Revises: 068_component_advisor_policies
"""

import sqlalchemy as sa
from alembic import op

revision = "069_component_recommendations"
down_revision = "068_component_advisor_policies"
branch_labels = None
depends_on = None

OPEN_STATUSES = "status IN ('OPEN','EVALUATING','REVIEW_REQUIRED','RECOMMENDED')"


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    tz = sa.DateTime(timezone=True)

    if "component_recommendation" not in tables:
        op.create_table(
            "component_recommendation",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
            sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="SET NULL"), nullable=True),
            sa.Column("sbom_id", sa.Integer(), sa.ForeignKey("sbom_source.id", ondelete="SET NULL"), nullable=True),
            sa.Column("scope_key", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("source_component_id", sa.Integer(), sa.ForeignKey("sbom_component.id", ondelete="SET NULL"), nullable=True),
            sa.Column("source_canonical_key", sa.String(80), nullable=False),
            sa.Column("source_family_key", sa.String(512), nullable=True),
            sa.Column("source_name", sa.String(512), nullable=False),
            sa.Column("source_version", sa.String(255), nullable=True),
            sa.Column("source_ecosystem", sa.String(64), nullable=True),
            sa.Column("trigger_type", sa.String(32), nullable=False),
            sa.Column("trigger_evidence_json", sa.JSON(), nullable=True),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("discovery_summary_json", sa.JSON(), nullable=True),
            sa.Column("evaluation_error", sa.Text(), nullable=True),
            sa.Column("correlation_id", sa.String(128), nullable=True),
            sa.Column("created_by", sa.String(128), nullable=True),
            sa.Column("created_at", tz, nullable=False),
            sa.Column("updated_at", tz, nullable=False),
            sa.Column("evaluated_at", tz, nullable=True),
            sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        )
        for column in ("tenant_id", "project_id", "product_id", "sbom_id", "source_canonical_key",
                       "source_family_key", "status", "correlation_id"):
            op.create_index(f"ix_component_recommendation_{column}", "component_recommendation", [column])
        op.create_index("ix_component_recommendation_tenant_status", "component_recommendation", ["tenant_id", "status"])
        op.create_index("ix_component_recommendation_tenant_identity", "component_recommendation", ["tenant_id", "id"])
        op.create_index(
            "uq_component_recommendation_open", "component_recommendation",
            ["tenant_id", "source_canonical_key", "scope_key", "trigger_type"], unique=True,
            postgresql_where=sa.text(OPEN_STATUSES), sqlite_where=sa.text(OPEN_STATUSES),
        )

    if "component_recommendation_candidate" not in tables:
        op.create_table(
            "component_recommendation_candidate",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column(
                "recommendation_id", sa.Integer(),
                sa.ForeignKey("component_recommendation.id", ondelete="CASCADE"), nullable=False,
            ),
            sa.Column("candidate_kind", sa.String(32), nullable=False),
            sa.Column("source_type", sa.String(32), nullable=False),
            sa.Column("candidate_canonical_key", sa.String(80), nullable=True),
            sa.Column("name", sa.String(512), nullable=False),
            sa.Column("version", sa.String(255), nullable=True),
            sa.Column("purl", sa.String(1024), nullable=True),
            sa.Column("ecosystem", sa.String(64), nullable=True),
            sa.Column("rank", sa.Integer(), nullable=False),
            sa.Column("evidence_sources_json", sa.JSON(), nullable=False),
            sa.Column("reasons_json", sa.JSON(), nullable=False),
            sa.Column("limitations_json", sa.JSON(), nullable=False),
            sa.Column("evaluation_json", sa.JSON(), nullable=False),
            sa.Column("score", sa.Float(), nullable=True),
            sa.Column("confidence", sa.String(32), nullable=True),
            sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_at", tz, nullable=False),
        )
        op.create_index("ix_component_recommendation_candidate_tenant_id", "component_recommendation_candidate", ["tenant_id"])
        op.create_index(
            "ix_component_recommendation_candidate_recommendation_id", "component_recommendation_candidate", ["recommendation_id"]
        )
        op.create_index(
            "ix_component_recommendation_candidate_tenant_identity", "component_recommendation_candidate", ["tenant_id", "id"]
        )


def downgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for table in ("component_recommendation_candidate", "component_recommendation"):
        if table in tables:
            op.drop_table(table)
