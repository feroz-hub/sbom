"""Per-user report subscriptions; scope-specific uniqueness handles NULL targets."""

import sqlalchemy as sa
from alembic import op

revision = "051_report_subscription"
down_revision = "050_optional_external_tenant_mapping"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "report_subscription",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("iam_user_id", sa.Integer, sa.ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id", ondelete="CASCADE")),
        sa.Column("product_id", sa.Integer, sa.ForeignKey("products.id", ondelete="CASCADE")),
        sa.Column("sbom_id", sa.Integer, sa.ForeignKey("sbom_source.id", ondelete="CASCADE")),
        sa.Column("cadence", sa.String(16), nullable=False, server_default="DAILY"),
        sa.Column("parts", sa.String(16), nullable=False, server_default="A,B"),
        sa.Column("formats", sa.String(32), nullable=False, server_default="PDF,XLSX"),
        sa.Column("severity_floor", sa.String(16), nullable=False, server_default="ALL"),
        sa.Column("baseline_mode", sa.String(32), nullable=False, server_default="FIRST_RUN_OF_SBOM"),
        sa.Column("cross_version_target", sa.String(16), nullable=False, server_default="PARENT"),
        sa.Column("timezone", sa.String(64), nullable=False, server_default="UTC"),
        sa.Column("suppress_when_unchanged", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("deactivated_at", sa.DateTime(timezone=True)),
        sa.Column("deactivated_by", sa.String),
        sa.Column("last_delivered_at", sa.String),
        sa.Column("created_on", sa.String, nullable=False),
        sa.Column("created_by", sa.String),
        sa.Column("modified_on", sa.String),
        sa.Column("modified_by", sa.String),
        sa.CheckConstraint("scope IN ('TENANT','PROJECT','PRODUCT','SBOM')", name="report_scope"),
        sa.CheckConstraint(
            "(scope='TENANT' AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='PROJECT' AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='PRODUCT' AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)",
            name="report_target",
        ),
        sa.CheckConstraint("cadence IN ('ON_EVERY_RUN','DAILY','WEEKLY','MONTHLY')", name="report_cadence"),
        sa.CheckConstraint("severity_floor IN ('ALL','LOW','MEDIUM','HIGH','CRITICAL')", name="report_severity"),
    )
    for scope, column in [("TENANT", None), ("PROJECT", "project_id"), ("PRODUCT", "product_id"), ("SBOM", "sbom_id")]:
        op.create_index(
            f"uq_report_subscription_{scope.lower()}",
            "report_subscription",
            ["tenant_id", "iam_user_id"] + ([column] if column else []),
            unique=True,
            postgresql_where=sa.text(f"is_active AND scope = '{scope}'"),
            sqlite_where=sa.text(f"is_active = 1 AND scope = '{scope}'"),
        )
    for column in ["tenant_id", "iam_user_id"]:
        op.create_index(f"ix_report_subscription_{column}", "report_subscription", [column])


def downgrade():
    op.drop_table("report_subscription")
