"""Add tenant schedules without altering existing schedule targets."""

import sqlalchemy as sa
from alembic import op

revision = "053_tenant_analysis_schedule"
down_revision = "052_report_delivery_artifact"
branch_labels = depends_on = None


def _constraints(tenant):
    names = {c["name"] for c in sa.inspect(op.get_bind()).get_check_constraints("analysis_schedule")}
    with op.batch_alter_table("analysis_schedule") as batch:
        for suffix in ["scope", "target"]:
            for name in [f"ck_analysis_schedule_{suffix}", f"ck_analysis_schedule_ck_analysis_schedule_{suffix}"]:
                if name in names:
                    batch.drop_constraint(op.f(name), type_="check")
        batch.create_check_constraint(
            op.f("ck_analysis_schedule_ck_analysis_schedule_scope"),
            "scope IN ('TENANT','PROJECT','PRODUCT','SBOM')" if tenant else "scope IN ('PROJECT','PRODUCT','SBOM')",
        )
        target = (
            "(scope='PROJECT' AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='PRODUCT' AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)"
        )
        if tenant:
            target += " OR (scope='TENANT' AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL)"
        batch.create_check_constraint(op.f("ck_analysis_schedule_ck_analysis_schedule_target"), target)


def upgrade():
    _constraints(True)
    op.create_index(
        "uq_analysis_schedule_tenant",
        "analysis_schedule",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("scope='TENANT' AND is_active"),
        sqlite_where=sa.text("scope='TENANT' AND is_active=1"),
    )


def downgrade():
    if op.get_bind().execute(sa.text("SELECT COUNT(*) FROM analysis_schedule WHERE scope='TENANT'")).scalar_one():
        raise RuntimeError("Remove tenant schedules before downgrading; no schedules were deleted.")
    op.drop_index("uq_analysis_schedule_tenant", table_name="analysis_schedule")
    _constraints(False)
