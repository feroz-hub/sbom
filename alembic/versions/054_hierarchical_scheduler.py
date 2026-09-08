"""Add explicit current-SBOM and hierarchical scheduler policy fields.

Revision ID: 054_hierarchical_scheduler
Revises: 053_tenant_analysis_schedule
Create Date: 2026-09-07

Existing schedules remain CUSTOM and default to CURRENT_ONLY.  Products are
not backfilled to an arbitrary SBOM: version strings are not safely sortable,
so administrators can select the current SBOM explicitly.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "054_hierarchical_scheduler"
down_revision = "053_tenant_analysis_schedule"
branch_labels = None
depends_on = None

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Alembic's SQLite batch mode reflects existing named checks before rebuilding
# the table.  Keep those names stable during downgrade instead of applying the
# project's ``ck_<table>_<constraint>`` convention to them a second time.
REFLECT_NAMING = {**NAMING, "ck": "%(constraint_name)s"}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    product_columns = {column["name"] for column in inspector.get_columns("products")}
    schedule_columns = {column["name"] for column in inspector.get_columns("analysis_schedule")}

    if "current_sbom_id" not in product_columns:
        op.add_column("products", sa.Column("current_sbom_id", sa.Integer(), nullable=True))
    inspector = sa.inspect(bind)
    current_fk_exists = any(
        fk["constrained_columns"] == ["current_sbom_id"]
        for fk in inspector.get_foreign_keys("products")
    )
    if not current_fk_exists:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("products", naming_convention=NAMING) as batch:
                batch.create_foreign_key(
                    "fk_products_current_sbom_id_sbom_source",
                    "sbom_source",
                    ["current_sbom_id"],
                    ["id"],
                    ondelete="SET NULL",
                )
        else:
            op.create_foreign_key(
                "fk_products_current_sbom_id_sbom_source",
                "products",
                "sbom_source",
                ["current_sbom_id"],
                ["id"],
                ondelete="SET NULL",
            )
    if "ix_products_current_sbom_id" not in {
        index["name"] for index in sa.inspect(bind).get_indexes("products")
    }:
        op.create_index("ix_products_current_sbom_id", "products", ["current_sbom_id"])

    if "mode" not in schedule_columns:
        op.add_column(
            "analysis_schedule",
            sa.Column("mode", sa.String(length=16), nullable=False, server_default="CUSTOM"),
        )
    if "target_version_policy" not in schedule_columns:
        op.add_column(
            "analysis_schedule",
            sa.Column(
                "target_version_policy",
                sa.String(length=32),
                nullable=False,
                server_default="CURRENT_ONLY",
            ),
        )
    check_names = {
        constraint["name"]
        for constraint in sa.inspect(bind).get_check_constraints("analysis_schedule")
    }
    with op.batch_alter_table("analysis_schedule", naming_convention=NAMING) as batch:
        if not any(name and name.endswith("analysis_schedule_mode") for name in check_names):
            batch.create_check_constraint(
                op.f("ck_analysis_schedule_ck_analysis_schedule_mode"),
                "mode IN ('CUSTOM','EXCLUDED')",
            )
        if not any(name and name.endswith("analysis_schedule_target_version_policy") for name in check_names):
            batch.create_check_constraint(
                op.f("ck_analysis_schedule_ck_analysis_schedule_target_version_policy"),
                "target_version_policy IN ('CURRENT_ONLY','ALL_ACTIVE_VERSIONS')",
            )


def downgrade() -> None:
    bind = op.get_bind()
    check_names = {
        constraint["name"]
        for constraint in sa.inspect(bind).get_check_constraints("analysis_schedule")
    }
    # The reflected SQLite constraints already have their fully-rendered names.
    # Supplying ``naming_convention`` here would apply the ``ck_`` template a
    # second time and make Alembic look for a non-existent constraint.
    with op.batch_alter_table(
        "analysis_schedule", naming_convention=REFLECT_NAMING
    ) as batch:
        for name in sorted(check_names):
            if name and (
                name.endswith("analysis_schedule_target_version_policy")
                or name.endswith("analysis_schedule_mode")
            ):
                batch.drop_constraint(op.f(name), type_="check")
        schedule_columns = {
            column["name"] for column in sa.inspect(bind).get_columns("analysis_schedule")
        }
        if "target_version_policy" in schedule_columns:
            batch.drop_column("target_version_policy")
        if "mode" in schedule_columns:
            batch.drop_column("mode")

    inspector = sa.inspect(bind)
    if "ix_products_current_sbom_id" in {index["name"] for index in inspector.get_indexes("products")}:
        op.drop_index("ix_products_current_sbom_id", table_name="products")
    current_fk = next(
        (
            fk
            for fk in sa.inspect(bind).get_foreign_keys("products")
            if fk["constrained_columns"] == ["current_sbom_id"]
        ),
        None,
    )
    if current_fk is not None:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(
                "products", naming_convention=REFLECT_NAMING
            ) as batch:
                batch.drop_constraint(op.f(current_fk["name"]), type_="foreignkey")
        else:
            op.drop_constraint(current_fk["name"], "products", type_="foreignkey")
    if "current_sbom_id" in {
        column["name"] for column in sa.inspect(bind).get_columns("products")
    }:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(
                "products", naming_convention=REFLECT_NAMING
            ) as batch:
                batch.drop_column("current_sbom_id")
        else:
            op.drop_column("products", "current_sbom_id")
