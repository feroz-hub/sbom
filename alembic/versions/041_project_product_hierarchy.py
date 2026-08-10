"""Add project product hierarchy.

Revision ID: 041_project_product_hierarchy
Revises: 040_analysis_run_trigger_source
Create Date: 2026-07-03
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "041_project_product_hierarchy"
down_revision = "040_analysis_run_trigger_source"
branch_labels = None
depends_on = None

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

DEFAULT_PRODUCT_NAME = "Legacy / Unassigned Product"
DEFAULT_PRODUCT_SLUG = "legacy-unassigned-product"
DEFAULT_PRODUCT_NORMALIZED = "legacy / unassigned product"
DEFAULT_UNASSIGNED_PROJECT_NAME = "Unassigned Project"


def _tables(bind: sa.engine.Connection) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    if table not in _tables(bind):
        return set()
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _indexes(bind: sa.engine.Connection, table: str) -> set[str]:
    if table not in _tables(bind):
        return set()
    return {index["name"] for index in sa.inspect(bind).get_indexes(table)}


def _foreign_key_exists(bind: sa.engine.Connection, table: str, columns: list[str]) -> bool:
    return any(fk.get("constrained_columns") == columns for fk in sa.inspect(bind).get_foreign_keys(table))


def _create_products_table(bind: sa.engine.Connection) -> None:
    if "products" in _tables(bind):
        return
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("product_key", sa.String(length=128), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("latest_version", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=True),
        sa.Column("deleted_at", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_by", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_products_tenant_id_tenants"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], name="fk_products_project_id_projects", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "project_id", "slug", name="uq_products_tenant_project_slug"),
    )
    for name, cols in (
        ("ix_products_tenant_id", ["tenant_id"]),
        ("ix_products_project_id", ["project_id"]),
        ("ix_products_product_key", ["product_key"]),
        ("ix_products_status", ["status"]),
        ("ix_products_created_by", ["created_by"]),
        ("ix_products_created_at", ["created_at"]),
        ("ix_products_deleted_at", ["deleted_at"]),
        ("ix_products_tenant_project_name", ["tenant_id", "project_id", "normalized_name"]),
        ("ix_products_tenant_project", ["tenant_id", "project_id"]),
    ):
        op.create_index(name, "products", cols)


def _add_fk_column(bind: sa.engine.Connection, table: str, column_name: str, referred_table: str) -> None:
    if table not in _tables(bind) or column_name in _columns(bind, table):
        return
    column = sa.Column(column_name, sa.Integer(), nullable=True)
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table, naming_convention=NAMING) as batch:
            batch.add_column(column)
            batch.create_foreign_key(f"fk_{table}_{column_name}_{referred_table}", referred_table, [column_name], ["id"])
    else:
        op.add_column(table, column)
        op.create_foreign_key(f"fk_{table}_{column_name}_{referred_table}", table, referred_table, [column_name], ["id"])


def _add_product_columns(bind: sa.engine.Connection) -> None:
    _add_fk_column(bind, "sbom_source", "product_id", "products")
    _add_fk_column(bind, "analysis_run", "product_id", "products")
    _add_fk_column(bind, "analysis_schedule", "product_id", "products")
    for table in ("sbom_source", "analysis_run", "analysis_schedule"):
        if table in _tables(bind):
            index = f"ix_{table}_product_id"
            if index not in _indexes(bind, table):
                op.create_index(index, table, ["product_id"])
    if "ix_sbom_source_tenant_product" not in _indexes(bind, "sbom_source"):
        op.create_index("ix_sbom_source_tenant_product", "sbom_source", ["tenant_id", "product_id"])


def _backfill_products(bind: sa.engine.Connection) -> None:
    if not {"projects", "products", "sbom_source"}.issubset(_tables(bind)):
        return
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    projects = bind.execute(sa.text("SELECT id, tenant_id FROM projects")).mappings().all()
    for project in projects:
        product_id = bind.execute(
            sa.text(
                """
                SELECT id FROM products
                WHERE tenant_id = :tenant_id
                  AND project_id = :project_id
                  AND slug = :slug
                """
            ),
            {"tenant_id": project["tenant_id"], "project_id": project["id"], "slug": DEFAULT_PRODUCT_SLUG},
        ).scalar_one_or_none()
        if product_id is None:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO products (
                        tenant_id, project_id, name, normalized_name, slug,
                        description, status, created_by, created_at, updated_at, is_active
                    )
                    VALUES (
                        :tenant_id, :project_id, :name, :normalized_name, :slug,
                        :description, 'active', 'migration', :now, :now, :is_active
                    )
                    """
                ),
                {
                    "tenant_id": project["tenant_id"],
                    "project_id": project["id"],
                    "name": DEFAULT_PRODUCT_NAME,
                    "normalized_name": DEFAULT_PRODUCT_NORMALIZED,
                    "slug": DEFAULT_PRODUCT_SLUG,
                    "description": "Compatibility product for SBOMs uploaded before product assignment became required.",
                    "now": now,
                    "is_active": True,
                },
            )
            product_id = bind.execute(
                sa.text(
                    """
                    SELECT id FROM products
                    WHERE tenant_id = :tenant_id AND project_id = :project_id AND slug = :slug
                    """
                ),
                {"tenant_id": project["tenant_id"], "project_id": project["id"], "slug": DEFAULT_PRODUCT_SLUG},
            ).scalar_one()
        bind.execute(
            sa.text(
                """
                UPDATE sbom_source
                SET product_id = :product_id,
                    product_name = COALESCE(product_name, :product_name)
                WHERE tenant_id = :tenant_id
                  AND projectid = :project_id
                  AND product_id IS NULL
                """
            ),
            {
                "product_id": product_id,
                "product_name": DEFAULT_PRODUCT_NAME,
                "tenant_id": project["tenant_id"],
                "project_id": project["id"],
            },
        )
    projectless_tenants = bind.execute(
        sa.text("SELECT DISTINCT tenant_id FROM sbom_source WHERE projectid IS NULL")
    ).scalars().all()
    for tenant_id in projectless_tenants:
        project_id = bind.execute(
            sa.text(
                """
                SELECT id FROM projects
                WHERE tenant_id = :tenant_id AND project_name = :name
                """
            ),
            {"tenant_id": tenant_id, "name": DEFAULT_UNASSIGNED_PROJECT_NAME},
        ).scalar_one_or_none()
        if project_id is None:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO projects (
                        tenant_id, project_name, project_details, project_status,
                        created_on, created_by, is_active
                    )
                    VALUES (:tenant_id, :name, :details, 1, :now, 'migration', :is_active)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "name": DEFAULT_UNASSIGNED_PROJECT_NAME,
                    "details": "Compatibility project for legacy SBOMs created without project_id.",
                    "now": now,
                    "is_active": True,
                },
            )
            project_id = bind.execute(
                sa.text("SELECT id FROM projects WHERE tenant_id = :tenant_id AND project_name = :name"),
                {"tenant_id": tenant_id, "name": DEFAULT_UNASSIGNED_PROJECT_NAME},
            ).scalar_one()
        product_id = bind.execute(
            sa.text(
                """
                SELECT id FROM products
                WHERE tenant_id = :tenant_id AND project_id = :project_id AND slug = :slug
                """
            ),
            {"tenant_id": tenant_id, "project_id": project_id, "slug": DEFAULT_PRODUCT_SLUG},
        ).scalar_one_or_none()
        if product_id is None:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO products (
                        tenant_id, project_id, name, normalized_name, slug,
                        description, status, created_by, created_at, updated_at, is_active
                    )
                    VALUES (
                        :tenant_id, :project_id, :name, :normalized_name, :slug,
                        :description, 'active', 'migration', :now, :now, :is_active
                    )
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "project_id": project_id,
                    "name": DEFAULT_PRODUCT_NAME,
                    "normalized_name": DEFAULT_PRODUCT_NORMALIZED,
                    "slug": DEFAULT_PRODUCT_SLUG,
                    "description": "Compatibility product for SBOMs uploaded before product assignment became required.",
                    "now": now,
                    "is_active": True,
                },
            )
            product_id = bind.execute(
                sa.text(
                    """
                    SELECT id FROM products
                    WHERE tenant_id = :tenant_id AND project_id = :project_id AND slug = :slug
                    """
                ),
                {"tenant_id": tenant_id, "project_id": project_id, "slug": DEFAULT_PRODUCT_SLUG},
            ).scalar_one()
        bind.execute(
            sa.text(
                """
                UPDATE sbom_source
                SET projectid = :project_id,
                    product_id = :product_id,
                    product_name = COALESCE(product_name, :product_name)
                WHERE tenant_id = :tenant_id
                  AND projectid IS NULL
                  AND product_id IS NULL
                """
            ),
            {
                "project_id": project_id,
                "product_id": product_id,
                "product_name": DEFAULT_PRODUCT_NAME,
                "tenant_id": tenant_id,
            },
        )
    if "analysis_run" in _tables(bind):
        bind.execute(
            sa.text(
                """
                UPDATE analysis_run
                SET product_id = (
                    SELECT s.product_id
                    FROM sbom_source s
                    WHERE s.id = analysis_run.sbom_id
                )
                WHERE product_id IS NULL
                  AND EXISTS (
                    SELECT 1
                    FROM sbom_source s
                    WHERE s.id = analysis_run.sbom_id
                      AND s.product_id IS NOT NULL
                  )
                """
            )
        )


def _update_schedule_constraint(bind: sa.engine.Connection) -> None:
    if "analysis_schedule" not in _tables(bind):
        return
    # SQLite batch mode cannot reliably drop anonymous historical CHECK
    # constraints across local DB variants. Fresh SQLite schemas get the new
    # ORM constraint via Base.metadata; Alembic-managed Postgres gets the hard
    # migration here.
    if bind.dialect.name == "sqlite":
        return
    constraints = {item["name"] for item in sa.inspect(bind).get_check_constraints("analysis_schedule")}
    for name in ("ck_analysis_schedule_scope", "ck_analysis_schedule_ck_analysis_schedule_scope"):
        if name in constraints:
            op.execute(sa.text(f'ALTER TABLE analysis_schedule DROP CONSTRAINT IF EXISTS "{name}"'))
    for name in ("ck_analysis_schedule_target", "ck_analysis_schedule_ck_analysis_schedule_target"):
        if name in constraints:
            op.execute(sa.text(f'ALTER TABLE analysis_schedule DROP CONSTRAINT IF EXISTS "{name}"'))
    op.execute(
        """
        ALTER TABLE analysis_schedule
        ADD CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_scope
        CHECK (scope IN ('PROJECT','PRODUCT','SBOM'))
        """
    )
    op.execute(
        """
        ALTER TABLE analysis_schedule
        ADD CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_target
        CHECK (
            (scope = 'PROJECT' AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL)
            OR (scope = 'PRODUCT' AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL)
            OR (scope = 'SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)
        )
        """
    )


def upgrade() -> None:
    bind = op.get_bind()
    _create_products_table(bind)
    _add_product_columns(bind)
    _backfill_products(bind)
    _update_schedule_constraint(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite" and "analysis_schedule" in _tables(bind):
        constraints = {item["name"] for item in sa.inspect(bind).get_check_constraints("analysis_schedule")}
        for name in ("ck_analysis_schedule_scope", "ck_analysis_schedule_ck_analysis_schedule_scope"):
            if name in constraints:
                op.execute(sa.text(f'ALTER TABLE analysis_schedule DROP CONSTRAINT IF EXISTS "{name}"'))
        for name in ("ck_analysis_schedule_target", "ck_analysis_schedule_ck_analysis_schedule_target"):
            if name in constraints:
                op.execute(sa.text(f'ALTER TABLE analysis_schedule DROP CONSTRAINT IF EXISTS "{name}"'))
        op.execute(
            """
            ALTER TABLE analysis_schedule
            ADD CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_scope
            CHECK (scope IN ('PROJECT','SBOM'))
            """
        )
        op.execute(
            """
            ALTER TABLE analysis_schedule
            ADD CONSTRAINT ck_analysis_schedule_ck_analysis_schedule_target
            CHECK (
                (scope = 'PROJECT' AND project_id IS NOT NULL AND sbom_id IS NULL)
                OR (scope = 'SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL)
            )
            """
        )
    for table in ("analysis_schedule", "analysis_run", "sbom_source"):
        if table in _tables(bind) and "product_id" in _columns(bind, table):
            if bind.dialect.name == "sqlite":
                with op.batch_alter_table(table, naming_convention=NAMING) as batch:
                    batch.drop_column("product_id")
            else:
                op.drop_column(table, "product_id")
    if "products" in _tables(bind):
        op.drop_table("products")
