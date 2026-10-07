"""Add logical SBOM masters without changing uploaded-version identities.

Revision ID: 076_logical_sbom_versions
Revises: 075_platform_advisor_policies
"""

from datetime import UTC, datetime
import sqlalchemy as sa
from alembic import op

revision = "076_logical_sbom_versions"
down_revision = "075_platform_advisor_policies"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    with op.batch_alter_table("products") as batch:
        batch.create_unique_constraint("uq_products_id_tenant", ["id", "tenant_id"])
    op.create_table(
        "logical_sbom",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_logical_sbom_id_tenant"),
        sa.UniqueConstraint("id", "tenant_id", "product_id", name="uq_logical_sbom_id_tenant_product"),
        sa.ForeignKeyConstraint(
            ["product_id", "tenant_id"],
            ["products.id", "products.tenant_id"],
            name="fk_logical_sbom_product_tenant",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_logical_sbom_product_id", "logical_sbom", ["product_id"])
    op.create_index("ix_logical_sbom_tenant_id", "logical_sbom", ["tenant_id"])
    op.create_index("ix_logical_sbom_tenant_product", "logical_sbom", ["tenant_id", "product_id"])
    op.add_column("sbom_source", sa.Column("logical_sbom_id", sa.Integer(), nullable=True))
    _backfill(bind)
    with op.batch_alter_table("sbom_source") as batch:
        batch.drop_constraint("uq_sbom_source_tenant_name_version", type_="unique")
        batch.alter_column("logical_sbom_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key("fk_sbom_source_logical", "logical_sbom", ["logical_sbom_id"], ["id"])
        batch.create_foreign_key(
            "fk_sbom_source_logical_tenant", "logical_sbom", ["logical_sbom_id", "tenant_id"], ["id", "tenant_id"]
        )
        batch.create_foreign_key(
            "fk_sbom_source_logical_product",
            "logical_sbom",
            ["logical_sbom_id", "tenant_id", "product_id"],
            ["id", "tenant_id", "product_id"],
        )
        batch.create_unique_constraint("uq_sbom_source_logical_version", ["logical_sbom_id", "sbom_version"])
    op.create_index("ix_sbom_source_logical_sbom_id", "sbom_source", ["logical_sbom_id"])
    op.create_index(
        "uq_sbom_source_logical_unversioned",
        "sbom_source",
        ["logical_sbom_id"],
        unique=True,
        postgresql_where=sa.text("sbom_version IS NULL"),
        sqlite_where=sa.text("sbom_version IS NULL"),
    )


def _backfill(bind):
    metadata = sa.MetaData()
    versions = sa.Table("sbom_source", metadata, autoload_with=bind)
    masters = sa.Table("logical_sbom", metadata, autoload_with=bind)
    fields = (
        "id",
        "tenant_id",
        "product_id",
        "projectid",
        "parent_id",
        "source_sbom_id",
        "sbom_name",
        "sbom_version",
        "description",
        "created_by",
        "created_on",
        "modified_on",
    )
    # Do not load potentially huge raw SBOM documents during backfill.
    rows = {
        row["id"]: row
        for row in bind.execute(sa.select(*(versions.c[field] for field in fields)).order_by(versions.c.id)).mappings()
    }
    assigned, labels = {}, {}
    now = datetime.now(UTC).isoformat()

    def compatible(row, parent):
        return (
            parent is not None
            and row["source_sbom_id"] is None
            and all(row[key] == parent[key] for key in ("tenant_id", "product_id", "projectid"))
        )

    for seed in rows.values():
        if seed["id"] in assigned:
            continue
        stack, visiting = [], set()
        row = seed
        # Iterative traversal also handles forward references, cycles and long histories.
        while row["id"] not in assigned and row["id"] not in visiting:
            visiting.add(row["id"])
            stack.append(row)
            parent = rows.get(row["parent_id"])
            if not compatible(row, parent):
                break
            row = parent
        for row in reversed(stack):
            parent = rows.get(row["parent_id"])
            master_id = assigned.get(parent["id"]) if compatible(row, parent) else None
            if master_id is not None and row["sbom_version"] in labels[master_id]:
                master_id = None
            if master_id is None:
                master_id = bind.execute(
                    masters.insert()
                    .values(
                        tenant_id=row["tenant_id"],
                        product_id=row["product_id"],
                        name=row["sbom_name"],
                        description=row["description"],
                        created_by=row["created_by"],
                        created_at=row["created_on"] or now,
                        updated_at=row["modified_on"] or row["created_on"] or now,
                    )
                    .returning(masters.c.id)
                ).scalar_one()
                labels[master_id] = set()
            labels[master_id].add(row["sbom_version"])
            assigned[row["id"]] = master_id
            bind.execute(versions.update().where(versions.c.id == row["id"]).values(logical_sbom_id=master_id))


def downgrade():
    raise RuntimeError(
        "Logical SBOM history requires a reviewed rollback; tenant-wide name/version uniqueness may no longer hold."
    )
