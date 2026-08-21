"""Introduce stable, immutable, opaque tenant_key for tenants.

Revision ID: 051_tenant_key
Revises: 050_optional_external_tenant_mapping
Create Date: 2026-08-19
"""

from __future__ import annotations

import uuid
import sqlalchemy as sa
from alembic import op

revision = "051_tenant_key"
down_revision = "050_optional_external_tenant_mapping"
branch_labels = None
depends_on = None


def _generate_opaque_tenant_key() -> str:
    return f"tnt_{uuid.uuid4().hex}"


def upgrade() -> None:
    bind = op.get_bind()

    # Step 1: Add tenant_key as nullable
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(
            sa.Column("tenant_key", sa.String(length=64), nullable=True)
        )

    # Step 2: Backfill existing rows with distinct opaque keys
    tenant_ids = [
        row[0]
        for row in bind.execute(sa.text("SELECT id FROM tenants ORDER BY id")).all()
    ]
    for tenant_id in tenant_ids:
        key = _generate_opaque_tenant_key()
        bind.execute(
            sa.text("UPDATE tenants SET tenant_key = :key WHERE id = :id"),
            {"key": key, "id": tenant_id},
        )

    # Step 3: Validate that all rows have non-null, unique keys
    null_or_empty_count = int(
        bind.execute(
            sa.text(
                "SELECT COUNT(*) FROM tenants "
                "WHERE tenant_key IS NULL OR tenant_key = ''"
            )
        ).scalar_one()
    )
    if null_or_empty_count:
        raise RuntimeError(
            f"Migration failed: {null_or_empty_count} tenant row(s) have NULL or empty tenant_key after backfill."
        )

    duplicate_count = int(
        bind.execute(
            sa.text(
                "SELECT COUNT(*) FROM ("
                "  SELECT tenant_key FROM tenants "
                "  GROUP BY tenant_key HAVING COUNT(*) > 1"
                ") duplicates"
            )
        ).scalar_one()
    )
    if duplicate_count:
        raise RuntimeError(
            f"Migration failed: {duplicate_count} duplicate tenant_key group(s) exist after backfill."
        )

    # Step 4 & 5: Alter column to NOT NULL and add named unique constraint
    with op.batch_alter_table("tenants") as batch:
        batch.alter_column(
            "tenant_key",
            existing_type=sa.String(length=64),
            nullable=False,
        )
        batch.create_unique_constraint(
            "uq_tenants_tenant_key",
            ["tenant_key"],
        )

    # Step 6: Create index
    op.create_index("ix_tenants_tenant_key", "tenants", ["tenant_key"])


def downgrade() -> None:
    op.drop_index("ix_tenants_tenant_key", table_name="tenants")
    with op.batch_alter_table("tenants") as batch:
        batch.drop_constraint("uq_tenants_tenant_key", type_="unique")
        batch.drop_column("tenant_key")
