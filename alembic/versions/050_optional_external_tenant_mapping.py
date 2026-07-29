"""Make the legacy external tenant mapping optional and non-authoritative.

Revision ID: 050_optional_external_tenant_mapping
Revises: 049_tenant_multi_role_assignments
Create Date: 2026-07-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "050_optional_external_tenant_mapping"
down_revision = "049_tenant_multi_role_assignments"
branch_labels = None
depends_on = None


def _alter_nullable(nullable: bool) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("tenants") as batch:
            batch.alter_column(
                "external_iam_tenant_id",
                existing_type=sa.String(length=255),
                nullable=nullable,
            )
        return
    op.alter_column(
        "tenants",
        "external_iam_tenant_id",
        existing_type=sa.String(length=255),
        nullable=nullable,
    )


def upgrade() -> None:
    # Existing values and the unique constraint/index are deliberately kept.
    # PostgreSQL unique constraints allow multiple NULLs.
    _alter_nullable(True)


def downgrade() -> None:
    bind = op.get_bind()
    null_count = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM tenants "
            "WHERE external_iam_tenant_id IS NULL"
        )
    ).scalar_one()
    if null_count:
        raise RuntimeError(
            "Cannot restore tenants.external_iam_tenant_id to NOT NULL while "
            f"{null_count} tenant row(s) have no legacy external mapping."
        )
    _alter_nullable(False)
