"""Reconcile PostgreSQL defaults and Alembic bookkeeping.

Revision ID: 032_postgres_compat
Revises: 031_nvd_lookup_cache
Create Date: 2026-06-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "032_postgres_compat"
down_revision = "031_nvd_lookup_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.alter_column(
        "alembic_version",
        "version_num",
        existing_type=sa.String(length=128),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    for column in ("can_edit", "can_ai_fix"):
        op.alter_column(
            "sbom_validation_sessions",
            column,
            existing_type=sa.Boolean(),
            existing_nullable=False,
            server_default=sa.true(),
        )


def downgrade() -> None:
    # Keep the wider Alembic column: later historical revision identifiers
    # still need it if the database is upgraded again.
    return
