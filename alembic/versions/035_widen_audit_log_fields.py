"""Widen audit_log fields for namespaced audit events.

Revision ID: 035_widen_audit_log_fields
Revises: 034_lifecycle_provider_admin
Create Date: 2026-06-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "035_widen_audit_log_fields"
down_revision = "034_lifecycle_provider_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.alter_column(
            "action",
            existing_type=sa.String(length=48),
            type_=sa.String(length=128),
            existing_nullable=False,
        )
        batch_op.alter_column(
            "target_kind",
            existing_type=sa.String(length=24),
            type_=sa.String(length=128),
            existing_nullable=False,
        )
        batch_op.alter_column(
            "detail",
            existing_type=sa.String(length=240),
            type_=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "entity_type",
            existing_type=sa.String(length=64),
            type_=sa.String(length=128),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "entity_id",
            existing_type=sa.String(length=128),
            type_=sa.String(length=128),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "user_agent",
            existing_type=sa.String(length=512),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.alter_column(
            "user_agent",
            existing_type=sa.Text(),
            type_=sa.String(length=512),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "entity_id",
            existing_type=sa.String(length=128),
            type_=sa.String(length=128),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "entity_type",
            existing_type=sa.String(length=128),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "detail",
            existing_type=sa.Text(),
            type_=sa.String(length=240),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "target_kind",
            existing_type=sa.String(length=128),
            type_=sa.String(length=24),
            existing_nullable=False,
        )
        batch_op.alter_column(
            "action",
            existing_type=sa.String(length=128),
            type_=sa.String(length=48),
            existing_nullable=False,
        )
