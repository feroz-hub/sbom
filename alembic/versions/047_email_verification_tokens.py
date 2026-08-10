"""Add secure, single-use SBOM email verification tokens.

Revision ID: 047_email_verification_tokens
Revises: 046_external_identity_and_verification_fields
Create Date: 2026-07-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "047_email_verification_tokens"
down_revision = "046_external_identity_and_verification_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_verification_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("email_snapshot", sa.String(320), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invalidation_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by_ip_hash", sa.String(64), nullable=True),
        sa.Column("consumed_by_ip_hash", sa.String(64), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("delivery_status", sa.String(16), nullable=False),
        sa.Column("delivery_attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivery_error_code", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["iam_users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_email_verification_tokens_token_hash",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_email_verification_tokens_email_verification_expiry",
        ),
        sa.CheckConstraint(
            "consumed_at IS NULL OR consumed_at >= created_at",
            name="ck_email_verification_tokens_email_verification_consumed_time",
        ),
        sa.CheckConstraint(
            "invalidated_at IS NULL OR invalidated_at >= created_at",
            name="ck_email_verification_tokens_email_verification_invalidated_time",
        ),
        sa.CheckConstraint(
            "delivery_status IN ('PENDING','SENT','FAILED','SKIPPED')",
            name="ck_email_verification_tokens_email_verification_delivery_status",
        ),
    )
    op.create_index(
        "ix_email_verification_tokens_user_id",
        "email_verification_tokens",
        ["user_id"],
    )
    op.create_index(
        "ix_email_verification_tokens_expires_at",
        "email_verification_tokens",
        ["expires_at"],
    )
    op.create_index(
        "ix_email_verification_tokens_user_created",
        "email_verification_tokens",
        ["user_id", "created_at"],
    )
    op.create_index(
        "ix_email_verification_tokens_user_consumed",
        "email_verification_tokens",
        ["user_id", "consumed_at"],
    )
    op.create_index(
        "uq_email_verification_tokens_active_user",
        "email_verification_tokens",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL AND invalidated_at IS NULL"),
        sqlite_where=sa.text("consumed_at IS NULL AND invalidated_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table("email_verification_tokens")
