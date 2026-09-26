"""Encrypted transactional security-mail outbox.

Revision ID: 061_security_mail_outbox
Revises: 060_native_identity_foundation
"""

import sqlalchemy as sa
from alembic import op

revision = "061_security_mail_outbox"
down_revision = "060_native_identity_foundation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_mail_outbox",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "token_id",
            sa.Integer(),
            sa.ForeignKey("account_action_tokens.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("payload", sa.LargeBinary()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("failed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('PENDING','DELIVERED','FAILED','EXPIRED','CANCELLED')", name="security_mail_status"
        ),
        sa.CheckConstraint("attempts >= 0", name="security_mail_attempts"),
    )
    op.create_index("ix_security_mail_due", "security_mail_outbox", ["status", "next_attempt_at"])


def downgrade():
    if op.get_bind().scalar(sa.text("SELECT count(*) FROM security_mail_outbox WHERE status = 'PENDING'")):
        raise RuntimeError("Refusing downgrade while security mail deliveries are pending")
    op.drop_table("security_mail_outbox")
