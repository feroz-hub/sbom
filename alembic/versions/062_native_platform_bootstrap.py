"""Durable one-time Native platform enrollment reservation."""
import sqlalchemy as sa
from alembic import op

revision = "062_native_platform_bootstrap"
down_revision = "061_security_mail_outbox"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "native_platform_bootstrap",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("iam_users.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("operator_reference", sa.String(128), nullable=False),
        sa.CheckConstraint("id = 1", name="native_bootstrap_singleton"),
        sa.CheckConstraint("state IN ('PENDING','COMPLETED')", name="native_bootstrap_state"),
        sa.CheckConstraint("(state = 'PENDING' AND completed_at IS NULL) OR (state = 'COMPLETED' AND completed_at IS NOT NULL)", name="native_bootstrap_completion"),
    )


def downgrade():
    if op.get_bind().scalar(sa.text("SELECT count(*) FROM native_platform_bootstrap")):
        raise RuntimeError("Refusing to erase a Native bootstrap reservation")
    op.drop_table("native_platform_bootstrap")
