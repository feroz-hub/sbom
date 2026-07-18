"""Add database-authoritative platform grants and identity constraints.

Revision ID: 045_secure_authorization_model
Revises: 044_kev_vulnerabilities_table
Create Date: 2026-07-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "045_secure_authorization_model"
down_revision = "044_kev_vulnerabilities_table"
branch_labels = None
depends_on = None


def _check_names(bind, table: str) -> set[str]:
    return {item.get("name") for item in sa.inspect(bind).get_check_constraints(table)}


def _add_check(bind, table: str, name: str, expression: str) -> None:
    if name in _check_names(bind, table) or f"ck_{table}_{name}" in _check_names(bind, table):
        return
    with op.batch_alter_table(table) as batch:
        batch.create_check_constraint(name, expression)


def upgrade() -> None:
    bind = op.get_bind()

    # Legacy migration 033 used a tenant membership as a platform bootstrap.
    # Tenant memberships can no longer carry platform authority.
    bind.execute(sa.text("UPDATE tenant_users SET role='TENANT_ADMIN' WHERE role='PLATFORM_ADMIN'"))
    bind.execute(
        sa.text(
            "UPDATE tenant_users SET status='DISABLED' WHERE user_id IN "
            "(SELECT id FROM iam_users WHERE external_iam_user_id IN ('local-dev-admin','dev-user'))"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE iam_users SET status='DISABLED' "
            "WHERE external_iam_user_id IN ('local-dev-admin','dev-user')"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE tenant_users SET role='VIEWER', status='DISABLED' "
            "WHERE role NOT IN ('TENANT_ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE tenant_users SET status='DISABLED' "
            "WHERE status NOT IN ('ACTIVE','PENDING','DISABLED')"
        )
    )
    bind.execute(
        sa.text("UPDATE iam_users SET status='DISABLED' WHERE status NOT IN ('ACTIVE','PENDING','DISABLED')")
    )
    bind.execute(
        sa.text("UPDATE tenants SET status='DISABLED' WHERE status NOT IN ('ACTIVE','PENDING','DISABLED')")
    )

    _add_check(bind, "tenants", "tenant_status", "status IN ('ACTIVE','PENDING','DISABLED')")
    _add_check(bind, "iam_users", "iam_user_status", "status IN ('ACTIVE','PENDING','DISABLED')")
    _add_check(
        bind,
        "tenant_users",
        "tenant_user_role",
        "role IN ('TENANT_ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')",
    )
    _add_check(bind, "tenant_users", "tenant_user_status", "status IN ('ACTIVE','PENDING','DISABLED')")

    op.create_table(
        "platform_user_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["iam_users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("user_id", name="uq_platform_user_roles_user_id"),
        sa.CheckConstraint("role = 'PLATFORM_ADMIN'", name="ck_platform_user_roles_platform_user_role"),
        sa.CheckConstraint(
            "status IN ('ACTIVE','DISABLED')",
            name="ck_platform_user_roles_platform_user_role_status",
        ),
    )
    op.create_index("ix_platform_user_roles_user_id", "platform_user_roles", ["user_id"])
    op.create_index("ix_platform_user_roles_status", "platform_user_roles", ["status"])

    op.create_table(
        "authorization_audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("target_membership_id", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("old_value", sa.JSON(), nullable=True),
        sa.Column("new_value", sa.JSON(), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("detail", sa.String(240), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["iam_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_user_id"], ["iam_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_membership_id"], ["tenant_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "outcome IN ('SUCCESS','DENIED','FAILED')",
            name="ck_authorization_audit_log_authorization_audit_outcome",
        ),
    )
    for column in (
        "actor_user_id",
        "target_user_id",
        "target_membership_id",
        "tenant_id",
        "action",
        "outcome",
        "correlation_id",
        "created_at",
    ):
        op.create_index(f"ix_authorization_audit_log_{column}", "authorization_audit_log", [column])


def downgrade() -> None:
    op.drop_table("authorization_audit_log")
    op.drop_table("platform_user_roles")
    for table, names in (
        ("tenant_users", ("tenant_user_status", "tenant_user_role")),
        ("iam_users", ("iam_user_status",)),
        ("tenants", ("tenant_status",)),
    ):
        with op.batch_alter_table(table) as batch:
            for name in names:
                batch.drop_constraint(name, type_="check")
