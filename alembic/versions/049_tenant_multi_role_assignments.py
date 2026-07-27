"""Add tenant multi-role assignments and immutable lifecycle history.

Revision ID: 049_tenant_multi_role_assignments
Revises: 048_authorization_catalog
Create Date: 2026-07-27
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "049_tenant_multi_role_assignments"
down_revision = "048_authorization_catalog"
branch_labels = None
depends_on = None


def _check_names(bind, table: str) -> dict[str, str]:
    return {
        str(item["name"]): str(item.get("sqltext") or "")
        for item in sa.inspect(bind).get_check_constraints(table)
        if item.get("name")
    }


def _legacy_role_check(bind) -> str | None:
    for name, sql in _check_names(bind, "tenant_users").items():
        normalized = sql.lower().replace('"', "")
        if "role" in normalized and "tenant_admin" in normalized:
            return name
    return None


def _create_assignment_tables() -> None:
    op.create_table(
        "tenant_user_role_assignments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("tenant_user_id", sa.Integer(), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("assignment_source", sa.String(32), nullable=False),
        sa.Column("assigned_by_user_id", sa.Integer(), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by_user_id", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(512), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_user_id", "tenant_id"],
            ["tenant_users.id", "tenant_users.tenant_id"],
            name="fk_tenant_role_assignment_membership_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["authorization_roles.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"], ["iam_users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_user_id"], ["iam_users.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "tenant_user_id",
            "role_id",
            name="uq_tenant_user_role_assignments_membership_role",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE','REVOKED')",
            name="tenant_role_assignment_status",
        ),
        sa.CheckConstraint(
            "assignment_source IN ('MIGRATION','TENANT_CREATION','TENANT_ADMIN','PLATFORM_ADMIN','SYSTEM','API')",
            name="tenant_role_assignment_source",
        ),
        sa.CheckConstraint("version >= 1", name="tenant_role_assignment_version"),
        sa.CheckConstraint(
            "(status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by_user_id IS NULL) "
            "OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND is_primary = false)",
            name="tenant_role_assignment_revocation_state",
        ),
    )
    for name, columns in (
        ("ix_tenant_user_role_assignments_tenant_id", ["tenant_id"]),
        ("ix_tenant_user_role_assignments_tenant_user_id", ["tenant_user_id"]),
        ("ix_tenant_user_role_assignments_role_id", ["role_id"]),
        ("ix_tenant_user_role_assignments_status", ["status"]),
        (
            "ix_tenant_user_role_assignments_tenant_status",
            ["tenant_id", "status"],
        ),
        (
            "ix_tenant_user_role_assignments_membership_status",
            ["tenant_user_id", "status"],
        ),
    ):
        op.create_index(name, "tenant_user_role_assignments", columns)
    op.create_index(
        "uq_tenant_user_role_assignments_active_primary",
        "tenant_user_role_assignments",
        ["tenant_user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE' AND is_primary"),
        sqlite_where=sa.text("status = 'ACTIVE' AND is_primary = 1"),
    )

    op.create_table(
        "tenant_user_role_assignment_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("tenant_user_id", sa.Integer(), nullable=True),
        sa.Column("assignment_id", sa.Integer(), nullable=True),
        sa.Column("role_id", sa.Integer(), nullable=True),
        sa.Column("role_code_snapshot", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("previous_status", sa.String(16), nullable=True),
        sa.Column("new_status", sa.String(16), nullable=True),
        sa.Column("previous_primary", sa.Boolean(), nullable=True),
        sa.Column("new_primary", sa.Boolean(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("assignment_source", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(512), nullable=True),
        sa.Column("before_membership_version", sa.Integer(), nullable=False),
        sa.Column("after_membership_version", sa.Integer(), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_user_id"], ["tenant_users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["assignment_id"],
            ["tenant_user_role_assignments.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["authorization_roles.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["iam_users.id"], ondelete="SET NULL"
        ),
        sa.CheckConstraint(
            "event_type IN ('MIGRATED','GRANTED','REACTIVATED','REVOKED','PRIMARY_SELECTED','PRIMARY_CHANGED','ROLE_SET_REPLACED','ASSIGNMENT_REJECTED')",
            name="tenant_role_assignment_history_event",
        ),
        sa.CheckConstraint(
            "assignment_source IN ('MIGRATION','TENANT_CREATION','TENANT_ADMIN','PLATFORM_ADMIN','SYSTEM','API')",
            name="tenant_role_assignment_history_source",
        ),
        sa.CheckConstraint(
            "before_membership_version >= 1 AND after_membership_version >= before_membership_version",
            name="tenant_role_assignment_history_versions",
        ),
    )
    for name, columns in (
        ("ix_tenant_role_assignment_history_tenant_id", ["tenant_id"]),
        ("ix_tenant_role_assignment_history_tenant_user_id", ["tenant_user_id"]),
        ("ix_tenant_role_assignment_history_assignment_id", ["assignment_id"]),
        ("ix_tenant_role_assignment_history_occurred_at", ["occurred_at"]),
        (
            "ix_tenant_role_assignment_history_membership_time",
            ["tenant_id", "tenant_user_id", "occurred_at"],
        ),
    ):
        op.create_index(name, "tenant_user_role_assignment_history", columns)


def _backfill(bind) -> None:
    invalid = bind.execute(
        sa.text(
            """
            SELECT tu.id, tu.role
              FROM tenant_users tu
              LEFT JOIN authorization_roles ar
                ON ar.code = tu.role
               AND ar.scope = 'TENANT'
               AND ar.status = 'ACTIVE'
               AND ar.is_assignable = true
             WHERE ar.id IS NULL
            """
        )
    ).all()
    if invalid:
        rendered = ", ".join(f"{row.id}:{row.role}" for row in invalid[:20])
        raise RuntimeError(
            "Phase 9 cannot map legacy tenant roles to an active assignable "
            f"TENANT catalogue role. Remediate memberships: {rendered}"
        )

    memberships = bind.execute(
        sa.text(
            """
            SELECT tu.id, tu.tenant_id, tu.role, tu.created_at, ar.id AS role_id
              FROM tenant_users tu
              JOIN authorization_roles ar
                ON ar.code = tu.role
               AND ar.scope = 'TENANT'
               AND ar.status = 'ACTIVE'
               AND ar.is_assignable = true
             ORDER BY tu.id
            """
        )
    ).mappings()
    now = datetime.now(UTC)
    for row in memberships:
        assigned_at = row["created_at"] or now
        result = bind.execute(
            sa.text(
                """
                INSERT INTO tenant_user_role_assignments
                    (tenant_id, tenant_user_id, role_id, status, is_primary,
                     assignment_source, assigned_at, version, created_at, updated_at)
                VALUES
                    (:tenant_id, :membership_id, :role_id, 'ACTIVE', true,
                     'MIGRATION', :assigned_at, 1, :assigned_at, :now)
                RETURNING id
                """
            ),
            {
                "tenant_id": row["tenant_id"],
                "membership_id": row["id"],
                "role_id": row["role_id"],
                "assigned_at": assigned_at,
                "now": now,
            },
        )
        assignment_id = result.scalar_one()
        bind.execute(
            sa.text(
                """
                INSERT INTO tenant_user_role_assignment_history
                    (tenant_id, tenant_user_id, assignment_id, role_id,
                     role_code_snapshot, event_type, previous_status, new_status,
                     previous_primary, new_primary, assignment_source,
                     before_membership_version, after_membership_version,
                     occurred_at, metadata_json)
                VALUES
                    (:tenant_id, :membership_id, :assignment_id, :role_id,
                     :role_code, 'MIGRATED', NULL, 'ACTIVE',
                     NULL, true, 'MIGRATION', 1, 1, :occurred_at,
                     '{"source":"tenant_users.role"}')
                """
            ),
            {
                "tenant_id": row["tenant_id"],
                "membership_id": row["id"],
                "assignment_id": assignment_id,
                "role_id": row["role_id"],
                "role_code": row["role"],
                "occurred_at": now,
            },
        )
    mismatch = bind.scalar(
        sa.text(
            """
            SELECT count(*)
              FROM tenant_users tu
             WHERE (
                SELECT count(*) FROM tenant_user_role_assignments a
                 WHERE a.tenant_user_id = tu.id
                   AND a.tenant_id = tu.tenant_id
                   AND a.status = 'ACTIVE'
                   AND a.is_primary = true
             ) <> 1
            """
        )
    )
    if mismatch:
        raise RuntimeError("Phase 9 backfill did not create one primary assignment per membership")


def upgrade() -> None:
    bind = op.get_bind()
    legacy_check = _legacy_role_check(bind)
    with op.batch_alter_table("tenant_users") as batch:
        batch.add_column(
            sa.Column(
                "role_assignment_version",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.create_unique_constraint(
            "uq_tenant_users_id_tenant", ["id", "tenant_id"]
        )
        if legacy_check:
            batch.drop_constraint(op.f(legacy_check), type_="check")
        batch.create_check_constraint(
            "tenant_user_role_normalized",
            "length(trim(role)) > 0 AND role = upper(role)",
        )
        batch.create_check_constraint(
            "tenant_user_role_assignment_version",
            "role_assignment_version >= 1",
        )
    _create_assignment_tables()
    _backfill(bind)


def downgrade() -> None:
    bind = op.get_bind()
    unsafe = bind.execute(
        sa.text(
            """
            SELECT tu.id
              FROM tenant_users tu
             WHERE tu.role NOT IN ('TENANT_ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')
                OR (SELECT count(*) FROM tenant_user_role_assignments a
                     WHERE a.tenant_user_id = tu.id AND a.status = 'ACTIVE') <> 1
                OR NOT EXISTS (
                    SELECT 1
                      FROM tenant_user_role_assignments a
                      JOIN authorization_roles ar ON ar.id = a.role_id
                     WHERE a.tenant_user_id = tu.id
                       AND a.status = 'ACTIVE'
                       AND a.is_primary = true
                       AND ar.code = tu.role
                )
             LIMIT 1
            """
        )
    ).first()
    if unsafe:
        raise RuntimeError(
            "Phase 9 downgrade refused: every membership must have exactly one "
            "active primary legacy-compatible role. Run prepare_phase9_downgrade.py."
        )

    op.drop_table("tenant_user_role_assignment_history")
    op.drop_table("tenant_user_role_assignments")
    checks = _check_names(bind, "tenant_users")
    with op.batch_alter_table("tenant_users") as batch:
        for name, sql in checks.items():
            if (
                "tenant_user_role_assignment_version" in name
                or "tenant_user_role_normalized" in name
                or "role_assignment_version" in sql
                or "length(trim(role))" in sql.lower()
            ):
                batch.drop_constraint(op.f(name), type_="check")
        batch.drop_constraint(op.f("uq_tenant_users_id_tenant"), type_="unique")
        batch.drop_column("role_assignment_version")
        batch.create_check_constraint(
            "tenant_user_role",
            "role IN ('TENANT_ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')",
        )
