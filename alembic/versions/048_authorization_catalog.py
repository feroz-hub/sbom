"""Add and seed the database-backed authorization catalogue.

Revision ID: 048_authorization_catalog
Revises: 047_email_verification_tokens
Create Date: 2026-07-27

Schema and seed are deliberately atomic: DATABASE mode can never observe an
installed but empty catalogue. The seed is imported from the immutable v1
snapshot, not from live authorization constants.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from app.authorization_catalog_seed_v1 import (
    ALL_PERMISSIONS_V1,
    PROTECTED_ROLE_PERMISSIONS_V1,
    ROLE_PERMISSIONS_V1,
    ROLE_SCOPES_V1,
)

revision = "048_authorization_catalog"
down_revision = "047_email_verification_tokens"
branch_labels = None
depends_on = None


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _create_tables(bind) -> None:
    existing = _tables(bind)
    if "authorization_roles" not in existing:
        op.create_table(
            "authorization_roles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("code", sa.String(64), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("scope", sa.String(16), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
            sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("is_assignable", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["iam_users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("scope", "code", name="uq_authorization_roles_scope_code"),
            sa.CheckConstraint("scope IN ('PLATFORM','TENANT')", name="authorization_role_scope"),
            sa.CheckConstraint(
                "status IN ('ACTIVE','DISABLED','DRAFT')",
                name="authorization_role_status",
            ),
            sa.CheckConstraint("version >= 1", name="authorization_role_version"),
            sa.CheckConstraint("length(trim(code)) > 0", name="authorization_role_code_not_blank"),
            sa.CheckConstraint("length(trim(name)) > 0", name="authorization_role_name_not_blank"),
            sa.CheckConstraint("code = upper(code)", name="authorization_role_code_normalized"),
        )
        op.create_index("ix_authorization_roles_scope", "authorization_roles", ["scope"])
        op.create_index("ix_authorization_roles_status", "authorization_roles", ["status"])

    existing = _tables(bind)
    if "authorization_permissions" not in existing:
        op.create_table(
            "authorization_permissions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("code", sa.String(128), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("scope", sa.String(16), nullable=False),
            sa.Column("resource", sa.String(128), nullable=False),
            sa.Column("action", sa.String(64), nullable=False),
            sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
            sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("code", name="uq_authorization_permissions_code"),
            sa.CheckConstraint("scope IN ('PLATFORM','TENANT')", name="authorization_permission_scope"),
            sa.CheckConstraint("status IN ('ACTIVE','DISABLED')", name="authorization_permission_status"),
            sa.CheckConstraint(
                "length(trim(code)) > 0",
                name="authorization_permission_code_not_blank",
            ),
            sa.CheckConstraint(
                "length(trim(name)) > 0",
                name="authorization_permission_name_not_blank",
            ),
            sa.CheckConstraint(
                "code = lower(code) AND code NOT LIKE '% %'",
                name="authorization_permission_code_normalized",
            ),
        )
        for name, columns in (
            ("ix_authorization_permissions_code", ["code"]),
            ("ix_authorization_permissions_scope", ["scope"]),
            ("ix_authorization_permissions_resource", ["resource"]),
            ("ix_authorization_permissions_action", ["action"]),
            ("ix_authorization_permissions_status", ["status"]),
        ):
            op.create_index(name, "authorization_permissions", columns)

    existing = _tables(bind)
    if "authorization_role_permissions" not in existing:
        op.create_table(
            "authorization_role_permissions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("role_id", sa.Integer(), nullable=False),
            sa.Column("permission_id", sa.Integer(), nullable=False),
            sa.Column("is_protected", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["role_id"], ["authorization_roles.id"], ondelete="RESTRICT"
            ),
            sa.ForeignKeyConstraint(
                ["permission_id"],
                ["authorization_permissions.id"],
                ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(
                ["created_by_user_id"], ["iam_users.id"], ondelete="SET NULL"
            ),
            sa.UniqueConstraint(
                "role_id",
                "permission_id",
                name="uq_authorization_role_permissions_role_permission",
            ),
        )
        op.create_index(
            "ix_authorization_role_permissions_role_id",
            "authorization_role_permissions",
            ["role_id"],
        )
        op.create_index(
            "ix_authorization_role_permissions_permission_id",
            "authorization_role_permissions",
            ["permission_id"],
        )


def _permission_parts(code: str) -> tuple[str, str]:
    parts = code.split(":")
    return ":".join(parts[:-1]), parts[-1]


def _seed(bind) -> None:
    now = datetime.now(UTC)
    role_table = sa.table(
        "authorization_roles",
        sa.column("id", sa.Integer),
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("scope", sa.String),
        sa.column("status", sa.String),
        sa.column("is_system", sa.Boolean),
        sa.column("is_assignable", sa.Boolean),
        sa.column("version", sa.Integer),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    permission_table = sa.table(
        "authorization_permissions",
        sa.column("id", sa.Integer),
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("scope", sa.String),
        sa.column("resource", sa.String),
        sa.column("action", sa.String),
        sa.column("status", sa.String),
        sa.column("is_system", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    mapping_table = sa.table(
        "authorization_role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
        sa.column("is_protected", sa.Boolean),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )

    existing_roles = set(bind.execute(sa.select(role_table.c.code)).scalars())
    for code, scope in ROLE_SCOPES_V1.items():
        if code not in existing_roles:
            bind.execute(
                role_table.insert().values(
                    code=code,
                    name=code.replace("_", " ").title(),
                    description=f"System {scope.lower()} role {code}.",
                    scope=scope,
                    status="ACTIVE",
                    is_system=True,
                    is_assignable=True,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

    existing_permissions = set(
        bind.execute(sa.select(permission_table.c.code)).scalars()
    )
    for code in ALL_PERMISSIONS_V1:
        if code not in existing_permissions:
            resource, action = _permission_parts(code)
            bind.execute(
                permission_table.insert().values(
                    code=code,
                    name=code.replace(":", " ").replace("-", " ").title(),
                    description=f"Allows {action} access to {resource}.",
                    scope="PLATFORM" if code.startswith("platform:") else "TENANT",
                    resource=resource,
                    action=action,
                    status="ACTIVE",
                    is_system=True,
                    created_at=now,
                    updated_at=now,
                )
            )

    role_ids = dict(bind.execute(sa.select(role_table.c.code, role_table.c.id)).all())
    permission_ids = dict(
        bind.execute(sa.select(permission_table.c.code, permission_table.c.id)).all()
    )
    existing_mappings = set(
        bind.execute(
            sa.select(mapping_table.c.role_id, mapping_table.c.permission_id)
        ).all()
    )
    for role_code, permission_codes in ROLE_PERMISSIONS_V1.items():
        protected = set(PROTECTED_ROLE_PERMISSIONS_V1.get(role_code, ()))
        for permission_code in permission_codes:
            key = (role_ids[role_code], permission_ids[permission_code])
            if key not in existing_mappings:
                bind.execute(
                    mapping_table.insert().values(
                        role_id=key[0],
                        permission_id=key[1],
                        is_protected=permission_code in protected,
                        created_at=now,
                        updated_at=now,
                    )
                )


def _validate_existing_assignments(bind) -> None:
    tables = _tables(bind)
    if "tenant_users" in tables:
        unknown = set(
            bind.execute(
                sa.text(
                    "SELECT DISTINCT role FROM tenant_users "
                    "WHERE role IS NOT NULL AND role NOT IN "
                    "('TENANT_ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')"
                )
            ).scalars()
        )
        if unknown:
            raise RuntimeError(
                "Unsupported tenant role assignments block authorization catalogue migration: "
                + ", ".join(sorted(unknown))
            )
    if "platform_user_roles" in tables:
        unknown = set(
            bind.execute(
                sa.text(
                    "SELECT DISTINCT role FROM platform_user_roles "
                    "WHERE role IS NOT NULL AND role <> 'PLATFORM_ADMIN'"
                )
            ).scalars()
        )
        if unknown:
            raise RuntimeError(
                "Unsupported platform role assignments block authorization catalogue migration: "
                + ", ".join(sorted(unknown))
            )


def _validate_seeded_catalog(bind) -> None:
    for role_code, expected_codes in ROLE_PERMISSIONS_V1.items():
        rows = bind.execute(
            sa.text(
                """
                SELECT p.code, r.scope AS role_scope, p.scope AS permission_scope,
                       r.status AS role_status, p.status AS permission_status
                FROM authorization_roles r
                JOIN authorization_role_permissions rp ON rp.role_id = r.id
                JOIN authorization_permissions p ON p.id = rp.permission_id
                WHERE r.code = :role_code
                """
            ),
            {"role_code": role_code},
        ).mappings().all()
        actual = {row["code"] for row in rows}
        if actual != set(expected_codes):
            raise RuntimeError(
                f"Authorization catalogue seed mismatch for role {role_code}"
            )
        if any(
            row["role_status"] != "ACTIVE"
            or row["permission_status"] != "ACTIVE"
            or (
                row["role_scope"] != row["permission_scope"]
                and role_code != "PLATFORM_ADMIN"
            )
            for row in rows
        ):
            raise RuntimeError(
                f"Authorization catalogue contains inactive or cross-scope mappings for {role_code}"
            )


def _audit_seed(bind) -> None:
    if "authorization_audit_log" not in _tables(bind):
        return
    audit_table = sa.table(
        "authorization_audit_log",
        sa.column("action", sa.String),
        sa.column("outcome", sa.String),
        sa.column("new_value", sa.JSON),
        sa.column("detail", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    bind.execute(
        audit_table.insert().values(
            action="AUTHORIZATION_CATALOG_SEEDED",
            outcome="SUCCESS",
            new_value={
                "role_count": len(ROLE_PERMISSIONS_V1),
                "permission_count": len(ALL_PERMISSIONS_V1),
            },
            detail="Revision 048 installed immutable catalogue seed",
            created_at=datetime.now(UTC),
        )
    )


def upgrade() -> None:
    bind = op.get_bind()
    # Alembic's default 32-character version column is too small for this
    # repository's descriptive revision identifiers.
    if bind.dialect.name == "postgresql" and "alembic_version" in _tables(bind):
        op.execute(
            "ALTER TABLE alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(128)"
        )
    _validate_existing_assignments(bind)
    _create_tables(bind)
    _seed(bind)
    _validate_seeded_catalog(bind)
    _audit_seed(bind)


def downgrade() -> None:
    bind = op.get_bind()
    existing = _tables(bind)
    if "authorization_role_permissions" in existing:
        op.drop_table("authorization_role_permissions")
    if "authorization_permissions" in existing:
        op.drop_table("authorization_permissions")
    if "authorization_roles" in existing:
        op.drop_table("authorization_roles")
    # Intentionally do not narrow alembic_version; later descriptive revision
    # identifiers may still need the safe width after a catalogue rollback.
