"""Add HCL IAM identity mapping and tenant isolation.

Revision ID: 033_hcl_iam_multitenancy
Revises: 032_postgres_compat
Create Date: 2026-06-22
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "033_hcl_iam_multitenancy"
down_revision = "032_postgres_compat"
branch_labels = None
depends_on = None

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

TENANT_TABLES = (
    "projects", "sbom_source", "sbom_validation_sessions",
    "sbom_validation_session_events", "sbom_analysis_report", "sbom_component",
    "vex_documents", "vex_statements", "component_lifecycle_override_audit",
    "vex_override_audit", "analysis_run", "analysis_finding", "run_cache",
    "analysis_schedule", "compare_cache", "ai_usage_log", "ai_fix_batch",
    "audit_log", "vulnerability_remediation", "vulnerability_remediation_audit",
)


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _columns(bind, table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _indexes(bind, table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes(table)}


def _foreign_key_exists(bind, table: str, columns: list[str]) -> bool:
    return any(
        fk.get("constrained_columns") == columns
        for fk in sa.inspect(bind).get_foreign_keys(table)
    )


def _create_identity_tables(bind) -> None:
    tables = _tables(bind)
    if "tenants" not in tables:
        op.create_table(
            "tenants",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("slug", sa.String(128), nullable=False),
            sa.Column("external_iam_tenant_id", sa.String(255), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("slug", name="uq_tenants_slug"),
            sa.UniqueConstraint("external_iam_tenant_id", name="uq_tenants_external_iam_tenant_id"),
        )
    if "iam_users" not in tables:
        op.create_table(
            "iam_users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("external_iam_user_id", sa.String(255), nullable=False),
            sa.Column("email", sa.String(320), nullable=True),
            sa.Column("display_name", sa.String(255), nullable=True),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("external_iam_user_id", name="uq_iam_users_external_iam_user_id"),
        )
    if "tenant_users" not in tables:
        op.create_table(
            "tenant_users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("role", sa.String(64), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_tenant_users_tenant_id_tenants", ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["iam_users.id"], name="fk_tenant_users_user_id_iam_users", ondelete="CASCADE"),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_tenant_users_tenant_user"),
        )
    for name, table, columns, unique in (
        ("ix_tenants_slug", "tenants", ["slug"], False),
        ("ix_tenants_external_iam_tenant_id", "tenants", ["external_iam_tenant_id"], False),
        ("ix_iam_users_external_iam_user_id", "iam_users", ["external_iam_user_id"], False),
        ("ix_iam_users_email", "iam_users", ["email"], False),
        ("ix_tenant_users_tenant_id", "tenant_users", ["tenant_id"], False),
        ("ix_tenant_users_user_id", "tenant_users", ["user_id"], False),
        ("ix_tenant_users_tenant_status", "tenant_users", ["tenant_id", "status"], False),
    ):
        if name not in _indexes(bind, table):
            op.create_index(name, table, columns, unique=unique)


def _seed_default_identity(bind) -> None:
    now = datetime.now(UTC).isoformat()
    bind.execute(
        sa.text(
            "INSERT INTO tenants (id,name,slug,external_iam_tenant_id,status,created_at,updated_at) "
            "SELECT 1,'Default Tenant','default','local-default','ACTIVE',:now,:now "
            "WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id=1)"
        ),
        {"now": now},
    )
    bind.execute(
        sa.text(
            "INSERT INTO iam_users (id,external_iam_user_id,email,display_name,status,last_login_at,created_at,updated_at) "
            "SELECT 1,'local-dev-admin','local-admin@localhost','Local Development Admin','ACTIVE',:now,:now,:now "
            "WHERE NOT EXISTS (SELECT 1 FROM iam_users WHERE id=1)"
        ),
        {"now": now},
    )
    bind.execute(
        sa.text(
            "INSERT INTO tenant_users (tenant_id,user_id,role,status,created_at,updated_at) "
            "SELECT 1,1,'TENANT_ADMIN','ACTIVE',:now,:now "
            "WHERE NOT EXISTS (SELECT 1 FROM tenant_users WHERE tenant_id=1 AND user_id=1)"
        ),
        {"now": now},
    )


def _tenantize_table(bind, table: str) -> None:
    if table not in _tables(bind):
        return
    if "tenant_id" not in _columns(bind, table):
        op.add_column(table, sa.Column("tenant_id", sa.Integer(), nullable=True))
    bind.execute(sa.text(f'UPDATE "{table}" SET tenant_id=1 WHERE tenant_id IS NULL'))
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table, naming_convention=NAMING) as batch:
            batch.alter_column("tenant_id", existing_type=sa.Integer(), nullable=False)
            if not _foreign_key_exists(bind, table, ["tenant_id"]):
                batch.create_foreign_key(
                    f"fk_{table}_tenant_id_tenants", "tenants", ["tenant_id"], ["id"]
                )
    else:
        op.alter_column(table, "tenant_id", existing_type=sa.Integer(), nullable=False)
        if not _foreign_key_exists(bind, table, ["tenant_id"]):
            op.create_foreign_key(
                f"fk_{table}_tenant_id_tenants", table, "tenants", ["tenant_id"], ["id"]
            )
    existing_indexes = _indexes(bind, table)
    if f"ix_{table}_tenant_id" not in existing_indexes:
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    pk = sa.inspect(bind).get_pk_constraint(table).get("constrained_columns") or []
    if pk and f"ix_{table}_tenant_identity" not in existing_indexes:
        op.create_index(f"ix_{table}_tenant_identity", table, ["tenant_id", pk[0]])


def _audit_columns(bind) -> None:
    additions = (
        sa.Column("user_ref_id", sa.Integer(), nullable=True),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("old_value", sa.JSON(), nullable=True),
        sa.Column("new_value", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
    )
    for column in additions:
        if column.name not in _columns(bind, "audit_log"):
            op.add_column("audit_log", column)
    if not _foreign_key_exists(bind, "audit_log", ["user_ref_id"]):
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("audit_log", naming_convention=NAMING) as batch:
                batch.create_foreign_key(
                    "fk_audit_log_user_ref_id_iam_users", "iam_users", ["user_ref_id"], ["id"], ondelete="SET NULL"
                )
        else:
            op.create_foreign_key(
                "fk_audit_log_user_ref_id_iam_users", "audit_log", "iam_users", ["user_ref_id"], ["id"], ondelete="SET NULL"
            )
    for name, column in (
        ("ix_audit_log_user_ref_id", "user_ref_id"),
        ("ix_audit_log_entity_type", "entity_type"),
        ("ix_audit_log_entity_id", "entity_id"),
    ):
        if name not in _indexes(bind, "audit_log"):
            op.create_index(name, "audit_log", [column])


def _scoped_unique(bind, table: str, name: str, columns: list[str]) -> None:
    constraints = {item["name"]: item for item in sa.inspect(bind).get_unique_constraints(table)}
    existing = constraints.get(name)
    if existing and existing.get("column_names") == columns:
        return
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table, naming_convention=NAMING) as batch:
            if existing:
                batch.drop_constraint(name, type_="unique")
            batch.create_unique_constraint(name, columns)
    else:
        if existing:
            op.drop_constraint(name, table, type_="unique")
        op.create_unique_constraint(name, table, columns)


def upgrade() -> None:
    bind = op.get_bind()
    _create_identity_tables(bind)
    _seed_default_identity(bind)
    for table in TENANT_TABLES:
        _tenantize_table(bind, table)
    _audit_columns(bind)
    _scoped_unique(bind, "projects", "uq_projects_tenant_name", ["tenant_id", "project_name"])
    _scoped_unique(
        bind,
        "sbom_source",
        "uq_sbom_source_tenant_name_version",
        ["tenant_id", "sbom_name", "sbom_version"],
    )
    _scoped_unique(
        bind,
        "sbom_component",
        "uq_sbom_component_fingerprint",
        ["tenant_id", "sbom_id", "bom_ref", "name", "version", "cpe"],
    )
    for name, table, columns in (
        ("ix_projects_tenant_created", "projects", ["tenant_id", "created_on"]),
        ("ix_sbom_source_tenant_created", "sbom_source", ["tenant_id", "created_on"]),
        ("ix_sbom_source_tenant_project", "sbom_source", ["tenant_id", "projectid"]),
    ):
        if name not in _indexes(bind, table):
            op.create_index(name, table, columns)


def downgrade() -> None:
    # Tenant removal would destroy the isolation boundary and make existing
    # memberships ambiguous. Restore from a pre-migration backup instead.
    raise RuntimeError("Downgrading HCL IAM multitenancy is intentionally unsupported")
