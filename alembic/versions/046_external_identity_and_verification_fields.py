"""Add composite external identity and verification compatibility fields.

Revision ID: 046_external_identity_and_verification_fields
Revises: 045_secure_authorization_model
Create Date: 2026-07-26
"""

from __future__ import annotations

import os
import warnings
from urllib.parse import urlsplit

import sqlalchemy as sa
from alembic import context, op

revision = "046_external_identity_and_verification_fields"
down_revision = "045_secure_authorization_model"
branch_labels = None
depends_on = None

_ISSUER_ENVIRONMENT_VARIABLE = "SBOM_IDENTITY_BACKFILL_ISSUER"


def _column_exists(bind, column: str) -> bool:
    return column in {item["name"] for item in sa.inspect(bind).get_columns("iam_users")}


def _index_exists(bind, index: str) -> bool:
    return index in {item["name"] for item in sa.inspect(bind).get_indexes("iam_users")}


def _unique_exists(bind, name: str) -> bool:
    return name in {item["name"] for item in sa.inspect(bind).get_unique_constraints("iam_users")}


def _check_exists(bind, name: str) -> bool:
    return name in {item["name"] for item in sa.inspect(bind).get_check_constraints("iam_users")}


def _validated_backfill_issuer(*, required: bool) -> str | None:
    value = (os.getenv(_ISSUER_ENVIRONMENT_VARIABLE) or "").strip()
    if not value:
        if required:
            raise RuntimeError(
                "iam_users contains identities requiring issuer backfill. Set "
                "SBOM_IDENTITY_BACKFILL_ISSUER to the exact trusted HCL.CS JWT issuer "
                "and rerun the migration. No issuer was fabricated and no users were merged."
            )
        return None
    if len(value) > 512:
        raise RuntimeError("SBOM_IDENTITY_BACKFILL_ISSUER exceeds 512 characters")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "SBOM_IDENTITY_BACKFILL_ISSUER must be an absolute HTTPS URL without credentials, query, or fragment"
        )
    return value


def _duplicate_group_count(bind, expression: str, *, where: str = "") -> int:
    statement = (
        f"SELECT COUNT(*) FROM (SELECT {expression} FROM iam_users "
        f"{where} GROUP BY {expression} HAVING COUNT(*) > 1) duplicate_groups"
    )
    return int(bind.execute(sa.text(statement)).scalar_one())


def _validate_online_data(bind) -> str | None:
    rows_requiring_backfill = int(
        bind.execute(
            sa.text(
                "SELECT COUNT(*) FROM iam_users "
                "WHERE external_issuer IS NULL OR external_subject IS NULL"
            )
        ).scalar_one()
    )
    issuer = _validated_backfill_issuer(required=rows_requiring_backfill > 0)

    duplicate_legacy = _duplicate_group_count(
        bind,
        "external_iam_user_id",
        where="WHERE external_iam_user_id IS NOT NULL",
    )
    if duplicate_legacy:
        raise RuntimeError(
            f"Cannot migrate: {duplicate_legacy} duplicate external_iam_user_id group(s) exist. "
            "No records were merged. Remediate with: SELECT external_iam_user_id, COUNT(*) "
            "FROM iam_users GROUP BY external_iam_user_id HAVING COUNT(*) > 1"
        )

    duplicate_email = _duplicate_group_count(
        bind,
        "lower(trim(email))",
        where="WHERE email IS NOT NULL AND trim(email) <> ''",
    )
    if duplicate_email:
        warnings.warn(
            f"iam_users contains {duplicate_email} duplicate normalized email group(s); "
            "email remains non-unique and is not an identity key",
            stacklevel=2,
        )
    duplicate_upn = _duplicate_group_count(
        bind,
        "lower(trim(user_principal_name))",
        where="WHERE user_principal_name IS NOT NULL AND trim(user_principal_name) <> ''",
    )
    if duplicate_upn:
        warnings.warn(
            f"iam_users contains {duplicate_upn} duplicate normalized UPN group(s); "
            "UPN remains non-unique and is not an identity key",
            stacklevel=2,
        )
    return issuer


def _emit_offline_duplicate_guards() -> None:
    # Offline rendering targets PostgreSQL, the authoritative deployment
    # database. These guards execute before the unique constraint in the
    # generated script and preserve all rows when duplicates exist.
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM iam_users
            WHERE external_iam_user_id IS NOT NULL
            GROUP BY external_iam_user_id HAVING COUNT(*) > 1
          ) THEN
            RAISE EXCEPTION 'Duplicate external_iam_user_id values require remediation; no rows were merged';
          END IF;
        END $$;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM iam_users
            WHERE external_issuer IS NOT NULL AND external_subject IS NOT NULL
            GROUP BY external_issuer, external_subject HAVING COUNT(*) > 1
          ) THEN
            RAISE EXCEPTION 'Duplicate external issuer/subject pairs require remediation; no rows were merged';
          END IF;
        END $$;
        """
    )


def upgrade() -> None:
    offline = context.is_offline_mode()
    bind = op.get_bind()
    columns = (
        sa.Column("external_issuer", sa.String(512), nullable=True),
        sa.Column("external_subject", sa.String(255), nullable=True),
        sa.Column("employee_id", sa.String(128), nullable=True),
        sa.Column("user_principal_name", sa.String(320), nullable=True),
        sa.Column("department", sa.String(255), nullable=True),
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_claim_sync_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in columns:
        if offline or not _column_exists(bind, str(column.name)):
            op.add_column("iam_users", column)

    issuer = _validated_backfill_issuer(required=True) if offline else _validate_online_data(bind)

    if issuer is not None:
        bind.execute(
            sa.text(
                "UPDATE iam_users "
                "SET external_subject = COALESCE(external_subject, external_iam_user_id), "
                "external_issuer = COALESCE(external_issuer, :issuer) "
                "WHERE external_subject IS NULL OR external_issuer IS NULL"
            ).bindparams(issuer=issuer)
        )

    bind.execute(
        sa.text(
            """
            UPDATE iam_users
            SET email_verified = CASE
                    WHEN status = 'ACTIVE'
                     AND (
                       EXISTS (
                         SELECT 1 FROM tenant_users
                         WHERE tenant_users.user_id = iam_users.id
                           AND tenant_users.status = 'ACTIVE'
                       )
                       OR EXISTS (
                         SELECT 1 FROM platform_user_roles
                         WHERE platform_user_roles.user_id = iam_users.id
                           AND platform_user_roles.status = 'ACTIVE'
                       )
                     )
                    THEN true ELSE false
                END,
                verification_required = CASE
                    WHEN status = 'ACTIVE'
                     AND (
                       EXISTS (
                         SELECT 1 FROM tenant_users
                         WHERE tenant_users.user_id = iam_users.id
                           AND tenant_users.status = 'ACTIVE'
                       )
                       OR EXISTS (
                         SELECT 1 FROM platform_user_roles
                         WHERE platform_user_roles.user_id = iam_users.id
                           AND platform_user_roles.status = 'ACTIVE'
                       )
                     )
                    THEN false ELSE true
                END,
                email_verified_at = CASE
                    WHEN status = 'ACTIVE'
                     AND (
                       EXISTS (
                         SELECT 1 FROM tenant_users
                         WHERE tenant_users.user_id = iam_users.id
                           AND tenant_users.status = 'ACTIVE'
                       )
                       OR EXISTS (
                         SELECT 1 FROM platform_user_roles
                         WHERE platform_user_roles.user_id = iam_users.id
                           AND platform_user_roles.status = 'ACTIVE'
                       )
                     )
                    THEN COALESCE(created_at, CURRENT_TIMESTAMP)
                    ELSE NULL
                END
            """
        )
    )

    if offline:
        _emit_offline_duplicate_guards()
    else:
        duplicate_identity = _duplicate_group_count(
            bind,
            "external_issuer, external_subject",
            where="WHERE external_issuer IS NOT NULL AND external_subject IS NOT NULL",
        )
        if duplicate_identity:
            raise RuntimeError(
                f"Cannot migrate: {duplicate_identity} duplicate external identity group(s) exist. "
                "No records were merged. Remediate with: SELECT external_issuer, external_subject, COUNT(*) "
                "FROM iam_users GROUP BY external_issuer, external_subject HAVING COUNT(*) > 1"
            )

    if offline or not _index_exists(bind, "ix_iam_users_employee_id"):
        op.create_index("ix_iam_users_employee_id", "iam_users", ["employee_id"])
    if offline or not _index_exists(bind, "ix_iam_users_user_principal_name"):
        op.create_index("ix_iam_users_user_principal_name", "iam_users", ["user_principal_name"])
    if offline or not _index_exists(bind, "ix_iam_users_verification_status"):
        op.create_index(
            "ix_iam_users_verification_status",
            "iam_users",
            ["verification_required", "status"],
        )
    with op.batch_alter_table("iam_users") as batch:
        if offline or not _unique_exists(bind, "uq_iam_users_external_identity"):
            batch.create_unique_constraint(
                "uq_iam_users_external_identity",
                ["external_issuer", "external_subject"],
            )
        if offline or not _check_exists(bind, "ck_iam_users_external_issuer_not_blank"):
            batch.create_check_constraint(
                "external_issuer_not_blank",
                "external_issuer IS NULL OR length(trim(external_issuer)) > 0",
            )
        if offline or not _check_exists(bind, "ck_iam_users_external_subject_not_blank"):
            batch.create_check_constraint(
                "external_subject_not_blank",
                "external_subject IS NULL OR length(trim(external_subject)) > 0",
            )
        if offline or not _check_exists(bind, "ck_iam_users_email_verification_timestamp"):
            batch.create_check_constraint(
                "email_verification_timestamp",
                "email_verified = false OR email_verified_at IS NOT NULL",
            )

    # Issuer/subject deliberately remain nullable in Phase 3 so historical
    # non-HCL rows and local-development compatibility paths are not assigned
    # fabricated identities. Authenticated HCL.CS writes validate both fields.


def downgrade() -> None:
    op.drop_index("ix_iam_users_verification_status", table_name="iam_users")
    op.drop_index("ix_iam_users_user_principal_name", table_name="iam_users")
    op.drop_index("ix_iam_users_employee_id", table_name="iam_users")
    with op.batch_alter_table("iam_users") as batch:
        batch.drop_constraint("uq_iam_users_external_identity", type_="unique")
        batch.drop_constraint("external_issuer_not_blank", type_="check")
        batch.drop_constraint("external_subject_not_blank", type_="check")
        batch.drop_constraint("email_verification_timestamp", type_="check")
        batch.drop_column("last_claim_sync_at")
        batch.drop_column("verification_required")
        batch.drop_column("email_verified_at")
        batch.drop_column("email_verified")
        batch.drop_column("department")
        batch.drop_column("user_principal_name")
        batch.drop_column("employee_id")
        batch.drop_column("external_subject")
        batch.drop_column("external_issuer")
