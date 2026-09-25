"""Add native identity foundation alongside HCL.CS.

Revision ID: 060_native_identity_foundation
Revises: 059_vex_analyzer_sources

Global profile-email uniqueness is deliberately deferred: HCL profile emails
are mutable and historically non-unique. Native canonical identifiers have a
database unique index from day one. No users are merged or linked by email.
"""

from collections import defaultdict
import warnings

import sqlalchemy as sa
from alembic import context, op

revision = "060_native_identity_foundation"
down_revision = "059_vex_analyzer_sources"
branch_labels = None
depends_on = None

_NEW_STATUS = "status IN ('ACTIVE','PENDING','DISABLED','PENDING_EMAIL_VERIFICATION','LOCKED','FORCE_PASSWORD_CHANGE')"


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("Native identity migration requires an online connection for data-quality inspection.")
    bind = op.get_bind()
    # Lock the global identity tables during this operator-run migration so
    # normalization/backfill observes the same rows as the DDL transaction.
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("LOCK TABLE iam_users IN ACCESS EXCLUSIVE MODE"))
    for name, length in (("first_name", 255), ("last_name", 255), ("phone", 64), ("normalized_email", 320)):
        op.add_column("iam_users", sa.Column(name, sa.String(length), nullable=True))
    op.create_index("ix_iam_users_normalized_email", "iam_users", ["normalized_email"])
    op.alter_column("iam_users", "external_iam_user_id", existing_type=sa.String(255), nullable=True)
    op.drop_constraint(op.f("ck_iam_users_iam_user_status"), "iam_users", type_="check")
    op.create_check_constraint("iam_user_status", "iam_users", _NEW_STATUS)

    op.create_table(
        "user_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_type", sa.String(16), nullable=False),
        sa.Column("issuer", sa.String(512)),
        sa.Column("subject", sa.String(255)),
        sa.Column("provider_identifier", sa.String(320)),
        sa.Column("provider_email", sa.String(320)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("user_id", "provider_type", name="uq_user_identities_user_provider"),
        sa.UniqueConstraint("provider_type", "issuer", "subject", name="uq_user_identities_external"),
        sa.CheckConstraint("provider_type IN ('HCL_CS','NATIVE')", name="identity_provider"),
        sa.CheckConstraint(
            "(provider_type = 'HCL_CS' AND issuer IS NOT NULL AND length(trim(issuer)) > 0 "
            "AND subject IS NOT NULL AND length(trim(subject)) > 0) OR "
            "(provider_type = 'NATIVE' AND issuer IS NULL AND subject IS NULL "
            "AND provider_identifier IS NOT NULL AND length(trim(provider_identifier)) > 0 "
            "AND provider_identifier = lower(trim(provider_identifier)))",
            name="identity_provider_fields",
        ),
    )
    op.create_index("ix_user_identities_user_id", "user_identities", ["user_id"])
    op.create_index(
        "uq_user_identities_native_email",
        "user_identities",
        ["provider_identifier"],
        unique=True,
        postgresql_where=sa.text("provider_type = 'NATIVE'"),
    )
    groups = defaultdict(list)
    deferred = []
    # Freeze the canonicalization here: never import mutable application logic
    # into a historical migration. Match str.strip().lower() exactly.
    for row in bind.execute(sa.text("SELECT * FROM iam_users")).mappings().all():
        canonical = (row["email"].strip().lower() or None) if row["email"] is not None else None
        bind.execute(
            sa.text("UPDATE iam_users SET normalized_email=:email WHERE id=:id"), {"email": canonical, "id": row["id"]}
        )
        if canonical:
            groups[canonical].append(row["id"])
        if row["external_issuer"] and row["external_subject"]:
            bind.execute(
                sa.text(
                    "INSERT INTO user_identities (user_id, provider_type, issuer, subject, provider_identifier, "
                    "provider_email, created_at, updated_at, last_authenticated_at) "
                    "VALUES (:id, 'HCL_CS', :issuer, :subject, :identifier, :email, :created, :updated, :last)"
                ),
                {
                    "id": row["id"],
                    "issuer": row["external_issuer"],
                    "subject": row["external_subject"],
                    "identifier": row["external_iam_user_id"],
                    "email": row["email"],
                    "created": row["created_at"],
                    "updated": row["updated_at"],
                    "last": row["last_login_at"],
                },
            )
        elif row["external_iam_user_id"]:
            deferred.append(row["id"])
    collisions = [ids for ids in groups.values() if len(ids) > 1]
    if collisions:
        warnings.warn(
            f"Duplicate normalized profile emails for user IDs {collisions}. Global profile-email uniqueness "
            "is deferred. Run scripts/check_native_identity_data.py and resolve explicitly before a future "
            "global uniqueness migration. Native identifiers remain unique. No accounts were merged.",
            stacklevel=2,
        )
    if deferred:
        warnings.warn(
            f"HCL identity backfill deferred for user IDs {deferred}: issuer/subject incomplete. "
            "Legacy columns remain authoritative; next trusted HCL login fills the identity.",
            stacklevel=2,
        )

    op.create_table(
        "native_user_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False, unique=True
        ),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("password_hash_scheme", sa.String(32), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("security_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("failed_login_count >= 0 AND security_version >= 1", name="native_security_counters"),
        sa.CheckConstraint(
            "password_hash_scheme = 'argon2id' AND password_hash LIKE '$argon2id$%'", name="native_password_scheme"
        ),
    )
    op.create_table(
        "account_action_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("email_snapshot", sa.String(320), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "purpose IN ('ACCOUNT_ACTIVATION','PASSWORD_RESET','EMAIL_CHANGE')", name="account_action_purpose"
        ),
        sa.CheckConstraint("expires_at > created_at", name="account_action_expiry"),
        sa.CheckConstraint("consumed_at IS NULL OR consumed_at >= created_at", name="account_action_consumed_time"),
        sa.CheckConstraint(
            "invalidated_at IS NULL OR invalidated_at >= created_at", name="account_action_invalidated_time"
        ),
    )
    op.create_index("ix_account_action_tokens_user_id", "account_action_tokens", ["user_id"])
    op.create_index("ix_account_action_tokens_expires_at", "account_action_tokens", ["expires_at"])
    op.create_index(
        "uq_account_action_tokens_active",
        "account_action_tokens",
        ["user_id", "purpose"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL AND invalidated_at IS NULL"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if context.is_offline_mode():
        raise RuntimeError("Native identity downgrade requires online safety checks.")
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                "LOCK TABLE iam_users, user_identities, native_user_credentials, account_action_tokens IN ACCESS EXCLUSIVE MODE"
            )
        )
    unsafe = bind.scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM iam_users WHERE external_iam_user_id IS NULL "
            "OR status NOT IN ('ACTIVE','PENDING','DISABLED') OR first_name IS NOT NULL OR last_name IS NOT NULL OR phone IS NOT NULL) "
            "OR EXISTS(SELECT 1 FROM user_identities WHERE provider_type='NATIVE') "
            "OR EXISTS(SELECT 1 FROM native_user_credentials) OR EXISTS(SELECT 1 FROM account_action_tokens)"
        )
    )
    if unsafe:
        raise RuntimeError(
            "Refusing downgrade: native identity/profile/security data exists. Export and explicitly remediate it before retrying; no data was deleted."
        )
    op.drop_table("account_action_tokens")
    op.drop_table("native_user_credentials")
    op.drop_table("user_identities")
    op.drop_constraint(op.f("ck_iam_users_iam_user_status"), "iam_users", type_="check")
    op.create_check_constraint("iam_user_status", "iam_users", "status IN ('ACTIVE','PENDING','DISABLED')")
    op.alter_column("iam_users", "external_iam_user_id", existing_type=sa.String(255), nullable=False)
    op.drop_index("ix_iam_users_normalized_email", table_name="iam_users")
    for name in ("normalized_email", "phone", "last_name", "first_name"):
        op.drop_column("iam_users", name)
