"""ai_provider_credential + ai_settings + ai_credential_audit_log.

Revision ID: 010_ai_credentials
Revises: 009_ai_fix_cache
Create Date: 2026-05-04

Phase 2 §2.2 / §2.3 / §2.6 schemas:

  * ``ai_provider_credential`` — AES-GCM encrypted API keys + per-row
    metadata (provider, model, tier, default/fallback flags, last-test
    state). Tenant-shared by design (single-admin v1).

  * ``ai_settings`` — singleton row (``id = 1`` enforced at the
    constraint level). Per-org AI knobs (feature flag, kill switch,
    budget caps).

  * ``ai_credential_audit_log`` — append-only audit trail of every
    credential mutation. Stores user_id + action + target_id only —
    never the credential payload (Phase 2 §2.6 hard rule).

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-009.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "010_ai_credentials"
down_revision = "009_ai_fix_cache"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    # ------------------------------------------------------------------
    # ai_provider_credential
    # ------------------------------------------------------------------
    if not _table_exists(bind, "ai_provider_credential"):
        op.create_table(
            "ai_provider_credential",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("provider_name", sa.String(length=32), nullable=False),
            # ``label`` scaffolds for "multiple keys per provider" — UI
            # hides this in v1 so every row is "default". Phase 2 OOS.
            sa.Column(
                "label",
                sa.String(length=64),
                nullable=False,
                server_default=sa.text("'default'"),
            ),
            sa.Column("api_key_encrypted", sa.Text(), nullable=True),
            sa.Column("base_url", sa.String(length=512), nullable=True),
            sa.Column("default_model", sa.String(length=128), nullable=True),
            sa.Column(
                "tier",
                sa.String(length=16),
                nullable=False,
                server_default=sa.text("'paid'"),
            ),
            sa.Column(
                "is_default",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "is_fallback",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("1"),
            ),
            # Custom-OpenAI-compatible cost overrides (zeros for built-ins).
            sa.Column(
                "cost_per_1k_input_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "cost_per_1k_output_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "is_local",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("max_concurrent", sa.Integer(), nullable=True),
            sa.Column("rate_per_minute", sa.Float(), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("last_test_at", sa.String(), nullable=True),
            sa.Column("last_test_success", sa.Boolean(), nullable=True),
            sa.Column("last_test_error", sa.Text(), nullable=True),
            sa.UniqueConstraint(
                "provider_name", "label", name="uq_ai_provider_credential_provider_label"
            ),
        )

    if not _index_exists(bind, "ai_provider_credential", "ix_ai_provider_credential_provider_name"):
        op.create_index(
            "ix_ai_provider_credential_provider_name",
            "ai_provider_credential",
            ["provider_name"],
        )

    # Singleton constraints — only one row may carry is_default=true,
    # only one may carry is_fallback=true. Implemented via partial
    # unique indices (Postgres + SQLite ≥ 3.8 both support these).
    if not _index_exists(bind, "ai_provider_credential", "ix_ai_only_one_default"):
        op.create_index(
            "ix_ai_only_one_default",
            "ai_provider_credential",
            ["is_default"],
            unique=True,
            sqlite_where=sa.text("is_default = 1"),
            postgresql_where=sa.text("is_default = TRUE"),
        )
    if not _index_exists(bind, "ai_provider_credential", "ix_ai_only_one_fallback"):
        op.create_index(
            "ix_ai_only_one_fallback",
            "ai_provider_credential",
            ["is_fallback"],
            unique=True,
            sqlite_where=sa.text("is_fallback = 1"),
            postgresql_where=sa.text("is_fallback = TRUE"),
        )

    # ------------------------------------------------------------------
    # ai_settings (singleton)
    # ------------------------------------------------------------------
    if not _table_exists(bind, "ai_settings"):
        op.create_table(
            "ai_settings",
            sa.Column(
                "id",
                sa.Integer(),
                primary_key=True,
                server_default=sa.text("1"),
            ),
            sa.Column(
                "feature_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column(
                "kill_switch_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column(
                "budget_per_request_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("0.10"),
            ),
            sa.Column(
                "budget_per_scan_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("5.00"),
            ),
            sa.Column(
                "budget_daily_usd",
                sa.Numeric(10, 6),
                nullable=False,
                server_default=sa.text("5.00"),
            ),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by_user_id", sa.String(), nullable=True),
            sa.CheckConstraint("id = 1", name="ck_ai_settings_singleton"),
        )
        # Seed the singleton row so reads always succeed.
        op.execute(
            "INSERT INTO ai_settings (id, feature_enabled, kill_switch_active, "
            "budget_per_request_usd, budget_per_scan_usd, budget_daily_usd, updated_at) "
            "VALUES (1, 1, 0, 0.10, 5.00, 5.00, '2026-05-04T00:00:00+00:00')"
        )

    # ------------------------------------------------------------------
    # ai_credential_audit_log
    # ------------------------------------------------------------------
    if not _table_exists(bind, "ai_credential_audit_log"):
        op.create_table(
            "ai_credential_audit_log",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("user_id", sa.String(length=128), nullable=True),
            sa.Column("action", sa.String(length=48), nullable=False),
            # ``target_kind`` lets one table audit credential + settings
            # mutations without creating a join graph: 'credential' |
            # 'settings'. ``target_id`` is the row id when applicable.
            sa.Column("target_kind", sa.String(length=24), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=True),
            sa.Column("provider_name", sa.String(length=32), nullable=True),
            # ``detail`` carries non-sensitive context (e.g. "set-default",
            # "test-failed:auth"). Hard rule: NEVER credential payloads.
            sa.Column("detail", sa.String(length=240), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
        )
    if not _index_exists(bind, "ai_credential_audit_log", "ix_ai_credential_audit_log_created_at"):
        op.create_index(
            "ix_ai_credential_audit_log_created_at",
            "ai_credential_audit_log",
            ["created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    for ix in (
        "ix_ai_only_one_default",
        "ix_ai_only_one_fallback",
        "ix_ai_provider_credential_provider_name",
    ):
        if _index_exists(bind, "ai_provider_credential", ix):
            op.drop_index(ix, table_name="ai_provider_credential")
    if _table_exists(bind, "ai_provider_credential"):
        op.drop_table("ai_provider_credential")
    if _table_exists(bind, "ai_credential_audit_log"):
        if _index_exists(bind, "ai_credential_audit_log", "ix_ai_credential_audit_log_created_at"):
            op.drop_index(
                "ix_ai_credential_audit_log_created_at",
                table_name="ai_credential_audit_log",
            )
        op.drop_table("ai_credential_audit_log")
    if _table_exists(bind, "ai_settings"):
        op.drop_table("ai_settings")
