"""PostgreSQL migration coverage for revision 047."""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.postgres

REVISION = "047_email_verification_tokens"
CURRENT_HEAD = "055_ai_model_registry"
PREVIOUS_REVISION = "046_external_identity_and_verification_fields"


def _database_url() -> str:
    value = os.environ["TEST_POSTGRES_DATABASE_URL"]
    assert make_url(value).get_backend_name() == "postgresql"
    assert "test" in (make_url(value).database or "").lower()
    return value


def _config() -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", _database_url())
    return config


def _upgrade_head() -> None:
    command.upgrade(_config(), "head")


def test_head_contains_token_table_constraints_indexes_and_foreign_key():
    engine = sa.create_engine(_database_url())
    try:
        inspector = sa.inspect(engine)
        assert "email_verification_tokens" in inspector.get_table_names()
        columns = {
            column["name"]
            for column in inspector.get_columns("email_verification_tokens")
        }
        assert {
            "id",
            "user_id",
            "token_hash",
            "email_snapshot",
            "expires_at",
            "consumed_at",
            "invalidated_at",
            "created_at",
            "delivery_status",
        } <= columns
        indexes = {
            index["name"]
            for index in inspector.get_indexes("email_verification_tokens")
        }
        assert {
            "ix_email_verification_tokens_user_id",
            "ix_email_verification_tokens_expires_at",
            "ix_email_verification_tokens_user_created",
            "ix_email_verification_tokens_user_consumed",
            "uq_email_verification_tokens_active_user",
        } <= indexes
        assert "uq_email_verification_tokens_token_hash" in {
            item["name"]
            for item in inspector.get_unique_constraints(
                "email_verification_tokens"
            )
        }
        foreign_keys = inspector.get_foreign_keys("email_verification_tokens")
        assert any(
            item["referred_table"] == "iam_users"
            and item["options"].get("ondelete") == "CASCADE"
            for item in foreign_keys
        )
        with engine.connect() as connection:
            assert (
                connection.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                ).scalar_one()
                    == CURRENT_HEAD
            )
    finally:
        engine.dispose()


def test_upgrade_preserves_users_memberships_grants_and_verification_state():
    engine = sa.create_engine(_database_url())
    command.downgrade(_config(), PREVIOUS_REVISION)
    try:
        now = "2026-07-26T00:00:00+00:00"
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO iam_users
                      (id, external_iam_user_id, external_issuer, external_subject,
                       email, display_name, status, email_verified, email_verified_at,
                       verification_required, created_at, updated_at)
                    VALUES
                      (500, 'phase5-migration', 'https://hcl-cs.test', 'phase5-migration',
                       'phase5@example.test', 'Phase Five', 'ACTIVE', true, :now,
                       false, :now, :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO tenant_users
                      (id, tenant_id, user_id, role, status, created_at, updated_at)
                    VALUES (500, 1, 500, 'VIEWER', 'ACTIVE', :now, :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO platform_user_roles
                      (id, user_id, role, status, created_at, updated_at)
                    VALUES (500, 500, 'PLATFORM_ADMIN', 'ACTIVE', :now, :now)
                    """
                ),
                {"now": now},
            )
        _upgrade_head()
        _upgrade_head()
        with engine.connect() as connection:
            user = connection.execute(
                sa.text(
                    """
                    SELECT email_verified, email_verified_at, verification_required
                    FROM iam_users WHERE id=500
                    """
                )
            ).one()
            assert tuple(user) == (True, user.email_verified_at, False)
            assert user.email_verified_at is not None
            assert connection.execute(
                sa.text("SELECT user_id FROM tenant_users WHERE id=500")
            ).scalar_one() == 500
            assert connection.execute(
                sa.text("SELECT user_id FROM platform_user_roles WHERE id=500")
            ).scalar_one() == 500
            assert connection.execute(
                sa.text("SELECT COUNT(*) FROM email_verification_tokens")
            ).scalar_one() == 0
    finally:
        _upgrade_head()
        engine.dispose()


def test_hash_uniqueness_active_token_policy_and_cascade_delete():
    engine = sa.create_engine(_database_url())
    now = "2026-07-26T00:00:00+00:00"
    later = "2026-07-27T00:00:00+00:00"
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO iam_users
                      (id, external_iam_user_id, external_issuer, external_subject,
                       email, display_name, status, email_verified,
                       verification_required, created_at, updated_at)
                    VALUES
                      (501, 'phase5-fk', 'https://hcl-cs.test', 'phase5-fk',
                       'phase5-fk@example.test', 'Phase Five FK', 'ACTIVE', false,
                       true, :now, :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO email_verification_tokens
                      (id, user_id, token_hash, email_snapshot, expires_at,
                       created_at, delivery_status)
                    VALUES
                      (501, 501, :hash, 'phase5-fk@example.test', :later,
                       :now, 'PENDING')
                    """
                ),
                {"hash": "a" * 64, "now": now, "later": later},
            )
        with pytest.raises(sa.exc.IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO email_verification_tokens
                          (user_id, token_hash, email_snapshot, expires_at,
                           created_at, delivery_status)
                        VALUES
                          (501, :hash, 'phase5-fk@example.test', :later,
                           :now, 'PENDING')
                        """
                    ),
                    {"hash": "a" * 64, "now": now, "later": later},
                )
        with engine.begin() as connection:
            connection.execute(sa.text("DELETE FROM iam_users WHERE id=501"))
        with engine.connect() as connection:
            assert connection.execute(
                sa.text(
                    "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id=501"
                )
            ).scalar_one() == 0
    finally:
        engine.dispose()


def test_downgrade_and_reupgrade_are_safe():
    engine = sa.create_engine(_database_url())
    try:
        command.downgrade(_config(), PREVIOUS_REVISION)
        assert "email_verification_tokens" not in sa.inspect(engine).get_table_names()
        _upgrade_head()
        assert "email_verification_tokens" in sa.inspect(engine).get_table_names()
    finally:
        _upgrade_head()
        engine.dispose()
