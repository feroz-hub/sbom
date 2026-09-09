"""Authoritative PostgreSQL tests for migration 046."""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.postgres

REVISION = "046_external_identity_and_verification_fields"
CURRENT_HEAD = "055_ai_model_registry"
PREVIOUS_REVISION = "045_secure_authorization_model"
TEST_ISSUER = "https://hcl-cs.test"


def _database_url() -> str:
    value = os.environ["TEST_POSTGRES_DATABASE_URL"]
    assert make_url(value).get_backend_name() == "postgresql"
    assert "test" in (make_url(value).database or "").lower()
    return value


def _config() -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", _database_url())
    return config


def _revision(connection) -> str:
    return str(connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one())


def _upgrade_head() -> None:
    os.environ["SBOM_IDENTITY_BACKFILL_ISSUER"] = TEST_ISSUER
    command.upgrade(_config(), "head")


def test_fresh_head_has_phase3_columns_indexes_and_unique_constraint():
    engine = sa.create_engine(_database_url())
    try:
        inspector = sa.inspect(engine)
        columns = {column["name"] for column in inspector.get_columns("iam_users")}
        assert {
            "external_issuer",
            "external_subject",
            "employee_id",
            "user_principal_name",
            "department",
            "email_verified",
            "email_verified_at",
            "verification_required",
            "last_claim_sync_at",
        } <= columns
        assert "uq_iam_users_external_identity" in {
            constraint["name"] for constraint in inspector.get_unique_constraints("iam_users")
        }
        indexes = {index["name"] for index in inspector.get_indexes("iam_users")}
        assert {
            "ix_iam_users_employee_id",
            "ix_iam_users_user_principal_name",
            "ix_iam_users_verification_status",
        } <= indexes
        with engine.connect() as connection:
            assert _revision(connection) == CURRENT_HEAD
    finally:
        engine.dispose()


def test_upgrade_from_045_preserves_ids_access_and_audit_references(monkeypatch):
    engine = sa.create_engine(_database_url())
    command.downgrade(_config(), PREVIOUS_REVISION)
    try:
        now = "2026-07-01T00:00:00+00:00"
        with engine.begin() as connection:
            for user_id, external_id, status in (
                (100, "active-member", "ACTIVE"),
                (101, "pending-user", "PENDING"),
                (102, "disabled-user", "DISABLED"),
                (103, "active-platform", "ACTIVE"),
            ):
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO iam_users
                          (id, external_iam_user_id, email, display_name, status,
                           last_login_at, created_at, updated_at)
                        VALUES
                          (:id, :external_id, :email, :name, :status, :now, :now, :now)
                        """
                    ),
                    {
                        "id": user_id,
                        "external_id": external_id,
                        "email": f"{external_id}@example.test",
                        "name": external_id,
                        "status": status,
                        "now": now,
                    },
                )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO tenant_users
                      (id, tenant_id, user_id, role, status, created_at, updated_at)
                    VALUES (100, 1, 100, 'VIEWER', 'ACTIVE', :now, :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO platform_user_roles
                      (id, user_id, role, status, created_at, updated_at)
                    VALUES (100, 103, 'PLATFORM_ADMIN', 'ACTIVE', :now, :now)
                    """
                ),
                {"now": now},
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO authorization_audit_log
                      (id, target_user_id, target_membership_id, tenant_id, action, outcome, created_at)
                    VALUES (100, 100, 100, 1, 'phase3.test', 'SUCCESS', :now)
                    """
                ),
                {"now": now},
            )

        monkeypatch.setenv("SBOM_IDENTITY_BACKFILL_ISSUER", TEST_ISSUER)
        command.upgrade(_config(), "head")
        command.upgrade(_config(), "head")  # repeated upgrade is a no-op

        with engine.connect() as connection:
            rows = {
                row.id: row
                for row in connection.execute(
                    sa.text(
                        """
                        SELECT id, external_iam_user_id, external_issuer, external_subject, status,
                               email_verified, verification_required, email_verified_at
                        FROM iam_users WHERE id BETWEEN 100 AND 103
                        """
                    )
                ).mappings()
            }
            assert set(rows) == {100, 101, 102, 103}
            assert all(row.external_issuer == TEST_ISSUER for row in rows.values())
            assert all(row.external_subject == row.external_iam_user_id for row in rows.values())
            assert rows[100].email_verified is True
            assert rows[100].verification_required is False
            assert rows[100].email_verified_at is not None
            assert rows[103].email_verified is True
            assert rows[101].status == "PENDING" and rows[101].email_verified is False
            assert rows[102].status == "DISABLED" and rows[102].email_verified is False
            assert connection.execute(
                sa.text("SELECT user_id FROM tenant_users WHERE id=100")
            ).scalar_one() == 100
            assert connection.execute(
                sa.text("SELECT user_id FROM platform_user_roles WHERE id=100")
            ).scalar_one() == 103
            audit = connection.execute(
                sa.text(
                    "SELECT target_user_id, target_membership_id FROM authorization_audit_log WHERE id=100"
                )
            ).one()
            assert tuple(audit) == (100, 100)

        command.downgrade(_config(), PREVIOUS_REVISION)
        with engine.connect() as connection:
            assert connection.execute(
                sa.text("SELECT external_iam_user_id FROM iam_users WHERE id=100")
            ).scalar_one() == "active-member"
        command.upgrade(_config(), "head")
    finally:
        _upgrade_head()
        engine.dispose()


def test_missing_issuer_fails_without_fabricating_identity(monkeypatch):
    engine = sa.create_engine(_database_url())
    command.downgrade(_config(), PREVIOUS_REVISION)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO iam_users
                      (id, external_iam_user_id, status, created_at, updated_at)
                    VALUES (200, 'missing-issuer', 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """
                )
            )
        monkeypatch.delenv("SBOM_IDENTITY_BACKFILL_ISSUER", raising=False)
        with pytest.raises(RuntimeError, match="SBOM_IDENTITY_BACKFILL_ISSUER"):
            command.upgrade(_config(), "head")
        with engine.connect() as connection:
            assert _revision(connection) == PREVIOUS_REVISION
            assert connection.execute(
                sa.text("SELECT external_iam_user_id FROM iam_users WHERE id=200")
            ).scalar_one() == "missing-issuer"
            assert "external_issuer" not in {
                column["name"] for column in sa.inspect(connection).get_columns("iam_users")
            }
    finally:
        _upgrade_head()
        engine.dispose()


def test_duplicate_legacy_identity_aborts_without_merging(monkeypatch):
    engine = sa.create_engine(_database_url())
    command.downgrade(_config(), PREVIOUS_REVISION)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text("ALTER TABLE iam_users DROP CONSTRAINT uq_iam_users_external_iam_user_id")
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO iam_users
                      (id, external_iam_user_id, status, created_at, updated_at)
                    VALUES
                      (300, 'duplicate-subject', 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                      (301, 'duplicate-subject', 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """
                )
            )
        monkeypatch.setenv("SBOM_IDENTITY_BACKFILL_ISSUER", TEST_ISSUER)
        with pytest.raises(RuntimeError, match="duplicate external_iam_user_id"):
            command.upgrade(_config(), "head")
        with engine.connect() as connection:
            assert _revision(connection) == PREVIOUS_REVISION
            assert connection.execute(
                sa.text("SELECT COUNT(*) FROM iam_users WHERE external_iam_user_id='duplicate-subject'")
            ).scalar_one() == 2
    finally:
        with engine.begin() as connection:
            connection.execute(sa.text("DELETE FROM iam_users WHERE id IN (300, 301)"))
            connection.execute(
                sa.text(
                    "ALTER TABLE iam_users ADD CONSTRAINT uq_iam_users_external_iam_user_id "
                    "UNIQUE (external_iam_user_id)"
                )
            )
        _upgrade_head()
        engine.dispose()
