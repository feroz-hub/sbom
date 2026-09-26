"""Upgrade populated revision 059 and prove downgrade refuses native data loss."""

import os

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

PREVIOUS = "059_vex_analyzer_sources"
REVISION = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()


def test_compatibility_migration_preserves_duplicates_pending_and_membership():
    engine = create_engine(os.environ["TEST_POSTGRES_DATABASE_URL"])
    config = Config("alembic.ini")
    command.downgrade(config, PREVIOUS)
    try:
        with engine.begin() as connection:
            for uid, status, email in [(901, "PENDING", " Foo@Example.com "), (902, "ACTIVE", "foo@example.com")]:
                connection.execute(
                    text(
                        "INSERT INTO iam_users (id, external_iam_user_id, external_issuer, external_subject, "
                        "email, status, email_verified, verification_required, created_at, updated_at) "
                        "VALUES (:id, :subject, 'https://hcl-cs.test', :subject, :email, :status, false, true, now(), now())"
                    ),
                    {"id": uid, "subject": f"migration-{uid}", "email": email, "status": status},
                )
            connection.execute(
                text(
                    "INSERT INTO tenant_users (tenant_id, user_id, role, status, created_at, updated_at) "
                    "VALUES (1, 902, 'VIEWER', 'ACTIVE', now(), now())"
                )
            )
        with pytest.warns(UserWarning, match="Duplicate normalized profile emails"):
            command.upgrade(config, "head")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == REVISION
            rows = connection.execute(
                text("SELECT id, status, normalized_email, external_subject FROM iam_users ORDER BY id")
            ).all()
            assert rows == [
                (901, "PENDING", "foo@example.com", "migration-901"),
                (902, "ACTIVE", "foo@example.com", "migration-902"),
            ]
            assert connection.scalar(text("SELECT count(*) FROM tenant_users WHERE user_id=902 AND tenant_id=1")) == 1
            assert connection.scalar(text("SELECT count(*) FROM user_identities WHERE provider_type='HCL_CS'")) == 2
        command.upgrade(config, "head")
        command.downgrade(config, PREVIOUS)
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM iam_users")) == 2
            assert "user_identities" not in inspect(connection).get_table_names()
    finally:
        command.upgrade(config, "head")
        engine.dispose()


def test_downgrade_refuses_native_records_without_deleting_anything():
    engine = create_engine(os.environ["TEST_POSTGRES_DATABASE_URL"])
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO iam_users (email, status, email_verified, verification_required, created_at, updated_at) "
                "VALUES ('native@example.test', 'PENDING_EMAIL_VERIFICATION', false, true, now(), now())"
            )
        )
    try:
        with pytest.raises(RuntimeError, match="Refusing downgrade"):
            command.downgrade(Config("alembic.ini"), PREVIOUS)
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == REVISION
            assert connection.scalar(text("SELECT count(*) FROM iam_users")) == 1
            assert "native_user_credentials" in inspect(connection).get_table_names()
    finally:
        engine.dispose()
