"""Opt-in actual startup upgrade, using ONLY the existing synthetic IAM fixture DB."""

import os
from unittest.mock import Mock

import pytest
from scripts import greenfield_migrations as migration
from sqlalchemy import text
from sqlalchemy.engine import make_url

from tests.test_iam_user_uuid_migration import legacy as legacy

pytestmark = pytest.mark.skipif(
    os.getenv("SBOM_RUN_GREENFIELD_STARTUP_ACCEPTANCE") != "1", reason="opt-in disposable startup/backup acceptance"
)


@pytest.fixture
def isolated_startup(legacy, monkeypatch, tmp_path):
    name = make_url(os.environ["IAM_UUID_UPGRADE_DATABASE_URL"]).database
    assert name == "sbom_iam_public_uuid_upgrade_test"
    with legacy.begin() as c:
        c.exec_driver_sql("ALTER SCHEMA public OWNER TO greenfield_owner")
        tables = (
            c.exec_driver_sql("SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'")
            .scalars()
            .all()
        )
        for table in tables:
            quoted = c.dialect.identifier_preparer.quote(table)
            c.exec_driver_sql(f"ALTER TABLE public.{quoted} OWNER TO greenfield_owner")
    legacy.dispose()  # no pooled competing client during exclusive preflight
    original_reader = migration.stack.read_private
    private = {key: original_reader(key) for key in ("setup-password", "docker-identities.json")}
    monkeypatch.setattr(migration.stack, "read_private", private.__getitem__)
    monkeypatch.setattr(migration.stack, "STATE", tmp_path)
    monkeypatch.setattr(migration.stack, "DB", name)
    return legacy


def test_real_confirmed_startup_encrypts_and_restores_backup_then_commits101(isolated_startup, tmp_path):
    migration.ensure_current(confirm=lambda: migration.CONFIRMATION)
    with isolated_startup.connect() as c:
        assert c.scalar(text("SELECT version_num FROM alembic_version")) == migration.CURRENT
        assert c.scalar(text("SELECT count(*) FROM iam_users WHERE public_id IS NOT NULL")) == 2
    folders = list((tmp_path / "upgrade-backups").iterdir())
    assert len(folders) == 1
    assert (folders[0] / "database.dump.fernet").stat().st_mode & 0o777 == 0o600
    assert (folders[0] / "backup-verified.json").is_file()
    assert (folders[0] / "upgrade-accepted.json").is_file()
    assert not (tmp_path / "pending-schema-upgrade.json").exists()


def test_real_precommit_failure_keeps100_and_retains_claim(isolated_startup, tmp_path, monkeypatch):
    from app import iam_schema

    actual = iam_schema.apply_user_uuid_revision

    def fail(c):
        actual(c)
        raise RuntimeError("synthetic failure after real migration body")

    monkeypatch.setattr(iam_schema, "apply_user_uuid_revision", fail)
    with pytest.raises(migration.SchemaUpgradeError, match="precommit migration"):
        migration.ensure_current(confirm=lambda: migration.CONFIRMATION)
    with isolated_startup.connect() as c:
        assert c.scalar(text("SELECT version_num FROM alembic_version")) == migration.PREVIOUS
        assert not c.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='iam_users' AND column_name='public_id')"
            )
        )
    assert (tmp_path / "pending-schema-upgrade.json").exists()
    prompt = Mock(side_effect=AssertionError("must not retry"))
    with pytest.raises(migration.SchemaUpgradeError, match="manual reconciliation"):
        migration.ensure_current(confirm=prompt)
    prompt.assert_not_called()
