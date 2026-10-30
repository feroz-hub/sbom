"""Mocked adapter contracts; these do not establish native Windows acceptance."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev
from scripts import greenfield_migrations as migrations
from scripts.dev import GreenfieldStack as legacy_stack


def test_windows_schema_reader_uses_canonical_acl_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(legacy_stack, "STATE", tmp_path)
    directory = Mock()
    reader = Mock(return_value=b"synthetic-private-value")
    monkeypatch.setattr(dev.LocalHttps, "private_directory", directory)
    monkeypatch.setattr(dev.LocalHttps, "read_file", reader)
    assert legacy_stack.read_private("runtime-password") == "synthetic-private-value"
    directory.assert_called_once_with(tmp_path)
    reader.assert_called_once_with(tmp_path / "runtime-password", key=True)


def test_windows_schema_reader_rejects_path_traversal(monkeypatch):
    monkeypatch.setattr(dev.sys, "platform", "win32")
    with pytest.raises(RuntimeError, match="filename"):
        legacy_stack.read_private("../runtime-password")


def test_windows_docker_uses_native_cli_without_unix_socket(monkeypatch):
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(dev.shutil, "which", lambda name: "docker.exe")
    assert dev.GreenfieldStack.docker_command() == ["docker.exe"]


def test_migration_preflight_uses_platform_null_device(monkeypatch):
    import sqlalchemy

    for name in list(migrations.os.environ):
        if name.startswith("PG"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(migrations.os, "devnull", "NUL")
    monkeypatch.setattr(
        migrations.stack,
        "url",
        lambda *args: "postgresql+psycopg://greenfield_setup:synthetic@127.0.0.1:56044/sbom_greenfield_uuid",
    )
    create = Mock()
    monkeypatch.setattr(sqlalchemy, "create_engine", create)
    migrations.engine()
    assert create.call_args.kwargs["connect_args"]["passfile"] == "NUL"
    assert "default_transaction_read_only=on" in create.call_args.kwargs["connect_args"]["options"]
    assert create.call_args.kwargs["hide_parameters"] is True


@pytest.mark.parametrize("current", [True, False])
def test_windows_schema_accepts_current_but_blocks_unverified_upgrade(monkeypatch, tmp_path, current):
    monkeypatch.setattr(migrations.sys, "platform", "win32")
    monkeypatch.setattr(migrations.stack, "STATE", tmp_path)
    monkeypatch.setattr(migrations.stack, "verify_resources", Mock())
    unit = Mock()
    unit.CURRENT = "synthetic-current"
    unit.PREVIOUS = "synthetic-previous"
    unit.inspect_current.return_value = ((), unit.CURRENT if current else unit.PREVIOUS)
    if current:
        migrations._ensure_unit(unit)
    else:
        with pytest.raises(migrations.SchemaUpgradeError, match="Windows"):
            migrations._ensure_unit(unit)
    unit.before_upgrade.assert_not_called()
    unit.engine.return_value.dispose.assert_called_once()


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_greenfield_complete_service_commands(monkeypatch, platform):
    monkeypatch.setattr(dev.sys, "platform", platform)
    env = {"SBOM_DEV_INSTANCE": "synthetic", "SBOM_DEV_PROFILE": "greenfield", "SBOM_DEV_STATE_DIR": "/synthetic"}
    commands = dev.GreenfieldProfile.commands(Path("node"), Path("cert"), Path("key"), Path("ui"), env)
    assert set(commands) == {"API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat"}
    assert "--queues=celery" in commands["Celery worker"][0]
    assert "--queues=reports" in commands["Celery reports worker"][0]
    pool = "prefork" if platform == "linux" else "solo"
    assert "--pool=" + pool in commands["Celery worker"][0]
    assert "--beat" not in commands["Celery worker"][0]
    assert "--scheduler=scripts.dev:LocalScheduler" in commands["Celery Beat"][0]
