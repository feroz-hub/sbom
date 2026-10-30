"""Canonical Greenfield orchestration contracts; all external operations mocked."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev
from scripts import greenfield_migrations as migrations


@pytest.fixture
def installed(monkeypatch, tmp_path):
    for name in ("environment.json", "runtime-password", "setup-password"):
        (tmp_path / name).write_text("synthetic")
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", tmp_path)
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", Mock())
    monkeypatch.setattr(migrations, "ensure_current", Mock())
    return tmp_path


def test_check_only_inspects_metadata(installed, monkeypatch):
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", lambda: [])
    forbidden = Mock(side_effect=AssertionError("mutation or credential read"))
    monkeypatch.setattr(dev.GreenfieldStack, "settings", forbidden)
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    dev.GreenfieldProfile.start(SimpleNamespace(check=True), None)
    migrations.ensure_current.assert_not_called()


def test_incomplete_install_never_falls_back(installed, monkeypatch):
    (installed / "runtime-password").unlink()
    inventory = Mock()
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", inventory)
    with pytest.raises(dev.SetupError, match="incomplete"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), Mock())
    inventory.assert_not_called()


def test_symlink_credential_refused(installed):
    (installed / "runtime-password").unlink()
    (installed / "runtime-password").symlink_to(installed / "setup-password")
    with pytest.raises(dev.SetupError, match="incomplete"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=True), None)


def test_inventory_verifies_before_inspection(monkeypatch):
    monkeypatch.setattr(dev.GreenfieldStack, "verify_resources", Mock(side_effect=RuntimeError("identity drift")))
    command = Mock()
    monkeypatch.setattr(dev.subprocess, "run", command)
    with pytest.raises(dev.SetupError, match="identity drift"):
        dev.GreenfieldProfile.inventory()
    command.assert_not_called()


def test_start_resumes_only_verified_stopped_container(installed, monkeypatch):
    observed = [{"Name": "/greenfield-postgres-1", "Id": "owned-pg", "State": {"Running": False}},
                {"Name": "/greenfield-redis-1", "Id": "owned-redis", "State": {"Running": True}}]
    healthy = json.loads(json.dumps(observed))
    healthy[0]["State"] = {"Running": True, "Health": {"Status": "healthy"}}
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", Mock(side_effect=[observed, healthy]))
    monkeypatch.setattr(dev.GreenfieldStack, "docker_command", lambda: ["docker"])
    command = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(dev.subprocess, "run", command)
    monkeypatch.setattr(dev.GreenfieldProfile, "start_services", lambda runtime: ({}, {}))
    monkeypatch.setattr(dev, "supervise_runtime", Mock(side_effect=dev.SetupError("finished fixture")))
    with pytest.raises(dev.SetupError, match="finished fixture"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), Mock())
    command.assert_called_once_with(["docker", "start", "owned-pg"], capture_output=True, timeout=60)
    assert callable(migrations.ensure_current.call_args.kwargs["confirm"])
    assert migrations.ensure_current.call_args.kwargs["confirm"]() == ""


def test_schema_failure_prevents_application_start(installed, monkeypatch):
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", lambda: [])
    monkeypatch.setattr(migrations, "ensure_current", Mock(side_effect=migrations.SchemaUpgradeError("not approved")))
    start = Mock()
    monkeypatch.setattr(dev.GreenfieldProfile, "start_services", start)
    with pytest.raises(migrations.SchemaUpgradeError, match="not approved"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), Mock())
    start.assert_not_called()


def test_start_requires_ownership_registry(installed, monkeypatch):
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", lambda: [])
    with pytest.raises(dev.SetupError, match="ownership registry"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), None)


def test_greenfield_routing_never_initializes_legacy(monkeypatch):
    route = Mock()
    monkeypatch.setattr(dev.GreenfieldProfile, "start", route)
    monkeypatch.setattr(dev, "prepare_managed_legacy", Mock(side_effect=AssertionError("Legacy selected")))
    args = SimpleNamespace(check=True, profile="greenfield")
    dev.start_application(args)
    route.assert_called_once_with(args, dev.ACTIVE_RUNTIME)


@pytest.mark.parametrize("profile", ["auto", "greenfield", "legacy"])
def test_explicit_profiles(profile):
    assert dev.parse_args(["start", "--profile", profile]).profile == profile
