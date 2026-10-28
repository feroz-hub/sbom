"""Launcher routing and existing-resource resume; no database or real secrets."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev
from scripts import dev_greenfield as launcher


@pytest.fixture
def installed(monkeypatch, tmp_path):
    for name in ("environment.json", "runtime-password", "setup-password"):
        (tmp_path / name).write_text("synthetic")
    monkeypatch.setattr(launcher.stack, "STATE", tmp_path)
    monkeypatch.setattr(launcher.https, "ensure_certificate", Mock())
    return tmp_path


def test_check_only_inspects_metadata(installed, monkeypatch):
    monkeypatch.setattr(launcher, "inventory", lambda: [{"Name": "/synthetic", "State": {"Running": False}}])
    run = Mock(side_effect=AssertionError("mutation"))
    monkeypatch.setattr(launcher.subprocess, "run", run)
    monkeypatch.setattr(launcher.stack, "settings", Mock(side_effect=AssertionError("credentials")))
    launcher.start(SimpleNamespace(check=True), None)
    run.assert_not_called()


def test_incomplete_install_never_falls_back(installed, monkeypatch):
    (installed / "runtime-password").unlink()
    probe = Mock()
    monkeypatch.setattr(launcher, "inventory", probe)
    with pytest.raises(RuntimeError, match="incomplete"):
        launcher.start(SimpleNamespace(check=False), Mock())
    probe.assert_not_called()


def test_symlink_credential_refused(installed, monkeypatch):
    (installed / "runtime-password").unlink()
    (installed / "runtime-password").symlink_to(installed / "setup-password")
    with pytest.raises(RuntimeError, match="incomplete"):
        launcher.start(SimpleNamespace(check=True), None)


def test_inventory_verifies_before_inspection(monkeypatch):
    verify = Mock(side_effect=RuntimeError("identity drift"))
    monkeypatch.setattr(launcher.stack, "verify_resources", verify)
    command = Mock()
    monkeypatch.setattr(launcher.subprocess, "check_output", command)
    with pytest.raises(RuntimeError, match="identity drift"):
        launcher.inventory()
    command.assert_not_called()


def test_start_resumes_only_recorded_stopped_container(installed, monkeypatch):
    observed = [
        {"Name": "/greenfield-postgres-1", "Id": "owned-pg", "State": {"Running": False}},
        {"Name": "/greenfield-redis-1", "Id": "owned-redis", "State": {"Running": True}},
    ]
    healthy = json.loads(json.dumps(observed))
    healthy[0]["State"] = {"Running": True, "Health": {"Status": "healthy"}}
    monkeypatch.setattr(launcher, "inventory", Mock(side_effect=[observed, healthy]))
    command = Mock()
    monkeypatch.setattr(launcher.subprocess, "run", command)
    services = Mock(return_value={"backend": Mock(poll=Mock(return_value=1))})
    monkeypatch.setattr(launcher.stack, "start_services", services)
    runtime = Mock()
    with pytest.raises(RuntimeError, match="service exited"):
        launcher.start(SimpleNamespace(check=False), runtime)
    command.assert_called_once_with(launcher.stack.DOCKER + ["start", "owned-pg"], check=True, capture_output=True)
    services.assert_called_once_with(runtime=runtime)
    runtime.refresh.assert_called_once()


def test_start_requires_ownership_registry(installed, monkeypatch):
    monkeypatch.setattr(launcher, "inventory", lambda: [])
    with pytest.raises(RuntimeError, match="ownership registry"):
        launcher.start(SimpleNamespace(check=False), None)


def test_greenfield_routing_does_not_initialize_legacy(monkeypatch):
    called = Mock()
    monkeypatch.setattr(launcher, "start", called)
    monkeypatch.setattr(dev, "ensure_dependencies", Mock(side_effect=AssertionError("legacy path")))
    args = SimpleNamespace(check=True, profile="greenfield")
    dev.start_application(args)
    called.assert_called_once_with(args, dev.ACTIVE_RUNTIME)


@pytest.mark.parametrize("profile", ["auto", "greenfield", "legacy"])
def test_explicit_profiles(profile):
    assert dev.parse_args(["start", "--profile", profile]).profile == profile
