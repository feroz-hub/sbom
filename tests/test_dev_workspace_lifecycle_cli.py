"""Workspace lifecycle CLI gates only; synthetic records, no live resources."""

from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_instance_plan, dev_instance_registry, dev_workspace
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_lifecycle as lifecycle

SECRET = "synthetic-lifecycle-private-value-never-output"
COMMANDS = ("start", "stop", "restart")


@pytest.fixture
def registered(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "checkout with spaces"
    root.mkdir()
    home = tmp_path.resolve() / "synthetic home"
    home.mkdir()
    protected = {root / ".dev-runtime.json": b"unknown ownership; preserve",
                 root / ".env.dev.local": SECRET.encode()}
    for path, content in protected.items():
        path.write_bytes(content)
    identity = dev_workspace.FilesystemIdentity(root, root.stat().st_dev, root.stat().st_ino)
    selected = dev_workspace.WorktreeSnapshot(
        "b" * 64, root, identity, "c" * 40, "refs/heads/synthetic", False, False, False, False, False
    )
    snapshot = dev_workspace.RepositorySnapshot("a" * 64, root, identity, selected.head, (selected,), identity)
    descriptor = dev_instance_plan.plan_instance(
        repository_id=snapshot.repository_id, worktree_id=selected.worktree_id, commit=selected.head,
        generation=1, mode="isolated", auth_mode="native", provider="container",
    ).descriptor
    entry = dev_instance_registry.RegistryEntry(descriptor)
    read = Mock(return_value=dev_instance_registry.RegistrySnapshot((entry,)))
    registry = SimpleNamespace(read=read)
    factory = Mock(return_value=registry)
    discover = Mock(return_value=snapshot)
    monkeypatch.setattr(dev_workspace, "discover_workspaces", discover)
    monkeypatch.setattr(cli, "_registry", factory)
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))
    forbidden = Mock(side_effect=AssertionError("Blocked lifecycle attempted mutation or private/service access"))
    for name in ("Runtime", "start_process", "start_background", "start_application", "ensure_database"):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(cli.dev_environment, "bounded_read_bytes", forbidden)
    monkeypatch.setattr(cli.dev_environment, "bounded_read_text", forbidden)
    monkeypatch.setattr(dev_instance_registry.InstanceRegistry, "publish", forbidden)
    monkeypatch.setattr(cli.dev_private, "create_private_file", forbidden)
    for name in ("Popen", "run", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("mkdir", "makedirs", "rename", "replace", "remove", "unlink", "rmdir", "kill", "system"):
        monkeypatch.setattr(os, name, forbidden)
    original_open, original_io_open = builtins.open, io.open

    def readonly_open(original):
        def check(file, mode="r", *args, **kwargs):
            if any(marker in mode for marker in "wax+"):
                forbidden()
            if isinstance(file, (str, bytes, os.PathLike)) and Path(file) in protected:
                forbidden()
            return original(file, mode, *args, **kwargs)
        return check

    monkeypatch.setattr(builtins, "open", readonly_open(original_open))
    monkeypatch.setattr(io, "open", readonly_open(original_io_open))
    yield SimpleNamespace(root=root, home=home, selected=selected, snapshot=snapshot, entry=entry,
                          read=read, factory=factory, discover=discover, forbidden=forbidden)
    forbidden.assert_not_called()
    for path, content in protected.items():
        with original_open(path, "rb") as stream:
            assert stream.read() == content
    assert list(home.iterdir()) == []


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("reported_state", ["PLANNED", "PREPARED", "READY"])
def test_registered_or_caller_ready_state_never_unlocks_execution(registered, monkeypatch, capsys, command, reported_state):
    entry = replace(registered.entry, state=reported_state)
    registered.read.return_value = dev_instance_registry.RegistrySnapshot((entry,))
    monkeypatch.setenv("SBOM_DEV_INSTANCE_READY", "1")
    monkeypatch.setenv("DATABASE_URL", SECRET)
    monkeypatch.setenv("NODE_OPTIONS", "--require " + SECRET)
    assert cli.run_cli([command, "--json"], registered.root) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["status"] == "BLOCKED"
    assert result["code"] == ("INSTANCE_RUNTIME_ADAPTER_REQUIRED" if command == "stop"
                              else "INSTANCE_PROVIDER_ATTESTATION_REQUIRED")
    assert result["blockers"] == list(lifecycle.live_execution_blockers())
    assert result["instance_id"] == entry.descriptor.instance_id
    assert result["runtime_ownership_verified"] is False and result["log_created"] is False
    assert Path(result["proposed_log_path"]) == registered.home / ".sbom-dev/instances" / entry.descriptor.instance_id / ".dev-logs"
    assert SECRET not in output.out + output.err
    registered.read.assert_called_once_with()


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("registry_code,expected", [
    (None, "WORKSPACE_INSTANCE_REGISTRATION_REQUIRED"),
    ("REGISTRY_MISSING", "WORKSPACE_INSTANCE_REGISTRATION_REQUIRED"),
    ("REGISTRY_UNKNOWN_ARTIFACT", "REGISTRY_UNKNOWN_ARTIFACT"),
    ("REGISTRY_SCHEMA_INVALID", "REGISTRY_SCHEMA_INVALID"),
])
def test_missing_or_uncertain_registry_refuses_without_repair(registered, capsys, command, registry_code, expected):
    registered.read.return_value = dev_instance_registry.RegistrySnapshot(
        codes=(registry_code,) if registry_code else ()
    )
    assert cli.run_cli([command, "--json"], registered.root) == 1
    assert json.loads(capsys.readouterr().out) == {"status": "BLOCKED", "code": expected}


@pytest.mark.parametrize("command", COMMANDS)
def test_source_head_change_blocks_launch_but_keeps_stop_at_runtime_ownership_gate(registered, capsys, command):
    changed = replace(registered.selected, head="d" * 40)
    registered.discover.return_value = replace(registered.snapshot, head=changed.head, worktrees=(changed,))
    assert cli.run_cli([command, "--json"], registered.root) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["code"] == ("INSTANCE_RUNTIME_ADAPTER_REQUIRED" if command == "stop"
                              else "WORKSPACE_INSTANCE_SOURCE_CHANGED")
    if command == "stop":
        assert "INSTANCE_RUNTIME_ADAPTER_REQUIRED" in result["blockers"]
        assert result["runtime_ownership_verified"] is False


@pytest.mark.parametrize("arguments", [
    ["--mode", "isolated"], ["--auth", "native"], ["--provider", "container"],
    ["--scope", "registry"], ["--generation", "2"], ["--port-min", "21000"], ["--port-max", "31000"],
])
def test_lifecycle_flags_cannot_silently_select_or_convert_prepared_profile(registered, capsys, arguments):
    assert cli.run_cli(["start", *arguments, "--json"], registered.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_PREPARED_SELECTION_REQUIRED"
    registered.discover.assert_not_called()
    registered.factory.assert_not_called()


def test_unlisted_worktree_cannot_reuse_registered_instance(registered, tmp_path, capsys):
    assert cli.run_cli(["stop", "--worktree", str(tmp_path / "unlisted"), "--json"], registered.root) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "WORKSPACE_TARGET_BLOCKED"
    registered.factory.assert_not_called()


@pytest.mark.parametrize("command", COMMANDS)
def test_text_diagnostics_are_actionable_and_redacted(registered, capsys, command):
    registered.read.side_effect = RuntimeError(SECRET)
    assert cli.run_cli([command], registered.root) == 1
    output = capsys.readouterr()
    assert "WORKSPACE_INSPECTION_FAILED" in output.out and "retained records" in output.out
    assert SECRET not in output.out + output.err


def test_caller_ready_cli_argument_cannot_supply_missing_adapter(registered, capsys):
    with pytest.raises(SystemExit) as caught:
        cli.run_cli(["start", "--ready", SECRET], registered.root)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert "WORKSPACE_ARGUMENTS_INVALID" in output.err and SECRET not in output.out + output.err
    registered.discover.assert_not_called()
