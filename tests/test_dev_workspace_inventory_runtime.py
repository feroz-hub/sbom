"""List observes only registered private runtimes through the real inspector.

All process identities are synthetic Windows API fixtures. No application
conftest, database, real process, configuration binding or health probe runs.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_private
from scripts import dev_instance_registry as registry
from scripts import dev_workspace as workspace
from scripts import dev_workspace_cli as cli
from scripts import dev_workspace_inspect as inspect

from tests.test_dev_workspace_database_prepare import prepared as prepared
from tests.test_dev_workspace_inspect import SECRET, rewrite
from tests.test_dev_workspace_inspect import runtime_state as runtime_state


@pytest.fixture
def inventory(runtime_state, monkeypatch):
    """Replace public discovery only; retain real private files and inspector."""
    root = runtime_state.home / "checkout"
    if os.name == "nt":
        inspect.runtime_adapter.dev_instance_storage._windows_create(root)
    else:
        root.mkdir(mode=0o700)
    original = root / ".dev-runtime.json"
    original.write_text("original-worktree-runtime-must-not-be-read", encoding="utf-8")
    descriptor = runtime_state.descriptor
    identity = workspace.FilesystemIdentity(root, root.stat().st_dev, root.stat().st_ino)
    worktree = workspace.WorktreeSnapshot(
        descriptor.worktree_id,
        root,
        identity,
        descriptor.commit,
        "refs/heads/feature/SBO-101-synthetic-inventory",
        False,
        False,
        False,
        False,
        False,
    )
    snapshot = workspace.RepositorySnapshot(
        descriptor.repository_id, root, identity, descriptor.commit, (worktree,), identity
    )
    records = registry.RegistrySnapshot((registry.RegistryEntry(descriptor, state="READY"),))
    reader = Mock(return_value=records)
    monkeypatch.setattr(workspace, "discover_workspaces", Mock(return_value=snapshot))
    monkeypatch.setattr(cli, "_registry", Mock(return_value=SimpleNamespace(read=reader)))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: runtime_state.home))
    return SimpleNamespace(runtime=runtime_state, root=root, original=original, reader=reader)


def _files(root):
    return {
        str(path.relative_to(root)): (
            path.read_bytes(),
            registry._stamp(path.lstat()),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def _listed(inventory, monkeypatch, capsys):
    """Every inspection uses the canonical Runtime without any writer API."""
    state = inventory.runtime
    before = _files(state.home)
    forbidden = Mock(side_effect=AssertionError("Inventory attempted mutation or unrelated runtime access"))
    original_init, original_open = dev.Runtime.__init__, os.open
    original_read_text, original_read_bytes = Path.read_text, Path.read_bytes
    constructed = []

    def private_runtime(self, root, *args, **kwargs):
        assert Path(root) == state.root
        constructed.append(Path(root))
        original_init(self, root, *args, **kwargs)

    def readonly_open(path, flags, *args, **kwargs):
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR | os.O_APPEND)
        return original_open(path, flags, *args, **kwargs)

    def read_text(path, *args, **kwargs):
        assert path != inventory.original
        return original_read_text(path, *args, **kwargs)

    def read_bytes(path, *args, **kwargs):
        assert path != inventory.original
        return original_read_bytes(path, *args, **kwargs)

    with monkeypatch.context() as guarded:
        guarded.setattr(dev.Runtime, "__init__", private_runtime)
        for name in (
            "acquire",
            "release",
            "begin",
            "register",
            "refresh",
            "save",
            "_publish_json",
            "terminate",
            "stop_services",
        ):
            guarded.setattr(dev.Runtime, name, forbidden, raising=False)
        guarded.setattr(dev, "atomic_json", forbidden)
        guarded.setattr(dev_private, "create_private_file", forbidden)
        guarded.setattr(registry.InstanceRegistry, "_lock", forbidden)
        guarded.setattr(registry.InstanceRegistry, "publish", forbidden)
        for name in ("mkdir", "remove", "unlink", "replace", "rename", "kill"):
            guarded.setattr(os, name, forbidden)
        guarded.setattr(os, "killpg", forbidden, raising=False)
        guarded.setattr(os, "open", readonly_open)
        guarded.setattr(Path, "read_text", read_text)
        guarded.setattr(Path, "read_bytes", read_bytes)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        assert cli.run_cli(["list", "--json"], inventory.root) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["application_readiness_verified"] is False
    assert SECRET not in output
    # The fixture token also occurs inside the public synthetic repository ID.
    assert state.state["instance"] not in json.dumps(result["worktrees"][0].get("process_observation", {}))
    assert state.state["services"]["API"]["exe"] not in output
    assert _files(state.home) == before
    forbidden.assert_not_called()
    state.kernel.TerminateProcess.assert_not_called()
    return result["worktrees"][0], constructed


def test_list_observes_verified_processes_but_never_trusts_saved_ready(inventory, monkeypatch, capsys):
    row, constructed = _listed(inventory, monkeypatch, capsys)
    assert constructed == [inventory.runtime.root]
    assert row["reported_state"] == "READY" and row["process_status"] == "RUNNING"
    assert row["runtime_ownership"] == "VERIFIED"
    observation = row["process_observation"]
    assert observation["readiness_verified"] is False
    assert observation["saved_ready_flag_trusted"] is False
    assert observation["resource_mutations_authorized"] is False
    kernel = inventory.runtime.kernel
    assert kernel.OpenProcess.called and kernel.GetProcessTimes.called
    assert kernel.QueryFullProcessImageNameW.called
    kernel.CreateToolhelp32Snapshot.assert_not_called()  # Inspect saved members, never refresh the tree.
    assert kernel.closed


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        ("pid-reuse", "PARTIAL", "PROCESS_IDENTITY_MISMATCH"),
        ("access-denied", "UNKNOWN", "PROCESS_IDENTITY_UNVERIFIED"),
        ("corrupt-private", "UNKNOWN", "RUNTIME_STATE_UNVERIFIED"),
        ("wrong-root-binding", "UNKNOWN", "RUNTIME_BINDING_MISMATCH"),
    ],
)
def test_list_preserves_uncertain_runtime_records(inventory, monkeypatch, capsys, failure, status, code):
    state = inventory.runtime
    if failure == "pid-reuse":
        state.kernel.processes[103]["birth"] += 1
    elif failure == "access-denied":
        state.kernel.fail("OpenProcess", 5)
    elif failure == "corrupt-private":
        (state.root / ".dev-runtime.json").write_text("{" + SECRET, encoding="utf-8")
    else:
        state.state["workspace_context"]["root_identity"] = [0, 0]
        rewrite(state)
    row, constructed = _listed(inventory, monkeypatch, capsys)
    assert constructed == [state.root]
    assert row["reported_state"] == "READY" and row["process_status"] == status
    assert row["runtime_ownership"] == "UNVERIFIED"
    diagnostics = row["process_observation"]["diagnostics"]
    assert any(item["code"] == code for item in diagnostics)
    if failure == "access-denied":
        assert any(item["winerror"] == 5 for item in diagnostics)
    if failure in {"corrupt-private", "wrong-root-binding"}:
        state.kernel.OpenProcess.assert_not_called()


def test_list_never_inspects_unregistered_original_or_unclaimed_private_runtime(inventory, monkeypatch, capsys):
    inventory.reader.return_value = registry.RegistrySnapshot()
    forbidden = Mock(side_effect=AssertionError("Unregistered runtime was adopted"))
    monkeypatch.setattr(inspect, "inspect_instance", forbidden)
    row, constructed = _listed(inventory, monkeypatch, capsys)
    assert row["reported_state"] == "UNREGISTERED" and row["process_status"] == "UNOBSERVED"
    assert row["runtime_ownership"] == "UNVERIFIED" and "process_observation" not in row
    assert not constructed
    inventory.runtime.kernel.OpenProcess.assert_not_called()
    forbidden.assert_not_called()
