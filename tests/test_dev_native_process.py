"""Native host smoke checks using only disposable, test-owned processes/ports.

These tests establish evidence for the host on which they execute, not for a
mocked operating system and not for application/database/browser acceptance.
Run with the other DB-free launcher tests and --noconftest.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev


@pytest.fixture
def owned_runtime(tmp_path):
    runtime = dev.Runtime(tmp_path)
    assert runtime.acquire()
    runtime.begin("legacy")
    children = []
    try:
        yield runtime, children
    finally:
        try:
            runtime.stop_services(lambda *args: None)
        finally:
            runtime.release()
            for child in children:
                if child.poll() is None:
                    child.kill()  # Only handles freshly created by this test.
                child.wait(timeout=10)


def sleeping_child(children):
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **dev.platform_spawn_options(),
    )
    children.append(process)
    return process


def test_native_stop_affects_only_recorded_child(owned_runtime):
    runtime, children = owned_runtime
    owned = sleeping_child(children)
    unrelated = sleeping_child(children)
    runtime.processes[owned.pid] = owned
    runtime.register("owned fixture", owned.pid)
    runtime.refresh()
    assert runtime.service_status(runtime.state["services"]["owned fixture"]) == "RUNNING"
    assert runtime.stop_services(lambda *args: None)
    assert owned.wait(timeout=10) is not None
    assert unrelated.poll() is None
    assert not runtime.path.exists()


def test_native_crashed_child_is_reaped_and_stale_state_cleans(owned_runtime):
    runtime, children = owned_runtime
    child = sleeping_child(children)
    runtime.processes[child.pid] = child
    runtime.register("crashed fixture", child.pid)
    child.terminate()
    child.wait(timeout=10)
    runtime.refresh()
    assert runtime.service_status(runtime.state["services"]["crashed fixture"]) == "STOPPED"
    assert runtime.stop_services(lambda *args: None)
    assert not runtime.path.exists()


def test_native_launcher_lock_prevents_concurrent_owner(owned_runtime, tmp_path):
    runtime, _ = owned_runtime
    competitor = dev.Runtime(tmp_path)
    try:
        assert not competitor.acquire()
        assert runtime.load()["instance"] == runtime.state["instance"]
    finally:
        competitor.release()


def test_native_unrelated_port_conflict_never_signals(monkeypatch, tmp_path):
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    forbidden = Mock(side_effect=AssertionError("port conflict attempted termination"))
    monkeypatch.setattr(dev.Runtime, "terminate", forbidden)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with pytest.raises(dev.SetupError, match="already in use"):
            dev.check_application_ports(port, port)
        assert listener.getsockname()[1] == port
        assert dev.reachable("127.0.0.1", port)
    forbidden.assert_not_called()


def test_native_cli_missing_node_has_actionable_failure_without_setup(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), PATH="")
    result = subprocess.run(
        [sys.executable, str(Path(dev.__file__).resolve()), "doctor", "--profile", "legacy"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 1
    assert "Node.js" in result.stderr and "Install" in result.stderr
    assert not list(tmp_path.iterdir())


def test_native_cli_incomplete_profile_fails_before_setup_without_fallback(tmp_path):
    private = tmp_path / ".sbom-greenfield-uuid"
    private.mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path), PATH="")
    result = subprocess.run(
        [sys.executable, str(Path(dev.__file__).resolve()), "start", "--profile", "auto"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 1
    assert "incomplete" in result.stderr and "No fallback" in result.stderr
    assert list(tmp_path.iterdir()) == [private]
    assert not list(private.iterdir())
