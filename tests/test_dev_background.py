"""Complete local runtime health contracts without real brokers or databases."""

import json
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "greenfield")
    state = {"instance": "synthetic-instance", "profile": "greenfield", "services": {}}
    env = {
        "SBOM_DEV_INSTANCE": state["instance"],
        "SBOM_DEV_PROFILE": "greenfield",
        "SBOM_DEV_STATE_DIR": str(tmp_path),
        "DATABASE_URL": "postgresql+psycopg://test:synthetic@127.0.0.1:56044/sbom_greenfield_uuid",
        "REDIS_URL": "redis://127.0.0.1:56381/0",
        "CELERY_BROKER_URL": "redis://127.0.0.1:56381/0",
    }
    manager = Mock(state=state, path=tmp_path / "runtime.json")
    manager.service_status.return_value = "RUNNING"
    manager.load.return_value = state
    for index, (name, role, queues) in enumerate(
        (
            ("Celery worker", "default", ["celery"]),
            ("Celery reports worker", "reports", ["reports"]),
            ("Celery Beat", "beat", None),
        ),
        100,
    ):
        state["services"][name] = {"pid": index}
        data = {"instance": state["instance"], "pid": index, "time": time.time(), "connected": True}
        if queues:
            data.update(node=dev.worker_node(role, state["instance"], "greenfield"), queues=queues)
        dev.heartbeat_path(env, role).write_text(json.dumps(data))
    return manager, env


@pytest.mark.parametrize("platform,pool", [("win32", "solo"), ("darwin", "solo"), ("linux", "prefork")])
def test_every_platform_has_two_queue_workers_and_exactly_one_separate_beat(runtime, monkeypatch, platform, pool):
    manager, env = runtime
    monkeypatch.setattr(dev.sys, "platform", platform)
    commands = dev.background_commands(env)
    assert set(commands) == {"Celery worker", "Celery reports worker", "Celery Beat"}
    for name, queue in (("Celery worker", "celery"), ("Celery reports worker", "reports")):
        assert "--queues=" + queue in commands[name]
        assert "--pool=" + pool in commands[name]
        assert "--beat" not in commands[name]
        assert "scripts.dev:celery_app" in commands[name]
    assert sum("beat" in command for command in commands.values()) == 1
    assert "--scheduler=scripts.dev:LocalScheduler" in commands["Celery Beat"]


def test_process_presence_alone_is_never_background_readiness(runtime):
    manager, env = runtime
    dev.heartbeat_path(env, "reports").unlink()
    with pytest.raises(dev.SetupError, match="Celery reports worker.*heartbeat"):
        dev.background_health(manager, env)


@pytest.mark.parametrize("role", ["default", "reports", "beat"])
def test_stale_or_foreign_heartbeat_is_rejected(runtime, role):
    manager, env = runtime
    path = dev.heartbeat_path(env, role)
    data = json.loads(path.read_text())
    data["instance"] = "foreign-instance"
    path.write_text(json.dumps(data))
    with pytest.raises(dev.SetupError, match="another instance"):
        dev.background_health(manager, env)
    data.update(instance=manager.state["instance"], time=time.time() - 90)
    path.write_text(json.dumps(data))
    with pytest.raises(dev.SetupError, match="stale"):
        dev.background_health(manager, env)


def test_wrong_queue_is_rejected(runtime):
    manager, env = runtime
    path = dev.heartbeat_path(env, "reports")
    data = json.loads(path.read_text())
    data["queues"] = ["celery"]
    path.write_text(json.dumps(data))
    with pytest.raises(dev.SetupError, match="reports worker.*wrong queues"):
        dev.background_health(manager, env)


def control_fixture(monkeypatch, manager, env):
    inspector = Mock()
    nodes = [
        (dev.worker_node(role, manager.state["instance"], "greenfield"), name, queue)
        for role, name, queue in (
            ("default", "Celery worker", "celery"),
            ("reports", "Celery reports worker", "reports"),
        )
    ]
    inspector.ping.return_value = {node: {"ok": "pong"} for node, _, _ in nodes}
    inspector.active_queues.return_value = {node: [{"name": queue}] for node, _, queue in nodes}
    inspector.stats.return_value = {node: {"pid": manager.state["services"][name]["pid"]} for node, name, _ in nodes}
    app = Mock()
    app.control.inspect.return_value = inspector
    context = Mock()
    context.__enter__ = Mock(return_value=app)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(dev, "celery_control", Mock(return_value=context))
    return inspector, nodes


def test_startup_requires_ping_actual_queues_and_owned_worker_pid(runtime, monkeypatch):
    manager, env = runtime
    inspector, nodes = control_fixture(monkeypatch, manager, env)
    dev.background_health(manager, env, require_control=True)
    inspector.ping.return_value.pop(nodes[1][0])
    with pytest.raises(dev.SetupError, match="reports worker.*control ping"):
        dev.background_health(manager, env, require_control=True)


def test_foreign_control_pid_cannot_attest_owned_worker_health(runtime, monkeypatch):
    manager, env = runtime
    inspector, nodes = control_fixture(monkeypatch, manager, env)
    inspector.stats.return_value[nodes[0][0]]["pid"] = 999999
    with pytest.raises(dev.SetupError, match="owned worker PID"):
        dev.background_health(manager, env, require_control=True)


def test_existing_unmanaged_worker_blocks_duplicate_start_without_termination(runtime, monkeypatch):
    manager, env = runtime
    inspector, _ = control_fixture(monkeypatch, manager, env)
    forbidden = Mock(side_effect=AssertionError("foreign process was terminated"))
    monkeypatch.setattr(dev.Runtime, "terminate", forbidden)
    with pytest.raises(dev.SetupError, match="Unmanaged Celery"):
        dev.reject_foreign_workers(env)
    forbidden.assert_not_called()
    inspector.ping.return_value = {}
    dev.reject_foreign_workers(env)


def test_broker_control_failure_names_component_and_corrective_action(runtime, monkeypatch):
    _, env = runtime
    monkeypatch.setattr(dev, "celery_control", Mock(side_effect=ConnectionError("synthetic connection refused")))
    with pytest.raises(dev.SetupError, match="Celery worker.*broker control connection failed.*Log:.*restart"):
        dev.reject_foreign_workers(env)


def test_data_failure_prevents_any_background_process(runtime, monkeypatch):
    manager, env = runtime
    monkeypatch.setattr(dev, "verify_data_connectivity", Mock(side_effect=dev.SetupError("PostgreSQL unavailable")))
    start = Mock()
    monkeypatch.setattr(dev, "start_process", start)
    with pytest.raises(dev.SetupError, match="PostgreSQL"):
        dev.start_background(manager, env, Path("cwd"))
    start.assert_not_called()


def test_start_order_waits_for_api_and_workers_before_frontend(runtime, monkeypatch):
    manager, env = runtime
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", manager)
    calls = []
    monkeypatch.setattr(dev, "start_background", lambda *args: calls.append("background healthy") or {})
    monkeypatch.setattr(dev, "start_process", lambda name, *args: calls.append(name) or Mock())
    monkeypatch.setattr(
        dev, "wait_http_component", lambda manager, env, name, *args, **kwargs: calls.append(name + " healthy")
    )
    monkeypatch.setattr(dev, "background_health", lambda *args, **kwargs: calls.append("queues verified"))
    dev.launch_services(
        env, 18000, 13000, ["node", "next"], cwd=Path("cwd"), frontend_cwd=Path("ui"), tls_context=Mock()
    )
    assert calls == ["background healthy", "API", "API healthy", "Frontend", "Frontend healthy", "queues verified"]
    assert manager.state["ready"] is True


def test_saved_powershell_is_data_not_executable(monkeypatch, tmp_path):
    path = tmp_path / "settings.ps1"
    path.write_text("$env:DATABASE_URL = 'synthetic'\n$env:LABEL = 'a''b'\n")
    assert dev.read_literal_windows_configuration(path)["LABEL"] == "a'b"
    path.write_text("$env:DATABASE_URL = $(Get-Credential)\n")
    with pytest.raises(dev.SetupError, match="not executed"):
        dev.read_literal_windows_configuration(path)


def test_setup_database_flags_are_rejected_by_start_before_side_effects(monkeypatch):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start", "--initialize-database"])
    forbidden = Mock(side_effect=AssertionError("startup side effects"))
    monkeypatch.setattr(dev, "ensure_virtualenv", forbidden)
    with pytest.raises(dev.SetupError, match="only.*setup"):
        dev.main()
    forbidden.assert_not_called()
