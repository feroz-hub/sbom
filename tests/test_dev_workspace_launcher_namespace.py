"""Real launcher queue/scheduler helpers with synthetic transports only."""

import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from app.dev_instance import get_instance_namespace
from scripts import dev

FIRST = "f8cf338c-4696-5862-b36d-989ad012ac79"
SECOND = "bb1c44d6-283e-548d-936e-0b42c29651cf"


@pytest.mark.parametrize("resource", [None, FIRST, SECOND])
def test_real_launcher_commands_and_health_expect_same_exact_queues(tmp_path, monkeypatch, resource):
    environment = {"SBOM_DEV_INSTANCE": "a" * 32, "SBOM_DEV_PROFILE": "legacy", "SBOM_DEV_STATE_DIR": str(tmp_path)}
    if resource is not None:
        environment["SBOM_DEV_RESOURCE_ID"] = resource
    namespace = get_instance_namespace(environment)
    monkeypatch.setattr(dev, "venv_python", lambda: tmp_path / "synthetic-python")
    commands = dev.background_commands(environment)
    assert "--queues=" + namespace.queue_default in commands["Celery worker"]
    assert "--queues=" + namespace.queue_reports in commands["Celery reports worker"]
    records = {}
    for component, role, queue in (
        ("Celery worker", "default", namespace.queue_default),
        ("Celery reports worker", "reports", namespace.queue_reports),
        ("Celery Beat", "beat", None),
    ):
        records[component] = {"pid": 123}
        data = {
            "instance": environment["SBOM_DEV_INSTANCE"],
            "pid": 123,
            "time": time.time(),
            "connected": True,
            "node": dev.worker_node(role, environment["SBOM_DEV_INSTANCE"], "legacy"),
            "queues": [queue] if queue else [],
        }
        (tmp_path / (role + "-health.json")).write_text(json.dumps(data), encoding="utf-8")
    runtime = SimpleNamespace(
        state={"instance": environment["SBOM_DEV_INSTANCE"], "services": records}, service_status=lambda _: "RUNNING"
    )
    monkeypatch.setattr(dev, "service_pid_matches", lambda *_: True)
    dev.background_health(runtime, environment)
    default_path = tmp_path / "default-health.json"
    value = json.loads(default_path.read_text(encoding="utf-8"))
    value["queues"] = ["unrelated-queue"]
    default_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(dev.SetupError, match="wrong queues"):
        dev.background_health(runtime, environment)


@pytest.mark.parametrize("resource", [None, FIRST, SECOND])
def test_actual_scheduler_lease_uses_optional_persistent_namespace(tmp_path, monkeypatch, resource):
    import redis
    from celery import beat

    environment = {
        "SBOM_DEV_INSTANCE": "a" * 32,
        "SBOM_DEV_PROFILE": "legacy",
        "REDIS_URL": "redis://synthetic.invalid:1/0",
        "DATABASE_URL": "postgresql://synthetic.invalid:2/isolated",
    }
    if resource is not None:
        environment["SBOM_DEV_RESOURCE_ID"] = resource
    monkeypatch.setattr(dev.os, "environ", environment)
    client = Mock()
    client.eval.return_value = 1
    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: client)
    monkeypatch.setattr(beat.PersistentScheduler, "tick", lambda *_args, **_kwargs: 1)
    heartbeat = Mock()
    monkeypatch.setattr(dev, "write_service_heartbeat", heartbeat)
    scheduler = object.__new__(dev.local_scheduler_class())
    monkeypatch.setattr(type(scheduler), "schedule", property(lambda _: {}))
    assert scheduler.tick() == 1
    assert client.eval.call_args.args[2] == (
        get_instance_namespace(environment).beat_namespace + ":legacy:synthetic.invalid:2:/isolated"
    )
    heartbeat.assert_called_once_with(environment, "beat", scheduled_tasks=0)
