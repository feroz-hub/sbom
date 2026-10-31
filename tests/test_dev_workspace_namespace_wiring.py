"""Execute actual queue/key wiring with in-memory transports and no app startup.

AST selection omits production imports/initialization, not the statements under
test. The original Celery configuration, report decorators/dispatch functions and
Native heartbeat/rate-limit functions execute unchanged against narrow fakes.
Run --noconftest: repository conftest can select/migrate/truncate PostgreSQL.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import io
import os
import socket
import subprocess
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from app import dev_instance as namespaces
from celery import Celery as MemoryCelery

ROOT = Path(__file__).resolve().parents[1]
CELERY = "app/workers/celery_app.py"
WORKER = "app/workers/report_notifications.py"
ROUTER = "app/routers/report_notifications.py"
OPERATIONS = "app/services/native_operations.py"
ABUSE = "app/services/native_abuse_service.py"
TREES = {
    name: ast.parse((ROOT / name).read_text(encoding="utf-8"), filename=name)
    for name in (CELERY, WORKER, ROUTER, OPERATIONS, ABUSE)
}
FIRST = "f8cf338c-4696-5862-b36d-989ad012ac79"
SECOND = "bb1c44d6-283e-548d-936e-0b42c29651cf"
SECRET = "synthetic-private-credential-never-output"


class FakeConf(SimpleNamespace):
    def __init__(self):
        super().__init__(updates=[])

    def update(self, **values):
        self.updates.append(values)
        self.__dict__.update(values)


class FakeTask:
    def __init__(self, function, options):
        self.function, self.options = function, options
        self.apply_async = Mock()

    def __call__(self, *arguments, **keywords):
        return self.function(*arguments, **keywords)


class FakeQuery:
    def where(self, *arguments):
        return self

    def limit(self, *arguments):
        return self

    def with_for_update(self, *arguments):
        return self


class FakeSession:
    def __init__(self, *, targets=(), row=None):
        self.execute = Mock(return_value=targets)
        self.scalar = Mock(return_value=row)
        self.commit, self.rollback = Mock(), Mock()

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        return False


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.writes, self.lookups = [], []

    def set(self, key, value, *, ex):
        self.writes.append((key, value, ex))
        self.values[key] = value

    def exists(self, key):
        self.lookups.append(key)
        return key in self.values

    def ping(self):
        return True

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        return False


class ResponseError(Exception):
    def __init__(self, status_code, detail, headers=None):
        self.status_code, self.detail, self.headers = status_code, detail, headers
        super().__init__(detail)


class FakeLimiter:
    def __init__(self):
        self.counts, self.hits = {}, []

    def hit(self, amount, *parts):
        self.hits.append((amount, *parts))
        self.counts[parts] = self.counts.get(parts, 0) + 1
        return self.counts[parts] <= amount


@pytest.fixture(autouse=True)
def protected_boundaries(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Namespace contract entered a real resource or startup path"))
    original_import = builtins.__import__
    report_task = SimpleNamespace(value=None)

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 2 and name == "workers.report_notifications" and report_task.value is not None:
            return SimpleNamespace(generate=report_task.value)
        package = (globals or {}).get("__package__", "")
        if (
            name.split(".", 1)[0] in {"app", "sqlalchemy", "psycopg", "redis", "limits", "dotenv"}
            or level
            and package.startswith("app")
        ):
            return forbidden(name)
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    yield SimpleNamespace(forbidden=forbidden, report_task=report_task)
    forbidden.assert_not_called()


def _is_namespace(node):
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "_INSTANCE_NAMESPACE" for target in node.targets
    )


def load(path, environment=None, *, functions=(), support=None):
    """Compile actual public source nodes; no importlib/app initialization."""
    selected = []
    for node in TREES[path].body:
        if _is_namespace(node) or isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
        elif path == CELERY:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name)
                and target.id == "celery_app"
                or isinstance(target, ast.Attribute)
                and target.attr == "beat_schedule"
                for target in node.targets
            ):
                selected.append(node)
            elif (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "update"
            ):
                selected.append(node)
            elif isinstance(node, ast.If):
                selected.append(node)
    assert sum(_is_namespace(node) for node in selected) == 1
    values = {
        "__name__": "synthetic_namespace_contract",
        "__package__": "app.routers" if path == ROUTER else "app.workers",
        "get_instance_namespace": lambda: namespaces.get_instance_namespace({} if environment is None else environment),
        **(support or {}),
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), path, "exec"), values)
    return SimpleNamespace(**values)


def celery(environment=None):
    created = []

    def construct(*arguments, **keywords):
        item = SimpleNamespace(arguments=arguments, keywords=keywords, conf=FakeConf())
        created.append(item)
        return item

    fixture = load(
        CELERY,
        environment,
        support={
            "Celery": construct,
            "_broker_url": lambda: "memory://",
            "_result_backend": lambda: "cache+memory://",
            "crontab": lambda **values: ("crontab", values),
        },
    )
    assert len(created) == 1
    return fixture.celery_app


def worker(environment=None, *, session=None):
    tasks = []

    def shared_task(**options):
        def decorate(function):
            task = FakeTask(function, options)
            tasks.append(task)
            return task

        return decorate

    functions = tuple(node.name for node in TREES[WORKER].body if isinstance(node, ast.FunctionDef))
    settings = SimpleNamespace(report_notifications_enabled=True, report_generation_timeout_seconds=60)
    fixture = load(
        WORKER,
        environment,
        functions=functions,
        support={
            "shared_task": shared_task,
            "get_settings": lambda: settings,
            "SessionLocal": lambda: session,
            "select": lambda *arguments: FakeQuery(),
            "ReportDelivery": SimpleNamespace(id=1, tenant_id=7, status="PENDING"),
            "tenant_scope": lambda context: nullcontext(),
            "minimal_background_context": lambda tenant: tenant,
            "now_iso": lambda: "2026-10-31T00:00:00+00:00",
            "datetime": datetime,
            "timedelta": timedelta,
            "UTC": UTC,
            "log": SimpleNamespace(warning=Mock()),
        },
    )
    fixture.tasks = tasks
    return fixture


def operations(environment=None, client=None):
    return load(
        OPERATIONS,
        environment,
        functions=("heartbeat", "readiness"),
        support={
            "redis_client": lambda: client,
            "get_settings": lambda: SimpleNamespace(native_security_outbox_enabled=True),
            "select": lambda *arguments: FakeQuery(),
            "SecurityMailOutbox": SimpleNamespace(id=1),
        },
    )


def abuse(environment=None, strategy=None, *, ip_limit=10, account_limit=1, enabled=True):
    return load(
        ABUSE,
        environment,
        functions=("check",),
        support={
            "get_settings": lambda: SimpleNamespace(
                native_auth_rate_limit_enabled=enabled,
                native_auth_rate_limit_storage_uri="memory://",
                native_auth_ip_limit_per_minute=ip_limit,
                native_auth_account_limit_per_minute=account_limit,
            ),
            "os": SimpleNamespace(getenv=lambda name, default=None: default),
            "hashlib": hashlib,
            "limiter": lambda uri: strategy,
            "RateLimitItemPerMinute": lambda amount: amount,
            "HTTPException": ResponseError,
            "log": SimpleNamespace(warning=Mock()),
        },
    )


@pytest.mark.parametrize("identifier", [None, FIRST, SECOND])
def test_actual_celery_routes_and_all_report_decorators_agree_with_explicit_queue(identifier):
    environment = {} if identifier is None else {"SBOM_DEV_RESOURCE_ID": identifier}
    namespace = namespaces.get_instance_namespace(environment)
    configured, reports = celery(environment), worker(environment)
    assert configured.conf.task_routes == {"report_notifications.*": {"queue": namespace.queue_reports}}
    if identifier is None:
        assert len(configured.conf.updates) == 1
        assert "task_default_queue" not in configured.conf.__dict__
        assert "task_default_exchange" not in configured.conf.__dict__
        assert "task_default_routing_key" not in configured.conf.__dict__
        assert namespace.queue_default == "celery" and namespace.queue_reports == "reports"
    else:
        assert len(configured.conf.updates) == 2
        assert configured.conf.task_default_queue == namespace.queue_default
        assert configured.conf.task_default_exchange == namespace.queue_default
        assert configured.conf.task_default_routing_key == namespace.queue_default
    assert {task.options["name"] for task in reports.tasks} == {
        "report_notifications.generate",
        "report_notifications.tick",
        "report_notifications.dispatch_pending",
        "report_notifications.purge",
    }
    assert all(
        task.options["queue"] == namespace.queue_reports and task.options["ignore_result"] is True
        for task in reports.tasks
    )
    assert reports.generate.options["acks_late"] is True
    assert configured.conf.beat_schedule["security-mail-outbox"] == {"task": "security_mail.dispatch", "schedule": 30.0}
    assert (
        configured.conf.beat_schedule["report-notifications-outbox"]["task"] == "report_notifications.dispatch_pending"
    )


@pytest.mark.parametrize("identifier", [None, FIRST, SECOND])
def test_real_celery_memory_routing_resolves_default_and_report_queue_exchange(identifier):
    environment = {} if identifier is None else {"SBOM_DEV_RESOURCE_ID": identifier}

    def construct(*arguments, **keywords):
        return MemoryCelery(*arguments, set_as_current=False, fixups=[], **keywords)

    fixture = load(
        CELERY,
        environment,
        support={
            "Celery": construct,
            "_broker_url": lambda: "memory://",
            "_result_backend": lambda: "cache+memory://",
            "crontab": lambda **values: ("crontab", values),
        },
    )
    configured = fixture.celery_app
    namespace = namespaces.get_instance_namespace(environment)
    try:
        default = configured.amqp.router.route({}, "security_mail.dispatch")["queue"]
        report = configured.amqp.router.route({}, "report_notifications.generate")["queue"]
        assert default.name == default.exchange.name == default.routing_key == namespace.queue_default
        assert report.name == report.exchange.name == report.routing_key == namespace.queue_reports
    finally:
        configured.close()


@pytest.mark.parametrize("identifier", [None, FIRST, SECOND])
def test_actual_periodic_report_dispatch_publishes_on_the_same_namespaced_queue(identifier):
    environment = {} if identifier is None else {"SBOM_DEV_RESOURCE_ID": identifier}
    row = SimpleNamespace(status="PENDING", claimed_at=None, dispatch_started_at=None, next_attempt_at=None)
    session = FakeSession(targets=[(51, 7)], row=row)
    reports = worker(environment, session=session)
    assert reports._dispatch_for_tenant() == {"pending": 1}
    reports.generate.apply_async.assert_called_once_with(
        args=[51, 7],
        queue=namespaces.get_instance_namespace(environment).queue_reports,
        time_limit=60,
    )
    session.commit.assert_not_called()
    session.rollback.assert_not_called()


@pytest.mark.parametrize("identifier", [None, FIRST, SECOND])
def test_actual_send_now_dispatch_preserves_tenant_args_and_namespaced_queue(identifier, protected_boundaries):
    environment = {} if identifier is None else {"SBOM_DEV_RESOURCE_ID": identifier}
    reports = worker(environment)
    protected_boundaries.report_task.value = reports.generate
    session = FakeSession()
    sub = SimpleNamespace(enabled=True, last_delivered_at=None, created_on="2026-01-01")
    permission, rate_limit = Mock(), Mock()
    fixture = load(
        ROUTER,
        environment,
        functions=("send_now",),
        support={
            "router": SimpleNamespace(post=lambda *arguments, **keywords: lambda function: function),
            "Depends": lambda value: None,
            "reader": object(),
            "CurrentContext": object,
            "Session": object,
            "get_db": protected_boundaries.forbidden,
            "_subscription": lambda *arguments, **keywords: sub,
            "authorize_preferences": permission,
            "preferences_for": lambda value: "preferences",
            "recipient_context": lambda *arguments: "recipient-context",
            "_rate_limit": rate_limit,
            "now_iso": lambda: "2026-10-31",
            "create_delivery": lambda *arguments, **keywords: SimpleNamespace(id=52, tenant_id=7),
            "scope_sboms": lambda *arguments: [SimpleNamespace(id=101)],
            "get_settings": lambda: SimpleNamespace(report_generation_timeout_seconds=60),
        },
    )
    assert fixture.send_now(12, SimpleNamespace(tenant_id=7), session) == {"id": 52, "status": "PENDING"}
    reports.generate.apply_async.assert_called_once_with(
        args=[52, 7],
        queue=namespaces.get_instance_namespace(environment).queue_reports,
        time_limit=60,
    )
    permission.assert_called_once()
    rate_limit.assert_called_once()
    session.commit.assert_called_once()


def test_mail_heartbeat_producer_and_readiness_reader_cannot_cross_instance():
    client = FakeRedis()
    first = operations({"SBOM_DEV_RESOURCE_ID": FIRST}, client)
    second = operations({"SBOM_DEV_RESOURCE_ID": SECOND}, client)
    first.heartbeat()
    assert first.readiness(FakeSession())["ready"] is True
    other = second.readiness(FakeSession())
    assert other["ready"] is False and other["checks"]["delivery_worker"] is False
    assert client.writes == [(namespaces.InstanceNamespace(FIRST).mail_worker_heartbeat, "ready", 120)]
    second.heartbeat()
    assert second.readiness(FakeSession())["ready"] is True
    assert len(client.values) == 2


def test_legacy_mail_heartbeat_name_value_and_ttl_are_exactly_preserved():
    client = FakeRedis()
    legacy = operations(client=client)
    legacy.heartbeat()
    assert legacy.readiness(FakeSession())["ready"] is True
    assert client.writes == [("sbom:iam:mail-worker", "ready", 120)]
    assert client.lookups == ["sbom:iam:mail-worker"]


@pytest.mark.parametrize("account", ["", " Account@Example.Test "])
def test_actual_native_rate_buckets_isolate_instances_without_exposing_accounts(account):
    strategy = FakeLimiter()
    first = abuse({"SBOM_DEV_RESOURCE_ID": FIRST}, strategy, ip_limit=1)
    second = abuse({"SBOM_DEV_RESOURCE_ID": SECOND}, strategy, ip_limit=1)
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.1"))
    first.check(request, "login", account)
    second.check(request, "login", account)
    with pytest.raises(ResponseError) as caught:
        first.check(request, "login", account)
    assert caught.value.status_code == 429 and caught.value.headers == {"Retry-After": "60"}
    buckets = {hit[1] for hit in strategy.hits}
    expected = {namespaces.InstanceNamespace(value).native_rate_limit_bucket for value in (FIRST, SECOND)}
    if account:
        expected |= {namespaces.InstanceNamespace(value).native_account_rate_limit_bucket for value in (FIRST, SECOND)}
        assert hashlib.sha256(account.strip().lower().encode()).hexdigest() in repr(strategy.hits)
        assert "account@example.test" not in repr(strategy.hits).lower()
    assert buckets == expected


def test_actual_legacy_native_buckets_and_hashing_remain_unchanged():
    strategy = FakeLimiter()
    legacy = abuse(strategy=strategy)
    legacy.check(SimpleNamespace(client=SimpleNamespace(host="192.0.2.2")), "login", " A@Example.Test ")
    assert strategy.hits == [
        (10, "native", "login", "192.0.2.2"),
        (1, "native-account", "login", hashlib.sha256(b"a@example.test").hexdigest()),
    ]


def test_limiter_transport_failure_still_fails_closed_and_redacts_private_details():
    strategy = SimpleNamespace(hit=Mock(side_effect=OSError(SECRET)))
    isolated = abuse({"SBOM_DEV_RESOURCE_ID": FIRST}, strategy)
    with pytest.raises(ResponseError) as caught:
        isolated.check(SimpleNamespace(client=None), "login", " A@Example.Test ")
    assert caught.value.status_code == 503 and SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "environment",
    [
        {"SBOM_DEV_RESOURCE_ID": ""},
        {"SBOM_DEV_RESOURCE_ID": SECRET},
        {"SBOM_DEV_RESOURCE_ID": None},
        {"sbom_dev_resource_id": FIRST},
        {"SBOM_DEV_RESOURCE_ID": FIRST, "sbom_dev_resource_id": FIRST},
    ],
)
@pytest.mark.parametrize("path", [CELERY, WORKER, ROUTER, OPERATIONS, ABUSE])
def test_malformed_or_ambiguous_uuid_fails_before_task_configuration_or_resource_calls(environment, path):
    forbidden = Mock(side_effect=AssertionError("Invalid UUID reached task or resource initialization"))
    with pytest.raises(namespaces.InstanceNamespaceError) as caught:
        load(path, environment, support={"Celery": forbidden})
    assert caught.value.code == "DEV_INSTANCE_RESOURCE_ID_INVALID"
    assert SECRET not in str(caught.value)
    forbidden.assert_not_called()


def test_persistent_uuid_is_snapshotted_and_not_replaced_by_launch_generation():
    environment = {"SBOM_DEV_RESOURCE_ID": FIRST, "SBOM_DEV_INSTANCE": "synthetic-launch-one"}
    first = operations(environment, FakeRedis())
    environment["SBOM_DEV_INSTANCE"] = "synthetic-launch-two"
    second = operations(environment, FakeRedis())
    assert first._INSTANCE_NAMESPACE == second._INSTANCE_NAMESPACE
    environment["SBOM_DEV_RESOURCE_ID"] = SECOND
    assert first._INSTANCE_NAMESPACE.resource_id == FIRST
    assert operations(environment, FakeRedis())._INSTANCE_NAMESPACE.resource_id == SECOND


def test_report_queue_callsite_audit_has_no_unwired_literal_dispatch_or_task_queue():
    calls = [
        keyword.value
        for name in (WORKER, ROUTER)
        for node in ast.walk(TREES[name])
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "queue"
    ]
    assert len(calls) == 6
    assert all(
        isinstance(value, ast.Attribute)
        and value.attr == "queue_reports"
        and isinstance(value.value, ast.Name)
        and value.value.id == "_INSTANCE_NAMESPACE"
        for value in calls
    )
    assert '"report_notifications.*": {"queue": "reports"}' in ast.unparse(TREES[CELERY]).replace("'", '"')
