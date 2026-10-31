"""Fake network/OS/crypto probes; only disposable public/private file fixtures."""

from __future__ import annotations

import base64
import ctypes
import importlib.util
import io
import json
import os
import socket
import ssl
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qsl, quote_plus, urlsplit

import pytest
from scripts import dev_instance_registry, dev_instance_storage, dev_private
from scripts import dev_workspace_preview as preview
from scripts import dev_workspace_readiness as readiness

SECRET = "synthetic-readiness-secret-never-expose"


def prepared_context(tmp_path, monkeypatch, *, auth="native"):
    # Positive fake transports must not depend on the hosted runner's libpq
    # configuration. Security cases explicitly reintroduce ambient inputs later.
    for name in tuple(os.environ):
        if name.startswith("PG") or name == "SSLKEYLOGFILE":
            monkeypatch.delenv(name, raising=False)
    fixture_spec = importlib.util.spec_from_file_location("readiness_pure_lifecycle_fixture",
                                                        Path(__file__).with_name("test_dev_workspace_lifecycle.py"))
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    descriptor, snapshot = fixture.prepared(platform=sys.platform, auth=auth)
    anchor = tmp_path.resolve() / "private fixture"
    if sys.platform == "win32":
        dev_instance_storage._windows_create(anchor)
    else:
        anchor.mkdir(mode=0o700)
    root, source = anchor / descriptor.instance_id, anchor / "source"
    tlsroot = root / "bundles" / "fixture-generation" / "tls"
    for path in (root, source, tlsroot):
        dev_instance_storage.initialize_private_directory(path, anchor=anchor)
    for name in ("leaf.pem", "key.pem", "trust-bundle.pem"):
        dev_private.create_private_file(tlsroot / name, ("synthetic fixture " + SECRET).encode())
    tls = preview.PreviewTls(tlsroot / "leaf.pem", tlsroot / "key.pem", tlsroot / "trust-bundle.pem")
    env = {key: value.replace(snapshot.state_root, str(root)).replace(quote_plus(snapshot.state_root, safe=""),
            quote_plus(str(root), safe="")) for key, value in snapshot.environment.items()}
    env["SBOM_DEV_INSTANCE"] = "f" * 32
    env["SBOM_DEV_STATE_DIR"] = str(root / ".dev-logs")
    env["SBOM_DEV_PROFILE"] = "isolated"
    dev_instance_storage.initialize_private_directory(root / ".dev-logs", anchor=anchor)
    def worker_node(role, instance, profile):
        return f"sbom-{profile}-{instance[:12]}-{role}@fixture-host"
    for index, role in enumerate(("default", "reports", "beat")):
        heartbeat = {"instance": env["SBOM_DEV_INSTANCE"], "pid": 10 + index, "time": readiness.time.time()}
        if role == "beat":
            heartbeat["scheduled_tasks"] = 3
        else:
            heartbeat.update(node=worker_node(role, env["SBOM_DEV_INSTANCE"], "isolated"), connected=True,
                queues=[descriptor.resources["queue_default" if role == "default" else "queue_reports"]])
        dev_private.create_private_file(root / ".dev-logs" / (role + "-health.json"), json.dumps(heartbeat).encode())
    if auth == "hcl":
        env["HCL_IAM_CLIENT_ID"] = "fixture-client"
    def identity(pid):
        return {"pid": pid, "birth": "birth-" + str(pid), "exe": "verified-executable"}
    records = {name: {**identity(index + 10), "members": []} for index, name in enumerate(readiness.dev_workspace_lifecycle.COMPONENTS)}
    info = dev_instance_registry._private(root, directory=True)
    state = {"instance": "f" * 32, "workspace_context": {"instance_id": descriptor.instance_id,
        "repository_id": descriptor.repository_id, "worktree_id": descriptor.worktree_id,
        "root_identity": [info.st_dev, info.st_ino]}, "services": records}
    runtime = SimpleNamespace(root=root, state=state, service_status=Mock(return_value="RUNNING"))
    launcher = SimpleNamespace(process_info=Mock(side_effect=identity), matches=lambda saved, current:
        all(saved.get(key) == current.get(key) for key in ("pid", "birth", "exe")),
        background_health=Mock(), validate_secrets=Mock(), worker_node=worker_node)
    providers = {name: (identity(index + 30),) for index, name in enumerate(("postgres", "redis", "mailpit"))}
    origins = ("https://identity.example.test",) if auth == "hcl" else ()
    context = readiness.ReadinessContext(descriptor, env, root, source, tls, "103_tenant_admin_governance", providers, origins)
    listener = Mock(side_effect=lambda address, port, pids, **kwargs: frozenset(pids))
    requests = []
    def request(scheme, host, port, path, timeout, context=None, **kwargs):
        requests.append((scheme, host, port, path, timeout, context, kwargs))
        return readiness.HttpResponse(200, json.dumps({"ready": True} if path == "/ready/iam" else {"service": "sbom-analyzer-api"}).encode())
    secure = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED, keylog_filename=None)
    monkeypatch.setattr(readiness, "_ssl_context", lambda *_: secure)
    tls_validator = Mock(return_value=secure)
    connect = Mock(side_effect=AssertionError("Unconfigured fake DB connection"))
    probe = readiness.WorkspaceReadiness(context, launcher, lambda: runtime, listener_inspector=listener,
                                        request=request, db_connect=connect, tls_validator=tls_validator)
    forbidden = Mock(side_effect=AssertionError("Readiness test attempted a real network/system probe"))
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    return SimpleNamespace(context=context, root=root, source=source, launcher=launcher, runtime=runtime,
                           records=records, probe=probe, requests=requests, listener=listener, connect=connect,
                           secure=secure, tls_validator=tls_validator, forbidden=forbidden, identity=identity)


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    value = prepared_context(tmp_path, monkeypatch)
    yield value
    value.forbidden.assert_not_called()


def spec(candidate, name):
    port = candidate.context.descriptor.ports["api" if name == "API" else "frontend"] if name in {"API", "Frontend"} else None
    return SimpleNamespace(name=name, environment=candidate.context.environment, port=port)


def test_api_inert_identifier_and_iam_are_bound_to_verified_process_before_and_after(candidate):
    assert candidate.probe.api(spec(candidate, "API"), 3)
    assert [call[3] for call in candidate.requests] == ["/", "/ready/iam"]
    assert not any("/health" in call[3] for call in candidate.requests)
    assert candidate.listener.call_count == 4
    assert candidate.launcher.process_info.call_count >= 8
    assert candidate.probe.results["API"].to_dict() == {"component": "API", "status": "PASS", "code": "API_READY", "winerror": None}
    assert SECRET not in repr(candidate.context) + repr(candidate.probe.results)


@pytest.mark.parametrize("owners", [frozenset({999}), frozenset({13, 999})])
def test_foreign_or_mixed_listener_owners_block_before_any_request(candidate, owners):
    candidate.listener.return_value = owners
    candidate.listener.side_effect = None
    with pytest.raises(readiness.ReadinessError, match="^LISTENER_OWNER_UNVERIFIED$"):
        candidate.probe.api(spec(candidate, "API"), 3)
    assert candidate.requests == []


def test_confirmed_absence_is_pending_without_connecting(candidate):
    candidate.listener.side_effect = None
    candidate.listener.return_value = frozenset()
    assert candidate.probe.api(spec(candidate, "API"), 3) is False
    assert candidate.probe.results["API"].code == "LISTENER_NOT_READY" and candidate.requests == []


def test_pid_reuse_after_response_blocks_readiness(candidate):
    original = candidate.probe.request
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        candidate.launcher.process_info.side_effect = lambda pid: {**candidate.identity(pid), "birth": "reused"}
        return result
    candidate.probe.request = changed
    with pytest.raises(readiness.ReadinessError, match="^PROCESS_IDENTITY_UNVERIFIED$"):
        candidate.probe.api(spec(candidate, "API"), 3)
    assert len(candidate.requests) == 1


def test_ownership_rechecked_even_when_network_probe_raises(candidate):
    candidate.probe.request = Mock(side_effect=ConnectionError(SECRET))
    assert candidate.probe.api(spec(candidate, "API"), 3) is False
    assert candidate.listener.call_count == 2
    assert SECRET not in repr(candidate.probe.results)


def test_access_denied_listener_error_has_safe_windows_code_and_no_request(candidate):
    candidate.listener.side_effect = readiness.ReadinessError("LISTENER_ENUMERATION_UNVERIFIED", 5)
    with pytest.raises(readiness.ReadinessError) as caught:
        candidate.probe.api(spec(candidate, "API"), 3)
    assert caught.value.winerror == 5 and candidate.requests == []


def test_frontend_connects_numeric_loopback_with_verified_origin_hostname(candidate):
    assert candidate.probe.frontend(spec(candidate, "Frontend"), 3)
    scheme, host, port, path, timeout, context, kwargs = candidate.requests[0]
    assert scheme == "https" and host == candidate.context.descriptor.hostname and kwargs == {"address": "127.0.0.1"}
    assert path == "/native-sign-in" and context is candidate.secure and 0 < timeout <= 3
    candidate.tls_validator.assert_called_once_with(candidate.context.tls, candidate.context.descriptor.hostname)
    public = candidate.probe.results["Frontend"].to_dict()
    assert public["trust_scope"] == "explicit_client_ca_and_hostname"
    assert public["browser_trust_verified"] is public["login_acceptance_verified"] is False
    assert candidate.context.to_public_dict()["browser_trust"] == "UNVERIFIED"
    assert candidate.context.browser_trust_verified is False


def test_runtime_token_and_environment_target_drift_cannot_unlock_probe(candidate):
    changed = spec(candidate, "API")
    changed.environment = {**changed.environment, "SBOM_DEV_INSTANCE": "different"}
    with pytest.raises(readiness.ReadinessError, match="^RUNTIME_BINDING_UNVERIFIED$"):
        candidate.probe.api(changed, 3)
    assert candidate.requests == []


def test_explicit_background_startup_uses_control_only_after_all_process_and_broker_proofs(candidate):
    assert candidate.probe.background_startup(spec(candidate, "Celery worker"), 3)
    candidate.launcher.background_health.assert_called_once_with(candidate.runtime, dict(candidate.context.environment), require_control=True)
    assert candidate.listener.call_count == 2


def test_explicit_background_startup_control_warmup_is_pending_and_ownership_still_rechecked(candidate):
    candidate.launcher.background_health.side_effect = RuntimeError(SECRET)
    assert candidate.probe.background_startup(spec(candidate, "Celery worker"), 3) is False
    assert candidate.probe.results["Celery worker"].code == "BACKGROUND_NOT_READY"
    assert candidate.listener.call_count == 2 and SECRET not in repr(candidate.probe.results)


def test_background_cannot_substitute_a_different_broker_after_proving_local_listener(candidate):
    changed = spec(candidate, "Celery worker")
    changed.environment = {**changed.environment, "CELERY_BROKER_URL": "redis://foreign.example.test/0"}
    with pytest.raises(readiness.ReadinessError, match="^RUNTIME_BINDING_UNVERIFIED$"):
        candidate.probe.background(changed, 3)
    candidate.launcher.background_health.assert_not_called()
    candidate.listener.assert_not_called()


@pytest.mark.parametrize("component", readiness.dev_workspace_lifecycle.COMPONENTS[:3])
def test_default_background_is_passive_without_app_import_broker_control_or_network(candidate, monkeypatch, component):
    import builtins
    before = json.dumps(candidate.runtime.state, sort_keys=True)
    original_import = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "celery", "kombu", "redis"}
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded)
    forbidden = Mock(side_effect=AssertionError("Passive background constructed broker control"))
    candidate.launcher.background_health = forbidden
    candidate.launcher.celery_control = forbidden
    assert candidate.probe.background(spec(candidate, component), 3)
    result = candidate.probe.results[component]
    assert result.code == "BACKGROUND_HEARTBEAT_OBSERVED" and not result.to_dict()["active_control_verified"]
    assert result.to_dict()["observation_scope"] == "passive-owned-heartbeat"
    assert json.dumps(candidate.runtime.state, sort_keys=True) == before
    assert candidate.requests == []
    candidate.listener.assert_not_called()
    candidate.connect.assert_not_called()
    forbidden.assert_not_called()


@pytest.mark.parametrize("change", ["stale", "future", "pid", "instance", "queues", "connected", "node", "nan", "beat"])
def test_passive_background_rejects_unverified_or_stale_heartbeat_without_control(candidate, change):
    path = candidate.root / ".dev-logs" / ("beat-health.json" if change == "beat" else "default-health.json")
    value = json.loads(path.read_bytes())
    if change == "stale":
        value["time"] -= 30
    elif change == "future":
        value["time"] += 30
    elif change == "pid":
        value["pid"] = 999
    elif change == "instance":
        value["instance"] = SECRET
    elif change == "queues":
        value["queues"] = ["celery"]
    elif change == "connected":
        value["connected"] = 1
    elif change == "node":
        value["node"] = SECRET
    elif change == "nan":
        value["time"] = float("nan")
    else:
        value["scheduled_tasks"] = False
    path.write_bytes(json.dumps(value).encode())
    assert candidate.probe.background(spec(candidate, "Celery worker"), 3) is False
    assert candidate.probe.results["Celery worker"].code == "BACKGROUND_NOT_READY"
    assert SECRET not in repr(candidate.probe.results)
    candidate.launcher.background_health.assert_not_called()
    candidate.listener.assert_not_called()


def test_passive_background_missing_heartbeat_does_not_create_or_repair_it(candidate):
    path = candidate.root / ".dev-logs" / "default-health.json"
    path.unlink()  # Brand-new synthetic fixture only.
    assert candidate.probe.background(spec(candidate, "Celery worker"), 3) is False
    assert not path.exists()
    candidate.launcher.background_health.assert_not_called()


def test_passive_background_rechecks_process_birth_after_reading_heartbeats(candidate):
    original = candidate.probe._background_heartbeats
    def heartbeat(*args):
        original(*args)
        candidate.launcher.process_info.side_effect = lambda pid: {**candidate.identity(pid), "birth": "reused"}
    candidate.probe._background_heartbeats = heartbeat
    with pytest.raises(readiness.ReadinessError, match="^PROCESS_IDENTITY_UNVERIFIED$"):
        candidate.probe.background(spec(candidate, "Celery worker"), 3)
    candidate.launcher.background_health.assert_not_called()


def test_passive_background_rejects_duplicate_heartbeat_fields(candidate):
    path = candidate.root / ".dev-logs" / "default-health.json"
    path.write_bytes(b'{"time":1,"time":2}')
    assert candidate.probe.background(spec(candidate, "Celery worker"), 3) is False
    candidate.launcher.background_health.assert_not_called()


def test_missing_host_forwarder_receipt_blocks_database_before_connect(candidate):
    candidate.probe.context = replace(candidate.context, provider_processes={})
    with pytest.raises(readiness.ReadinessError, match="^PROVIDER_HOST_OWNERSHIP_REQUIRED$"):
        candidate.probe.database(3)
    candidate.connect.assert_not_called()


def database(candidate, *, wrong_target=False, readonly=True, revision=None):
    calls = []
    descriptor = candidate.context.descriptor
    class Connection:
        pgconn = SimpleNamespace(ssl_in_use=True)
        def execute(self, sql):
            calls.append(sql)
            if sql.startswith("SHOW"):
                return SimpleNamespace(fetchone=lambda: ("on" if readonly else "off",))
            if sql.startswith("SELECT pg_catalog.current_database"):
                return SimpleNamespace(fetchone=lambda: ("wrong" if wrong_target else descriptor.resources["database"], descriptor.resources["restricted_database_role"]))
            return SimpleNamespace(fetchall=lambda: [(revision or candidate.context.schema_revision,)])
        def rollback(self):
            calls.append("ROLLBACK")
        def close(self):
            calls.append("CLOSE")
        def commit(self):
            pytest.fail("Readonly readiness committed")
    connection = Connection()
    candidate.connect.side_effect = None
    candidate.connect.return_value = connection
    return calls


def test_database_uses_exact_kwargs_readonly_sql_rollback_close_and_rechecks_owner(candidate):
    calls = database(candidate)
    assert candidate.probe.database(3)
    kwargs = candidate.connect.call_args.kwargs
    assert kwargs["hostaddr"] == "127.0.0.1" and kwargs["dbname"] == candidate.context.descriptor.resources["database"]
    assert kwargs["autocommit"] is False and "default_transaction_read_only=on" in kwargs["options"]
    assert kwargs["sslmode"] == "verify-full" and kwargs["sslrootcert"] == str(candidate.context.tls.ca_bundle)
    assert kwargs["gssencmode"] == kwargs["sslcertmode"] == "disable"
    assert dict(parse_qsl(urlsplit(candidate.context.environment["DATABASE_URL"]).query))["sslrootcert"] == kwargs["sslrootcert"]
    assert calls[-2:] == ["ROLLBACK", "CLOSE"] and candidate.listener.call_count == 2


@pytest.mark.parametrize("key", ["DATABASE_URL", "REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"])
def test_fixture_relocation_updates_encoded_ca_paths_as_well_as_plain_environment(candidate, key):
    query = dict(parse_qsl(urlsplit(candidate.context.environment[key]).query))
    assert query["sslrootcert" if key == "DATABASE_URL" else "ssl_ca_certs"] == candidate.context.environment["SSL_CERT_FILE"]
    assert Path(candidate.context.environment["SSL_CERT_FILE"]) == candidate.context.tls.ca_bundle


def test_fake_context_isolates_inherited_libpq_and_keylog_configuration(tmp_path, monkeypatch):
    for name in ("PGSERVICE", "PGPASSWORD", "SSLKEYLOGFILE"):
        monkeypatch.setenv(name, SECRET)
    monkeypatch.setenv("SBOM_TEST_PUBLIC_TRANSPORT", "fixture-public-marker")
    candidate = prepared_context(tmp_path, monkeypatch)
    assert not any(name.startswith("PG") or name == "SSLKEYLOGFILE" for name in os.environ)
    assert os.environ["SBOM_TEST_PUBLIC_TRANSPORT"] == "fixture-public-marker"
    calls = database(candidate)
    assert candidate.probe.database(3) and calls[-2:] == ["ROLLBACK", "CLOSE"]
    candidate.forbidden.assert_not_called()


@pytest.mark.parametrize("name", ["PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGPASSWORD", "PGPASSFILE", "PGSSLCERT", "SSLKEYLOGFILE"])
def test_database_refuses_nonempty_ambient_transport_before_connect_without_mutating_environment(candidate, monkeypatch, name):
    monkeypatch.setenv(name, SECRET)
    before = dict(os.environ)
    with pytest.raises(readiness.ReadinessError, match="^DATABASE_AMBIENT_CONFIGURATION_REFUSED$"):
        candidate.probe.database(3)
    candidate.connect.assert_not_called()
    assert dict(os.environ) == before and SECRET not in repr(candidate.probe.results)


def test_database_detects_tls_downgrade_before_reading_any_schema(candidate):
    calls = database(candidate)
    candidate.connect.return_value.pgconn = SimpleNamespace(ssl_in_use=False)
    with pytest.raises(readiness.ReadinessError, match="^TLS_VERIFICATION_REQUIRED$"):
        candidate.probe.database(3)
    assert calls == ["ROLLBACK", "CLOSE"] and candidate.listener.call_count == 2


def test_database_ca_drift_still_closes_original_connection_and_rechecks_listener(candidate):
    calls = database(candidate)
    connection = candidate.connect.return_value
    original = connection.close
    def close():
        original()
        candidate.context.tls.ca_bundle.write_bytes(b"synthetic-changed-ca")
    connection.close = close
    with pytest.raises(readiness.ReadinessError, match="^TLS_MATERIAL_UNVERIFIED$"):
        candidate.probe.database(3)
    assert calls[-2:] == ["ROLLBACK", "CLOSE"] and candidate.listener.call_count == 2


def test_database_repeated_cancellation_during_rollback_still_attempts_close(candidate):
    database(candidate)
    connection = candidate.connect.return_value
    connection.rollback = Mock(side_effect=KeyboardInterrupt)
    connection.close = Mock()
    with pytest.raises(readiness.ReadinessError, match="^DATABASE_CLEANUP_UNCONFIRMED$"):
        candidate.probe.database(3)
    connection.close.assert_called_once()


class FakeRedis:
    tls_verified = True
    def __init__(self):
        self.calls, self.closed, self.allow_foreign, self.auth_ok = [], False, False, True
    def settimeout(self, timeout):
        assert 0 < timeout <= 3
    def command(self, *parts):
        self.calls.append(parts)
        if parts[0] == "AUTH":
            if not self.auth_ok:
                raise readiness.RedisReplyError()
            return b"OK"
        if parts[0] == "SELECT":
            return b"OK"
        if parts[0] == "PING":
            return b"PONG"
        assert parts[0] == "GET"
        if parts[1] == "sbom:readiness:outside-session-prefix" and not self.allow_foreign:
            raise readiness.RedisReplyError(permission_denied=True)
        return None
    def close(self):
        self.closed = True


class FakeMail:
    def __init__(self):
        self.calls, self.tls_verified, self.closed, self.auth_ok, self.starttls_supported = [], False, False, True, True
    def settimeout(self, timeout):
        assert 0 < timeout <= 3
    def ehlo(self):
        self.calls.append(("EHLO",))
        return 250
    def has_extn(self, name):
        assert name == "starttls"
        return self.starttls_supported
    def starttls(self, *, context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname and not context.keylog_filename
        self.calls.append(("STARTTLS",))
        self.tls_verified = True
        return 220
    def login(self, user, password):
        assert self.tls_verified
        self.calls.append(("AUTH", user, password))
        return self.auth_ok
    def quit(self):
        self.calls.append(("QUIT",))
    def close(self):
        self.closed = True


def provider_client(candidate, kind):
    client = FakeMail() if kind == "mail" else FakeRedis()
    factory = Mock(return_value=client)
    if kind == "mail":
        candidate.probe.smtp_connect = factory
    else:
        candidate.probe.redis_connect = factory
    return client, factory


def health(candidate, kind):
    return candidate.probe.mail(3) if kind == "mail" else candidate.probe.redis(3, session=kind == "session")


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_health_uses_tls_auth_readonly_operations_and_owned_socket_cleanup(candidate, kind):
    client, factory = provider_client(candidate, kind)
    assert health(candidate, kind)
    assert client.closed and candidate.listener.call_count == 2
    kwargs = factory.call_args.kwargs
    assert kwargs["host"] == "127.0.0.1" and 0 < kwargs["timeout"] <= 3
    component = {"redis": "Redis", "session": "Session", "mail": "Mail"}[kind]
    assert candidate.probe.results[component].status == "PASS"
    assert SECRET not in repr(candidate.probe.results) + json.dumps(candidate.probe.results[component].to_dict())
    if kind == "mail":
        assert [call[0] for call in client.calls] == ["EHLO", "STARTTLS", "EHLO", "AUTH", "QUIT"]
        assert client.calls[3][1] == candidate.context.environment["SMTP_USERNAME"]
    else:
        assert {call[0] for call in client.calls} == {"AUTH", "SELECT", "PING", "GET"}
        assert client.calls[0][1] == ("sbom_session" if kind == "session" else "sbom_runtime")
        assert client.calls[1] == ("SELECT", "1" if kind == "session" else "0")
        assert len([call for call in client.calls if call[0] == "GET"]) == (2 if kind == "session" else 1)


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
@pytest.mark.parametrize("failure", ["foreign", "access-denied", "missing-forwarder"])
def test_provider_health_never_connects_when_host_listener_ownership_is_unverified(candidate, kind, failure):
    _, factory = provider_client(candidate, kind)
    if failure == "foreign":
        candidate.listener.side_effect, candidate.listener.return_value = None, frozenset({999})
    elif failure == "access-denied":
        candidate.listener.side_effect = readiness.ReadinessError("LISTENER_ENUMERATION_UNVERIFIED", 5, 678)
    else:
        candidate.probe.context = replace(candidate.context, provider_processes={})
    with pytest.raises(readiness.ReadinessError) as error:
        health(candidate, kind)
    factory.assert_not_called()
    if failure == "access-denied":
        assert error.value.winerror == 5 and error.value.probe_pid == 678
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_absence_is_pending_without_creating_a_client(candidate, kind):
    _, factory = provider_client(candidate, kind)
    candidate.listener.side_effect, candidate.listener.return_value = None, frozenset()
    assert health(candidate, kind) is False
    factory.assert_not_called()


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_credential_failure_is_redacted_and_does_not_send_data(candidate, kind):
    client, _ = provider_client(candidate, kind)
    client.auth_ok = False
    with pytest.raises(readiness.ReadinessError, match="^(MAIL|REDIS)_AUTHENTICATION_FAILED$"):
        health(candidate, kind)
    assert client.closed and candidate.listener.call_count == 2
    assert not any(call[0] in {"SET", "DEL", "EVAL", "MAIL", "RCPT", "DATA"} for call in client.calls)


def test_session_acl_must_deny_a_real_get_outside_exact_prefix(candidate):
    client, _ = provider_client(candidate, "session")
    client.allow_foreign = True
    with pytest.raises(readiness.ReadinessError, match="^REDIS_SESSION_ACL_UNVERIFIED$"):
        health(candidate, "session")
    assert client.closed


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_process_birth_race_is_detected_even_after_successful_protocol_exchange(candidate, kind):
    client, _ = provider_client(candidate, kind)
    original = client.close
    def close():
        original()
        candidate.launcher.process_info.side_effect = lambda pid: {**candidate.identity(pid), "birth": "reused"}
    client.close = close
    with pytest.raises(readiness.ReadinessError, match="^PROCESS_IDENTITY_UNVERIFIED$"):
        health(candidate, kind)
    assert client.closed


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_cleanup_error_cannot_claim_ready(candidate, kind):
    client, _ = provider_client(candidate, kind)
    client.close = Mock(side_effect=KeyboardInterrupt)
    with pytest.raises(readiness.ReadinessError, match="^(MAIL|REDIS)_CLEANUP_UNCONFIRMED$"):
        health(candidate, kind)
    assert candidate.listener.call_count == 2


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_transport_failure_is_pending_redacted_and_postchecked(candidate, kind):
    _, factory = provider_client(candidate, kind)
    failure = OSError(SECRET)
    failure.winerror = 10061
    factory.side_effect = failure
    assert health(candidate, kind) is False
    component = {"redis": "Redis", "session": "Session", "mail": "Mail"}[kind]
    assert candidate.probe.results[component].winerror == 10061 and candidate.listener.call_count == 2
    assert SECRET not in repr(candidate.probe.results)


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_ca_drift_after_connection_blocks_readiness(candidate, kind):
    client, _ = provider_client(candidate, kind)
    original = client.close
    def close():
        original()
        candidate.context.tls.ca_bundle.write_bytes(b"changed-synthetic-ca")
    client.close = close
    with pytest.raises(readiness.ReadinessError, match="^TLS_MATERIAL_UNVERIFIED$"):
        health(candidate, kind)


def test_mail_starttls_is_mandatory_and_authentication_never_precedes_it(candidate):
    client, _ = provider_client(candidate, "mail")
    client.starttls_supported = False
    with pytest.raises(readiness.ReadinessError, match="^MAIL_TLS_REQUIRED$"):
        health(candidate, "mail")
    assert [call[0] for call in client.calls] == ["EHLO", "QUIT"] and client.closed


def test_redis_plaintext_factory_cannot_authenticate(candidate):
    client, _ = provider_client(candidate, "redis")
    client.tls_verified = False
    with pytest.raises(readiness.ReadinessError, match="^TLS_VERIFICATION_REQUIRED$"):
        health(candidate, "redis")
    assert client.calls == [] and client.closed


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_certificate_failure_is_redacted_and_owned_listener_is_postchecked(candidate, kind):
    _, factory = provider_client(candidate, kind)
    factory.side_effect = ssl.SSLError(SECRET)
    with pytest.raises(readiness.ReadinessError, match="^TLS_VERIFICATION_REQUIRED$"):
        health(candidate, kind)
    assert candidate.listener.call_count == 2 and SECRET not in repr(candidate.probe.results)


def test_mail_quit_failure_still_closes_only_original_probe_socket(candidate):
    client, _ = provider_client(candidate, "mail")
    client.quit = Mock(side_effect=KeyboardInterrupt)
    with pytest.raises(readiness.ReadinessError, match="^MAIL_CLEANUP_UNCONFIRMED$"):
        health(candidate, "mail")
    assert client.closed and candidate.listener.call_count == 2


class WireSocket:
    def __init__(self, responses):
        self.responses, self.sent, self.closed, self.timeouts = list(responses), [], False, []
    def settimeout(self, timeout):
        assert 0 < timeout <= 3
        self.timeouts.append(timeout)
    def sendall(self, raw):
        self.sent.append(raw)
    def recv(self, maximum):
        assert maximum <= 4096
        return self.responses.pop(0) if self.responses else b""
    def close(self):
        self.closed = True


def wire_context(raw):
    def wrap(sock, *, server_hostname):
        assert sock is raw and server_hostname == "127.0.0.1"
        return sock
    return SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True, keylog_filename=None, wrap_socket=Mock(side_effect=wrap))


def test_concrete_resp_wire_uses_tls_numeric_hostname_and_only_fixed_readonly_commands(candidate, monkeypatch):
    raw = WireSocket([b"+OK\r\n", b"+OK\r\n", b"+PONG\r\n", b"$-1\r\n", b"-NOPERM " + SECRET.encode() + b"\r\n"])
    context = wire_context(raw)
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    client = readiness._RedisProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["redis"], timeout=2, context=context)
    assert client.command("AUTH", "sbom_session", SECRET) == b"OK"
    assert client.command("SELECT", "1") == b"OK" and client.command("PING") == b"PONG"
    assert client.command("GET", "own-prefix:__sbom_readiness__") is None
    with pytest.raises(readiness.RedisReplyError) as error:
        client.command("GET", "outside-prefix")
    assert error.value.permission_denied and SECRET not in str(error.value)
    before = list(raw.sent)
    with pytest.raises(readiness.ReadinessError):
        client.command("SET", "forbidden", "value")
    assert raw.sent == before
    client.close()
    assert raw.closed and context.wrap_socket.call_count == 1


@pytest.mark.parametrize("response", [b"*2\r\n", b"$99999\r\n", b"$2\r\nx!xx", b"+" + b"x" * 4097 + b"\r\n"])
def test_concrete_resp_parser_refuses_oversized_unexpected_or_malformed_payload(candidate, monkeypatch, response):
    raw = WireSocket([response])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    client = readiness._RedisProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["redis"], timeout=2, context=wire_context(raw))
    with pytest.raises(readiness.ReadinessError):
        client.command("PING")
    client.close()
    assert raw.closed


def test_concrete_resp_tls_failure_closes_original_raw_socket_without_auth(candidate, monkeypatch):
    raw = WireSocket([])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    context = wire_context(raw)
    context.wrap_socket.side_effect = ssl.SSLError(SECRET)
    with pytest.raises(ssl.SSLError):
        readiness._RedisProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["redis"], timeout=2, context=context)
    assert raw.closed and raw.sent == []


def test_concrete_resp_constructor_reports_repeated_cancellation_during_socket_cleanup(candidate, monkeypatch):
    raw = WireSocket([])
    raw.close = Mock(side_effect=KeyboardInterrupt)
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    context = wire_context(raw)
    context.wrap_socket.side_effect = ssl.SSLError(SECRET)
    with pytest.raises(readiness.ReadinessError, match="^REDIS_CLEANUP_UNCONFIRMED$"):
        readiness._RedisProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["redis"], timeout=2, context=context)
    raw.close.assert_called_once()
    assert raw.sent == []


def test_concrete_smtp_wire_requires_tls_reissues_ehlo_and_never_sends_a_message(candidate, monkeypatch):
    raw = WireSocket([b"220 ready\r\n", b"250-mailpit\r\n250 STARTTLS\r\n", b"220 encrypt now\r\n",
                      b"250-mailpit\r\n250 AUTH PLAIN LOGIN\r\n", b"235 ok\r\n", b"221 bye\r\n"])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    client = readiness._SmtpProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["smtp"], timeout=2)
    assert client.ehlo() == 250 and client.has_extn("starttls")
    assert client.starttls(context=wire_context(raw)) == 220 and client.tls_verified
    assert client.ehlo() == 250 and client.login("synthetic-user", SECRET)
    client.quit()
    client.close()
    assert raw.closed and [line.split(b" ", 1)[0].strip() for line in raw.sent] == [b"EHLO", b"STARTTLS", b"EHLO", b"AUTH", b"QUIT"]


def test_concrete_smtp_never_sends_credentials_before_starttls(candidate, monkeypatch):
    raw = WireSocket([b"220 ready\r\n"])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    client = readiness._SmtpProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["smtp"], timeout=2)
    with pytest.raises(readiness.ReadinessError, match="^MAIL_AUTHENTICATION_FAILED$"):
        client.login("synthetic-user", SECRET)
    assert raw.sent == []
    client.close()


@pytest.mark.parametrize("response", [b"999 bad\r\n", b"220-wrong\r\n250 changed\r\n", b"220-" + b"x" * 4097 + b"\r\n"])
def test_concrete_smtp_parser_refuses_malformed_banner_and_closes_socket(candidate, monkeypatch, response):
    raw = WireSocket([response])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    with pytest.raises(readiness.ReadinessError):
        readiness._SmtpProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["smtp"], timeout=2)
    assert raw.closed


def test_concrete_smtp_constructor_reports_repeated_cancellation_during_cleanup(candidate, monkeypatch):
    raw = WireSocket([b"999 wrong\r\n"])
    raw.close = Mock(side_effect=KeyboardInterrupt)
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    with pytest.raises(readiness.ReadinessError, match="^MAIL_CLEANUP_UNCONFIRMED$"):
        readiness._SmtpProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["smtp"], timeout=2)
    raw.close.assert_called_once()
    assert raw.sent == []


@pytest.mark.parametrize("value", [1, SECRET, {"approved": True}, None])
def test_redis_session_selector_requires_actual_boolean_without_authentication(candidate, value):
    _, factory = provider_client(candidate, "redis")
    with pytest.raises(readiness.ReadinessError, match="^REDIS_TARGET_UNVERIFIED$"):
        candidate.probe.redis(3, session=value)
    factory.assert_not_called()


@pytest.mark.parametrize("wrong,readonly,revision,code", [(True, True, None, "DATABASE_TARGET_UNVERIFIED"),
    (False, False, None, "DATABASE_NOT_READONLY"), (False, True, "wrong_revision", "DATABASE_SCHEMA_NOT_READY")])
def test_database_failures_preserve_rollback_and_close(candidate, wrong, readonly, revision, code):
    calls = database(candidate, wrong_target=wrong, readonly=readonly, revision=revision)
    with pytest.raises(readiness.ReadinessError, match="^" + code + "$"):
        candidate.probe.database(3)
    assert calls[-2:] == ["ROLLBACK", "CLOSE"]


def windows_api(rows_by_family, *, error=None, malformed=False):
    def api(buffer, size, ordered, family, kind, reserved):
        assert ordered is False and kind == 3 and reserved == 0
        if error:
            return error
        row_type = readiness._Tcp4 if family == 2 else readiness._Tcp6
        class Table(ctypes.Structure):
            _fields_ = [("count", ctypes.c_uint32), ("rows", row_type * 1)]
        rows = rows_by_family.get(family, ())
        raw = len(rows).to_bytes(4, sys.byteorder) + b"\0" * (Table.rows.offset - 4) + b"".join(bytes(row) for row in rows)
        pointer = ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32))
        if buffer is None:
            pointer.contents.value = len(raw)
            return 122
        pointer.contents.value = len(raw)
        ctypes.memmove(buffer, raw, len(raw))
        if malformed:
            ctypes.memmove(buffer, (999999).to_bytes(4, sys.byteorder), 4)
        return 0
    return api


def test_windows_real_ctypes_buffer_paths_handle_both_families_wildcards_and_ports():
    v4 = readiness._Tcp4(state=2, local_addr=0, local_port=socket.htons(24443), pid=123)
    v6 = readiness._Tcp6(local_port=socket.htons(24443), state=2, pid=456)
    assert readiness._windows_listener_pids("127.0.0.1", 24443, api=windows_api({2: (v4,), 23: (v6,)})) == {123, 456}


@pytest.mark.parametrize("error", [5, 50])
def test_windows_api_uses_returned_safe_error_code_not_get_last_error(error):
    with pytest.raises(readiness.ReadinessError) as caught:
        readiness._windows_listener_pids("127.0.0.1", 24443, api=windows_api({}, error=error))
    assert caught.value.code == "LISTENER_ENUMERATION_UNVERIFIED" and caught.value.winerror == error


def test_windows_malformed_or_growing_tables_never_guess_ownership():
    with pytest.raises(readiness.ReadinessError):
        readiness._windows_listener_pids("127.0.0.1", 24443, api=windows_api({}, malformed=True))
    def growing(buffer, size, *args):
        ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32)).contents.value = 32
        return 122
    with pytest.raises(readiness.ReadinessError) as caught:
        readiness._windows_listener_pids("127.0.0.1", 24443, api=growing)
    assert caught.value.winerror == 122


@pytest.mark.parametrize("uncovered", [False, True])
def test_linux_proc_adapter_requires_every_listener_inode_and_same_network_namespace(tmp_path, monkeypatch, uncovered):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "123/fd").mkdir(parents=True)
    (proc / "123/fd/7").write_text("fixture")
    header = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    row = "0: 0100007F:5F7B 00000000:0000 0A 0:0 0:0 0 0 0 777\n"
    if uncovered:
        row += "1: 00000000:5F7B 00000000:0000 0A 0:0 0:0 0 0 0 888\n"
    (proc / "net/tcp").write_text(header + row)
    (proc / "net/tcp6").write_text(header)
    def readlink(path):
        return "socket:[777]" if Path(path).name == "7" and Path(path).parent.name == "fd" else "net:[same]"
    monkeypatch.setattr(os, "readlink", readlink)
    if uncovered:
        with pytest.raises(readiness.ReadinessError, match="^LISTENER_OWNER_UNVERIFIED$"):
            readiness._linux_listener_pids("127.0.0.1", 24443, {123}, proc_root=proc)
    else:
        assert readiness._linux_listener_pids("127.0.0.1", 24443, {123}, proc_root=proc) == {123}


def test_macos_requires_owned_bounded_probe_and_never_falls_back_to_shell():
    with pytest.raises(readiness.ReadinessError, match="^MACOS_LISTENER_ADAPTER_REQUIRED$"):
        readiness._mac_listener_pids("127.0.0.1", 24443, {123})
    runner = Mock(return_value=SimpleNamespace(returncode=0, stdout=b"p123\0\nf7\0n127.0.0.1:24443\0\n", stderr=b""))
    assert readiness._mac_listener_pids("127.0.0.1", 24443, {123}, probe=runner) == {123}
    command = runner.call_args.args[0]
    assert command[0] == "/usr/sbin/lsof" and "-Di" in command and "-nP" in command
    assert runner.call_args.kwargs == {"timeout": 2, "max_output": 262144}


def test_tls_parser_never_generates_material_and_malformed_files_are_redacted(candidate):
    before = {path: path.read_bytes() for path in (candidate.context.tls.certificate, candidate.context.tls.private_key, candidate.context.tls.ca_bundle)}
    with pytest.raises(readiness.ReadinessError, match="^TLS_MATERIAL_UNVERIFIED$") as caught:
        readiness.validate_tls_material(candidate.context.tls, candidate.context.descriptor.hostname)
    assert SECRET not in str(caught.value)
    assert all(path.read_bytes() == value for path, value in before.items())


def test_explicit_ssl_context_never_calls_ambient_keylog_helper(monkeypatch, tmp_path):
    forbidden = Mock(side_effect=AssertionError("Ambient TLS helper opened a key log"))
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    contexts = []
    class Context:
        def __init__(self, protocol):
            self.protocol, self.verify_flags, self.keylog_filename = protocol, 0, None
            contexts.append(self)
        def load_verify_locations(self, *, cafile):
            self.cafile = cafile
    monkeypatch.setattr(ssl, "SSLContext", Context)
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / SECRET))
    context = readiness._ssl_context(tmp_path / "approved-ca.pem")
    assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED and context.keylog_filename is None
    assert not (tmp_path / SECRET).exists()
    forbidden.assert_not_called()


def test_context_is_immutable_and_boolean_or_unknown_ownership_receipts_are_rejected(candidate):
    with pytest.raises(FrozenInstanceError):
        candidate.context.schema_revision = "changed"
    with pytest.raises(TypeError):
        candidate.context.environment["DATABASE_URL"] = SECRET
    with pytest.raises(readiness.ReadinessError, match="^READINESS_CONTEXT_INVALID$"):
        replace(candidate.context, provider_processes={"postgres": True})
    with pytest.raises(readiness.ReadinessError, match="^READINESS_RESULT_INVALID$"):
        readiness.ReadinessResult(SECRET, "PASS", "API_READY")


def test_hcl_uses_approved_https_origins_public_jwks_only_and_no_login(tmp_path, monkeypatch):
    candidate = prepared_context(tmp_path, monkeypatch, auth="hcl")
    monkeypatch.setattr(readiness, "_ssl_context", lambda *_: candidate.secure)
    def encoded(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    requests = []
    def request(scheme, host, port, path, timeout, context=None):
        requests.append(path)
        data = ({"issuer": "https://identity.example.test", "jwks_uri": "https://identity.example.test/keys", "code_challenge_methods_supported": ["S256"]}
                if "openid-configuration" in path else {"keys": [{"kty": "RSA", "alg": "RS256", "e": encoded(65537), "n": encoded((1 << 2047) + 1)}]})
        return readiness.HttpResponse(200, json.dumps(data).encode())
    candidate.probe.request = request
    assert candidate.probe.authentication(3)
    assert requests == ["/.well-known/openid-configuration", "/keys"]
    candidate.launcher.validate_secrets.assert_not_called()
    candidate.forbidden.assert_not_called()


@pytest.mark.parametrize("mismatch", [False, True])
@pytest.mark.parametrize("root_count", [1, 119, 512, 513])
def test_tls_full_policy_key_pair_and_hostname_are_validated_without_generating_keys(candidate, monkeypatch, mismatch, root_count):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import verification

    public = SimpleNamespace(public_bytes=lambda *_: b"leaf-public")
    leaf = SimpleNamespace(public_key=lambda: public)
    ca = SimpleNamespace(extensions=SimpleNamespace(get_extension_for_class=lambda requested: SimpleNamespace(value=SimpleNamespace(ca=True))))
    private = SimpleNamespace(public_key=lambda: SimpleNamespace(public_bytes=lambda *_: b"different" if mismatch else b"leaf-public"))
    monkeypatch.setattr(x509, "load_pem_x509_certificates", Mock(side_effect=[[leaf], [ca] * root_count]))
    monkeypatch.setattr(serialization, "load_pem_private_key", Mock(return_value=private))
    no_generation = Mock(side_effect=AssertionError("Readiness generated a private key/certificate"))
    monkeypatch.setattr(rsa, "generate_private_key", no_generation)
    monkeypatch.setattr(x509, "random_serial_number", no_generation)
    verified = []
    class Policy:
        def store(self, authority):
            assert authority == (ca,) * root_count
            return self
        def time(self, instant):
            assert instant.tzinfo is not None
            return self
        def build_server_verifier(self, name):
            assert name.value == candidate.context.descriptor.hostname
            return SimpleNamespace(verify=lambda certificate, chain: verified.append((certificate, chain)))
    monkeypatch.setattr(verification, "Store", lambda authorities: tuple(authorities))
    monkeypatch.setattr(verification, "PolicyBuilder", Policy)
    monkeypatch.setattr(readiness, "_ssl_context", lambda ca_path: candidate.secure)
    if mismatch or root_count > 512:
        with pytest.raises(readiness.ReadinessError, match="^TLS_MATERIAL_UNVERIFIED$"):
            readiness.validate_tls_material(candidate.context.tls, candidate.context.descriptor.hostname)
        assert verified == []
    else:
        assert readiness.validate_tls_material(candidate.context.tls, candidate.context.descriptor.hostname) is candidate.secure
        assert verified == [(leaf, [])]
    no_generation.assert_not_called()


def test_tls_trust_bundle_remains_byte_bounded_at_one_mebibyte(candidate):
    candidate.context.tls.ca_bundle.write_bytes(b"x" * 1048577)
    with pytest.raises(readiness.ReadinessError, match="^TLS_MATERIAL_UNVERIFIED$"):
        readiness.validate_tls_material(candidate.context.tls, candidate.context.descriptor.hostname)


@pytest.mark.parametrize("kind", ["redis", "session", "mail"])
def test_provider_insecure_context_is_refused_before_client_or_auth(candidate, kind):
    _, factory = provider_client(candidate, kind)
    candidate.secure.verify_mode = ssl.CERT_NONE
    with pytest.raises(readiness.ReadinessError, match="^TLS_VERIFICATION_REQUIRED$"):
        health(candidate, kind)
    factory.assert_not_called()


def test_mail_false_starttls_acknowledgement_cannot_unlock_auth(candidate):
    client, _ = provider_client(candidate, "mail")
    client.starttls = Mock(return_value=220)
    with pytest.raises(readiness.ReadinessError, match="^MAIL_TLS_REQUIRED$"):
        health(candidate, "mail")
    assert not any(call[0] == "AUTH" for call in client.calls) and client.closed


def test_resp_partial_trickle_is_stopped_by_absolute_operation_deadline(candidate, monkeypatch):
    instant = [0.0]
    raw = WireSocket([])
    def receive(maximum):
        instant[0] += 1
        return b"+"
    raw.recv = receive
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: raw)
    client = readiness._RedisProbe(host="127.0.0.1", port=candidate.context.descriptor.ports["redis"],
                                   timeout=2, context=wire_context(raw), clock=lambda: instant[0])
    with pytest.raises(TimeoutError):
        client.command("PING")
    assert instant[0] == 2
    client.close()
    assert raw.closed


def test_native_authentication_only_validates_existing_prerequisites_and_never_enrolls(candidate):
    assert candidate.probe.authentication(3)
    candidate.launcher.validate_secrets.assert_called_once_with(dict(candidate.context.environment))
    assert candidate.requests == [] and candidate.connect.call_count == 0
    assert candidate.probe.results["Authentication"].code == "AUTHENTICATION_READY"


def test_https_transport_binds_loopback_but_uses_expected_sni_without_proxy_or_redirect(monkeypatch):
    events = []
    raw = SimpleNamespace(close=lambda: events.append("raw-close"))
    wrapped = object()
    class Connection:
        def __init__(self, host, port, *, timeout, context):
            self.sock = None
            events.append(("connection", host, port, timeout))
        def request(self, method, path, *, headers):
            assert self.sock is wrapped and method == "GET" and "Authorization" not in headers
            events.append(("request", path))
        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda size: b"fixture")
        def close(self):
            events.append("connection-close")
    def wrap(sock, *, server_hostname):
        assert sock is raw and server_hostname == "approved.localhost"
        events.append(("SNI", server_hostname))
        return wrapped
    context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED, keylog_filename=None, wrap_socket=wrap)
    connect = Mock(return_value=raw)
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(readiness.http.client, "HTTPSConnection", Connection)
    result = readiness.http_request("https", "approved.localhost", 24443, "/", 1, context, address="127.0.0.1")
    assert result.status == 200 and result.body == b"fixture"
    connect.assert_called_once_with(("127.0.0.1", 24443), timeout=1)
    assert events[-1] == "connection-close"


def test_insecure_tls_context_is_refused_before_any_connection(candidate):
    context = SimpleNamespace(check_hostname=False, verify_mode=ssl.CERT_NONE, keylog_filename=None)
    with pytest.raises(readiness.ReadinessError, match="^TLS_VERIFICATION_REQUIRED$"):
        readiness.http_request("https", "approved.localhost", 24443, "/", 1, context, address="127.0.0.1")
    candidate.forbidden.assert_not_called()


@pytest.mark.parametrize("mode", ["finished", "timeout", "force", "unknown", "reused", "overflow"])
def test_owned_macos_probe_has_pinned_executable_sanitized_env_and_verified_cleanup(tmp_path, monkeypatch, mode):
    anchor = tmp_path.resolve() / "owned tool fixture"
    if sys.platform == "win32":
        dev_instance_storage._windows_create(anchor)
    else:
        anchor.mkdir(mode=0o700)
    tool = anchor / "lsof"
    dev_private.create_private_file(tool, b"synthetic lsof executable; never run")
    if sys.platform != "win32":
        tool.chmod(0o700)
    events = []
    class Child:
        pid = 702
        def __init__(self):
            self.returncode = 0 if mode in {"finished", "overflow"} else None
            self.stdout = io.BytesIO(b"x" * 100 if mode == "overflow" else b"p123\0\nf7\0n127.0.0.1:24443\0\n")
            self.stderr = io.BytesIO()
        def poll(self):
            return self.returncode
        def terminate(self):
            events.append("terminate")
            if mode != "force":
                self.returncode = 0
        def kill(self):
            events.append("kill")
            self.returncode = 1
        def wait(self, timeout):
            assert timeout == 2
            if self.returncode is None:
                raise subprocess.TimeoutExpired("safe fixture command", timeout)
            return self.returncode
    child = Child()
    def popen(argv, **options):
        assert argv[0] == str(tool) and options["start_new_session"] is True and options["close_fds"] is True
        assert options["env"] == {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
        assert options["stdin"] == subprocess.DEVNULL and options["stdout"] == options["stderr"] == subprocess.PIPE
        assert options["bufsize"] == 0
        return child
    count, now = [0], [0.0]
    def process_info(pid):
        assert pid == child.pid
        count[0] += 1
        if mode == "unknown":
            raise PermissionError(SECRET)
        return {"pid": pid, "birth": "reused" if mode == "reused" and count[0] > 1 else "original", "exe": str(tool)}
    def advance(seconds):
        now[0] += seconds
    options = dict(process_info=process_info, matches=lambda old, current: old == current, popen=popen,
                   tool_path=tool, clock=lambda: now[0], sleep=advance, timeout=0.05,
                   max_output=16 if mode == "overflow" else 262144)
    argv = (str(tool), "-nP", "-Di", "+w", "-a", "-iTCP:24443", "-sTCP:LISTEN", "-F0pfn")
    if mode == "finished":
        result = readiness.owned_lsof_probe(argv, **options)
        assert result.returncode == 0 and result.stdout.startswith(b"p123\0")
        assert not events
    else:
        with pytest.raises(readiness.ReadinessError) as caught:
            readiness.owned_lsof_probe(argv, **options)
        assert SECRET not in str(caught.value)
        if mode in {"unknown", "reused"}:
            assert caught.value.code == "LISTENER_PROBE_CLEANUP_UNCONFIRMED" and caught.value.probe_pid == child.pid
            assert not events
        elif mode == "timeout":
            assert events == ["terminate"]
        elif mode == "force":
            assert events == ["terminate", "kill"] and count[0] >= 3
        else:
            assert caught.value.code == "LISTENER_ENUMERATION_UNVERIFIED" and not events
    assert child.stdout.closed and child.stderr.closed
