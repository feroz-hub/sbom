"""Read-only diagnostic dispatch and probe regressions; use --noconftest."""

from __future__ import annotations

import ast
import base64
import builtins
import json
import os
import ssl
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_config, dev_diagnostics

SECRET = "fixture-diagnostic-secret-never-log"
DATABASE_URL = f"postgresql+psycopg://postgres:{SECRET}@127.0.0.1:5432/sbom_analyser_dev"


def prepared_plan(**saved):
    return dev_config.resolve_configuration(
        profile="legacy",
        inherited={},
        saved={"DATABASE_URL": DATABASE_URL, **saved},
        root="C:/fixture/repository",
        platform="win32",
    )


def result(status="PASS", component="Fixture", code="FIXTURE_RESULT"):
    return dev_diagnostics.DiagnosticResult(component, status, code, "Safe corrective guidance.")


@pytest.mark.parametrize(
    "arguments",
    [
        ["diagnose"],
        ["doctor"],
        ["--check"],
        ["setup", "--check"],
        ["start", "--check"],
        ["stop", "--check"],
        ["restart", "--check"],
        ["status", "--check"],
        ["logs", "--check"],
    ],
)
def test_diagnostic_forms_dispatch_before_every_mutable_or_prerequisite_path(monkeypatch, arguments):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", *arguments])
    forbidden = Mock(side_effect=AssertionError("diagnostic dispatch entered mutable launcher path"))
    for name in (
        "validate_repository_layout",
        "validate_python_version",
        "venv_python",
        "ensure_virtualenv",
        "pin_legacy_configuration",
        "setup_application",
        "start_application",
        "stop_application",
        "Runtime",
        "check_profile_ownership",
        "resolve_profile",
        "control_profile",
        "ensure_dependencies",
        "ensure_frontend",
        "prepare_managed_legacy",
        "configure_local_database",
        "ensure_database",
        "run_migrations",
        "generate_keys",
        "write_config",
        "acquire_beat_lock",
        "atomic_json",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    checked = Mock(return_value=1)
    monkeypatch.setattr(dev, "diagnose", checked)
    assert dev.main() == 1
    checked.assert_called_once()
    forbidden.assert_not_called()


@pytest.mark.parametrize("command", [["diagnose"], ["doctor"], ["setup", "--check"], ["restart", "--check"]])
@pytest.mark.parametrize(
    "mutation",
    [
        ["--provision-greenfield"],
        ["--initialize-database"],
        ["--migrate"],
        ["--frontend-build"],
        ["--confirm-database", SECRET],
    ],
)
def test_diagnostic_mutation_flags_are_usage_errors_before_any_action(monkeypatch, capsys, command, mutation):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", *command, *mutation])
    forbidden = Mock(side_effect=AssertionError("mixed diagnostic invocation attempted an action"))
    monkeypatch.setattr(dev, "diagnose", forbidden)
    monkeypatch.setattr(dev, "setup_application", forbidden)
    monkeypatch.setattr(dev, "Runtime", forbidden)
    assert dev.cli() == 2
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    forbidden.assert_not_called()


@pytest.mark.parametrize("host_version", [(3, 9, 6), (3, 10, 14)])
def test_diagnostic_dispatch_does_not_handoff_or_create_a_venv_for_old_host(monkeypatch, host_version):
    monkeypatch.setattr(dev.sys, "version_info", host_version)
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "diagnose"])
    forbidden = Mock(side_effect=AssertionError("diagnostics attempted venv handoff/preparation"))
    monkeypatch.setattr(dev, "ensure_virtualenv", forbidden)
    monkeypatch.setattr(dev, "venv_python", forbidden)
    monkeypatch.setattr(dev, "diagnose", lambda args: 1)
    assert dev.main() == 1
    forbidden.assert_not_called()


def test_doctor_is_one_deprecated_alias_with_identical_result(monkeypatch, capsys):
    args = dev.parse_args(["doctor"])
    checked = Mock(return_value=1)
    monkeypatch.setattr(dev, "diagnose", checked)
    assert dev.doctor(args) == 1
    checked.assert_called_once_with(args)
    output = capsys.readouterr()
    assert output.err.lower().count("deprecated") == 1
    assert "diagnose" in output.err
    assert not output.out


def test_primary_diagnostic_help_preserves_compatibility_alias(capsys):
    with pytest.raises(SystemExit) as caught:
        dev.parse_args(["--help"])
    assert caught.value.code == 0
    output = capsys.readouterr().out
    assert "diagnose" in output
    assert "doctor" in output
    assert "--check" in output


@pytest.mark.parametrize("status", ["PASS", "WARN", "SKIPPED", "FAIL", "BLOCKED"])
def test_diagnostic_exit_policy_and_report_immutability(status):
    item = result(status)
    report = dev_diagnostics.DiagnosticReport((item,))
    assert report.exit_code == (1 if status in {"FAIL", "BLOCKED"} else 0)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        item.status = "PASS"
    with pytest.raises((FrozenInstanceError, AttributeError)):
        report.results = ()


def test_diagnose_wrapper_prints_results_and_propagates_report_exit(monkeypatch, capsys):
    args = dev.parse_args(["diagnose"])
    report = dev_diagnostics.DiagnosticReport((result("FAIL", "Database", "DATABASE_UNAVAILABLE"), result("WARN")))
    checked = Mock(return_value=report)
    monkeypatch.setattr(dev_diagnostics, "run_checks", checked)
    assert dev.diagnose(args) == 1
    checked.assert_called_once()
    assert checked.call_args.args[0] is args
    assert checked.call_args.args[1] is dev
    output = capsys.readouterr()
    assert "DATABASE_UNAVAILABLE" in output.out
    assert "FAIL" in output.out
    assert "WARN" in output.out
    assert SECRET not in output.out + output.err


def test_native_diagnostic_help_does_not_create_python_bytecode(tmp_path):
    launcher = Path(dev.__file__).resolve()
    fixture = tmp_path / "checkout"
    scripts = fixture / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "dev.py").write_bytes(launcher.read_bytes())
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    completed = subprocess.run(
        [sys.executable, "-S", str(scripts / "dev.py"), "--help"],
        cwd=fixture,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0
    assert not list(fixture.rglob("*.pyc"))
    assert not list(fixture.rglob("__pycache__"))


@pytest.mark.parametrize("arguments", [["diagnose"], ["doctor"], ["setup", "--check"]])
def test_native_diagnostic_imports_create_no_cache_or_runtime_files(tmp_path, arguments):
    fixture = tmp_path / "checkout"
    scripts = fixture / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "dev.py").write_bytes(Path(dev.__file__).read_bytes())
    (scripts / "dev_diagnostics.py").write_text(
        "import sys\nfrom types import SimpleNamespace\n"
        "def run_checks(args, launcher):\n"
        "    assert sys.dont_write_bytecode\n"
        "    return SimpleNamespace(results=(), exit_code=0)\n",
        encoding="utf-8",
    )
    before = {path.relative_to(fixture): path.read_bytes() for path in fixture.rglob("*") if path.is_file()}
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-S", str(scripts / "dev.py"), *arguments],
        cwd=fixture,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    after = {path.relative_to(fixture): path.read_bytes() for path in fixture.rglob("*") if path.is_file()}
    assert after == before


@pytest.mark.parametrize("condition", ["tree-unverified", "access-denied", "pid-reused", "executable-changed"])
def test_runtime_uncertainty_never_adopts_signals_or_rewrites_records(monkeypatch, condition):
    record = {"pid": 4321, "birth": "fixture-birth", "exe": "C:/fixture/python.exe", "members": []}
    if condition == "tree-unverified":
        record["tree_unverified"] = True
    state = {"profile": "legacy", "ready": False, "instance": "fixture-instance", "services": {"API": record}}
    before = json.dumps(state, sort_keys=True)
    current = {"pid": 4321, "birth": "fixture-birth", "exe": "C:/fixture/python.exe"}
    if condition == "pid-reused":
        current["birth"] = "different-birth"
    elif condition == "executable-changed":
        current["exe"] = "C:/unrelated/process.exe"
    probe = Mock(return_value=current)
    if condition == "access-denied":
        probe.side_effect = dev.OwnershipError("OpenProcess winerror=5 " + SECRET)
    monkeypatch.setattr(dev, "process_info", probe)
    forbidden = Mock(side_effect=AssertionError("diagnostics adopted, signaled or rewrote runtime state"))
    for name in (
        "Runtime",
        "atomic_json",
        "stop_application",
        "stop_processes",
        "celery_control",
        "reject_foreign_workers",
    ):
        if hasattr(dev, name):
            monkeypatch.setattr(dev, name, forbidden)
    checks = dev_diagnostics._runtime_checks(prepared_plan(), state, dev)
    assert any(item.status in {"FAIL", "BLOCKED"} for item in checks)
    if condition in {"tree-unverified", "access-denied"}:
        assert any(item.status == "BLOCKED" for item in checks)
    assert SECRET not in repr(checks)
    assert json.dumps(state, sort_keys=True) == before
    forbidden.assert_not_called()


def test_stopped_runtime_is_reported_without_process_or_worker_rpc(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("stopped diagnostics attempted process control/RPC"))
    monkeypatch.setattr(dev, "process_info", forbidden)
    for name in ("celery_control", "reject_foreign_workers"):
        if hasattr(dev, name):
            monkeypatch.setattr(dev, name, forbidden)
    checks = dev_diagnostics._runtime_checks(prepared_plan(), None, dev)
    assert checks
    assert all(item.status in {"PASS", "WARN", "SKIPPED"} for item in checks)
    assert any(item.status == "SKIPPED" for item in checks)
    forbidden.assert_not_called()


class ReadOnlyConnection:
    """A fake PostgreSQL connection that refuses every mutating SQL statement."""

    def __init__(self, database="sbom_analyser_dev", fail_query=False):
        self.database = database
        self.fail_query = fail_query
        self.statements = []
        self.rollbacks = 0
        self.closed = False
        self.readonly = "on"
        self.users = 0
        self.admins = 0
        self.reservation = None
        self.revisions = [("103_tenant_admin_governance",)]

    def execute(self, statement, parameters=None):
        query = str(statement)
        self.statements.append(query)
        normalized = query.strip().lower()
        assert normalized.startswith(("select", "show")), "Diagnostic SQL was not read-only"
        if self.fail_query:
            raise RuntimeError("connection failed " + SECRET)
        if "transaction_read_only" in normalized:
            row = (self.readonly,)
        elif "current_database()" in normalized:
            row = (self.database,)
        elif "alembic_version" in normalized:
            row = ("103_tenant_admin_governance",)
        elif "native_platform_bootstrap" in normalized:
            row = (self.reservation,) if self.reservation is not None else None
        elif "platform_user_roles" in normalized:
            row = (self.admins,)
        else:
            row = (self.users,)
        return SimpleNamespace(
            fetchone=lambda: row, fetchall=lambda: self.revisions if "alembic_version" in normalized else []
        )

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

    def commit(self):
        pytest.fail("Diagnostics committed a database transaction")


def fake_database(monkeypatch, database="sbom_analyser_dev", fail_query=False):
    connection = ReadOnlyConnection(database, fail_query)
    connect = Mock(return_value=connection)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    monkeypatch.setattr(dev_diagnostics, "discover", lambda root: SimpleNamespace(head="103_tenant_admin_governance"))
    return connection, connect


def test_database_diagnostics_are_bounded_read_only_and_close_without_commit(monkeypatch):
    connection, connect = fake_database(monkeypatch)
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert checks
    kwargs = connect.call_args.kwargs
    assert "default_transaction_read_only=on" in kwargs["options"]
    assert "statement_timeout=" in kwargs["options"]
    assert "lock_timeout=" in kwargs["options"]
    assert 0 < kwargs["connect_timeout"] <= 5
    assert any("current_database()" in sql.lower() for sql in connection.statements)
    target_index = next(index for index, sql in enumerate(connection.statements) if "current_database()" in sql.lower())
    enrollment_index = next(index for index, sql in enumerate(connection.statements) if "iam_users" in sql.lower())
    assert target_index < enrollment_index
    assert connection.rollbacks >= 1
    assert connection.closed


def test_database_target_is_checked_before_enrollment_reads(monkeypatch):
    connection, _ = fake_database(monkeypatch, database="unapproved_fixture_target")
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.status in {"FAIL", "BLOCKED"} for item in checks)
    assert all("iam_users" not in sql.lower() and "bootstrap" not in sql.lower() for sql in connection.statements)
    assert connection.rollbacks >= 1
    assert connection.closed


def test_database_query_failure_is_redacted_and_still_rolls_back_and_closes(monkeypatch):
    connection, _ = fake_database(monkeypatch, fail_query=True)
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.status in {"FAIL", "BLOCKED"} for item in checks)
    assert SECRET not in repr(checks)
    assert connection.rollbacks >= 1
    assert connection.closed


def test_probe_failures_do_not_import_application_startup(monkeypatch):
    fake_database(monkeypatch, fail_query=True)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "app" or name.startswith("app."):
            pytest.fail("Diagnostics imported application configuration/startup")
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.status in {"FAIL", "BLOCKED"} for item in checks)


def test_database_server_must_confirm_readonly_before_any_target_or_enrollment_query(monkeypatch):
    connection, _ = fake_database(monkeypatch)
    connection.readonly = "off"
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.code == "DATABASE_NOT_READONLY" and item.status == "FAIL" for item in checks)
    assert not any("current_database()" in sql.lower() or "iam_users" in sql.lower() for sql in connection.statements)
    assert connection.rollbacks >= 1 and connection.closed


@pytest.mark.parametrize(
    "revisions",
    [
        [],
        [("102_public_membership_grant_analysis_uuid",)],
        [("103_tenant_admin_governance",), ("fixture_unreviewed_head",)],
    ],
)
def test_pending_missing_or_multiple_schema_markers_block_enrollment(monkeypatch, revisions):
    connection, _ = fake_database(monkeypatch)
    connection.revisions = revisions
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.code == "SCHEMA_NOT_CURRENT" and item.status == "FAIL" for item in checks)
    assert not any("iam_users" in sql.lower() or "bootstrap" in sql.lower() for sql in connection.statements)
    assert connection.rollbacks >= 1 and connection.closed


def test_runtime_snapshot_matches_registry_and_protects_unknown_components(tmp_path, monkeypatch):
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    record = {"pid": 4321, "birth": "fixture-birth", "exe": "fixture-python"}
    state = {"version": 1, "root": str(tmp_path.resolve()), "services": {"API": record}, "instance": "fixture-instance"}
    path = tmp_path / ".dev-runtime.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    before = path.read_bytes()
    assert dev_diagnostics._runtime_state(dev) == dev.Runtime(tmp_path).load() == state
    assert path.read_bytes() == before
    state["services"]["UNREVIEWED_COMPONENT"] = record
    path.write_text(json.dumps(state), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(dev_diagnostics.DiagnosticError):
        dev_diagnostics._runtime_state(dev)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("admins", "reservation", "code"),
    [
        (1, None, "ADMIN_READY"),
        (0, None, "ENROLLMENT_REQUIRED"),
        (0, "PENDING", "PENDING_ACTIVATION"),
        (0, "COMPLETED", "BOOTSTRAP_RESERVED"),
    ],
)
def test_enrollment_is_observed_without_creating_or_clearing_anything(monkeypatch, admins, reservation, code):
    connection, _ = fake_database(monkeypatch)
    connection.admins = admins
    connection.reservation = reservation
    checks = dev_diagnostics._database_checks(prepared_plan(), dev)
    assert any(item.component == "Enrollment" and item.code == code for item in checks)
    assert connection.reservation == reservation
    assert connection.admins == admins
    assert connection.closed


def test_hcl_first_user_gap_remains_an_explicit_approval_gate(monkeypatch):
    fake_database(monkeypatch)
    checks = dev_diagnostics._database_checks(prepared_plan(HCL_AUTH_ENABLED="true", NATIVE_AUTH_ENABLED="false"), dev)
    assert any(item.code == "HCL_ENROLLMENT_APPROVAL_REQUIRED" and item.status == "BLOCKED" for item in checks)


def test_diagnostics_aggregate_independent_failures_and_redact_provider_exceptions(monkeypatch):
    args = dev.parse_args(["diagnose", "--profile", "legacy", "--legacy-config", "managed"])
    monkeypatch.setattr(dev_diagnostics, "_runtime_state", lambda launcher: None)
    monkeypatch.setattr(
        dev_diagnostics,
        "_dependency_checks",
        lambda launcher: (result("FAIL", "Dependencies", "DEPENDENCY_FIXTURE_FAILED"),),
    )
    monkeypatch.setattr(dev_diagnostics, "_select_profile", lambda *args: ("legacy", "managed"))
    monkeypatch.setattr(dev_diagnostics, "_configuration", lambda *args: prepared_plan(NATIVE_AUTH_ENABLED="true"))
    monkeypatch.setattr(
        dev_diagnostics,
        "_certificate_check",
        lambda *args: (result("FAIL", "Certificates", "CERTIFICATE_FIXTURE_FAILED"), None),
    )
    monkeypatch.setattr(
        dev_diagnostics,
        "_authentication_checks",
        lambda *args: (result("FAIL", "Authentication", "AUTH_FIXTURE_FAILED"),),
    )
    monkeypatch.setattr(
        dev_diagnostics, "_database_checks", lambda *args: (result("FAIL", "Database", "DATABASE_FIXTURE_FAILED"),)
    )
    monkeypatch.setattr(dev_diagnostics, "_redis_ping", Mock(side_effect=RuntimeError(SECRET)))
    monkeypatch.setattr(dev_diagnostics, "_smtp_check", Mock(side_effect=RuntimeError(SECRET)))
    runtime = Mock(return_value=(result("SKIPPED", "Runtime", "RUNTIME_STOPPED"),))
    monkeypatch.setattr(dev_diagnostics, "_runtime_checks", runtime)
    report = dev_diagnostics.run_checks(args, dev)
    components = {item.component for item in report.results}
    assert {
        "Dependencies",
        "Certificates",
        "Authentication",
        "Database",
        "Redis",
        "Sessions",
        "Rate limits",
        "SMTP",
        "Runtime",
    } <= components
    assert report.exit_code == 1
    assert SECRET not in repr(report)
    runtime.assert_called_once()


def test_unreadable_runtime_blocks_target_resolution_without_repair(monkeypatch):
    args = dev.parse_args(["diagnose"])
    load = Mock(side_effect=dev.OwnershipError("malformed protected record " + SECRET))
    monkeypatch.setattr(dev_diagnostics, "_runtime_state", load)
    monkeypatch.setattr(dev_diagnostics, "_dependency_checks", lambda launcher: (result(),))
    forbidden = Mock(side_effect=AssertionError("uncertain runtime triggered resolution or repair"))
    monkeypatch.setattr(dev_diagnostics, "_configuration", forbidden)
    monkeypatch.setattr(dev, "atomic_json", forbidden)
    report = dev_diagnostics.run_checks(args, dev)
    assert report.exit_code == 1
    assert any(item.code == "RUNTIME_STATE_UNVERIFIED" and item.status == "BLOCKED" for item in report.results)
    assert SECRET not in repr(report)
    forbidden.assert_not_called()


@pytest.mark.parametrize("fail_ping", [False, True])
def test_redis_probe_only_pings_with_bounded_timeouts_and_closes(monkeypatch, fail_ping):
    import redis

    ping = Mock(return_value=True, side_effect=RuntimeError(SECRET) if fail_ping else None)
    close = Mock()
    factory = Mock(return_value=SimpleNamespace(ping=ping, close=close))
    monkeypatch.setattr(redis.Redis, "from_url", factory)
    if fail_ping:
        with pytest.raises(RuntimeError):
            dev_diagnostics._redis_ping("redis://127.0.0.1:6379/0")
    else:
        assert dev_diagnostics._redis_ping("redis://127.0.0.1:6379/0") is True
    assert factory.call_args.kwargs["socket_connect_timeout"] <= 3
    assert factory.call_args.kwargs["socket_timeout"] <= 3
    ping.assert_called_once_with()
    close.assert_called_once_with()


@pytest.mark.parametrize(
    "suffix", ["?ssl_cert_reqs=none", "?ssl_check_hostname=false", "?host=other.invalid", "#", "\n"]
)
def test_redis_options_cannot_weaken_tls_or_redirect_diagnostic_target(monkeypatch, suffix):
    import redis

    factory = Mock(side_effect=AssertionError("Unreviewed Redis URI reached a connection factory"))
    monkeypatch.setattr(redis.Redis, "from_url", factory)
    with pytest.raises(dev_diagnostics.DiagnosticError):
        dev_diagnostics._redis_ping("rediss://127.0.0.1:6379/0" + suffix)
    factory.assert_not_called()


def test_rediss_probe_requires_peer_certificate_and_hostname_verification(monkeypatch):
    import redis

    client = SimpleNamespace(ping=Mock(return_value=True), close=Mock())
    factory = Mock(return_value=client)
    monkeypatch.setattr(redis.Redis, "from_url", factory)
    assert dev_diagnostics._redis_ping("rediss://127.0.0.1:6379/0")
    assert factory.call_args.kwargs["ssl_cert_reqs"] in {"required", ssl.CERT_REQUIRED}
    assert factory.call_args.kwargs["ssl_check_hostname"] is True
    client.close.assert_called_once()


@pytest.mark.parametrize(
    "settings",
    [
        {"SMTP_USE_TLS": "true", "SMTP_USE_STARTTLS": "true"},
        {"SMTP_USE_TLS": "false", "SMTP_USE_STARTTLS": "false", "SMTP_PASSWORD": SECRET},
    ],
)
def test_smtp_invalid_tls_policy_is_refused_before_connection(monkeypatch, settings):
    factory = Mock(side_effect=AssertionError("Invalid SMTP TLS policy reached a server"))
    monkeypatch.setattr(dev_diagnostics.smtplib, "SMTP", factory)
    monkeypatch.setattr(dev_diagnostics.smtplib, "SMTP_SSL", factory)
    with pytest.raises(dev_diagnostics.DiagnosticError) as caught:
        dev_diagnostics._smtp_check({"SMTP_HOST": "127.0.0.1", "SMTP_PORT": "1025", **settings})
    assert SECRET not in str(caught.value)
    factory.assert_not_called()


def test_smtp_probe_validates_protocol_tls_without_authentication_or_mail(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("diagnostic SMTP attempted authentication or delivery"))
    client = SimpleNamespace(
        ehlo=Mock(return_value=(250, b"fixture")), starttls=Mock(), close=Mock(), login=forbidden, sendmail=forbidden
    )
    connect = Mock(return_value=client)
    monkeypatch.setattr(dev_diagnostics.smtplib, "SMTP", connect)
    dev_diagnostics._smtp_check({"SMTP_HOST": "127.0.0.1", "SMTP_PORT": "1025", "SMTP_USE_STARTTLS": "true"})
    assert connect.call_args.kwargs["timeout"] <= 3
    context = client.starttls.call_args.kwargs["context"]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert client.ehlo.call_count == 2
    client.close.assert_called_once_with()
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "override", [{"NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "wrong-client"}, {"HCL_IAM_ISSUER": "http://fixture-idp.invalid"}]
)
def test_hcl_configuration_errors_precede_network_discovery(monkeypatch, override):
    env = {**valid_hcl_environment(), **override}
    forbidden = Mock(side_effect=AssertionError("invalid HCL configuration reached network discovery"))
    monkeypatch.setattr(dev_diagnostics, "_json_get", forbidden)
    with pytest.raises(dev_diagnostics.DiagnosticError):
        dev_diagnostics._hcl_check(env, Path("fixture-root"))
    forbidden.assert_not_called()


@pytest.mark.parametrize("identity_changes", [False, True])
def test_owned_api_uses_inert_identifier_and_rechecks_identity_after_native_readiness(monkeypatch, identity_changes):
    record = {"pid": 4321, "birth": "fixture-birth", "exe": "C:/fixture/python.exe", "members": [], "port": 18000}
    state = {"profile": "legacy", "ready": False, "instance": "fixture-instance", "services": {"API": record}}
    calls = []

    def process_info(pid):
        assert pid == record["pid"]
        calls.append(pid)
        if identity_changes and len(calls) >= 3:
            return {**record, "birth": "unrelated-reused-birth"}
        return dict(record)

    requested = []

    def json_get(url, context=None):
        assert "/health" not in url, "The application /health handler can initialize repository state"
        requested.append(url)
        if url == "http://127.0.0.1:18000/":
            return {"service": "sbom-analyzer-api"}
        assert url == "http://127.0.0.1:18000/ready/iam"
        return {"ready": True}

    monkeypatch.setattr(dev, "process_info", process_info)
    monkeypatch.setattr(dev_diagnostics, "_json_get", json_get)
    checks = dev_diagnostics._runtime_checks(
        prepared_plan(NATIVE_AUTH_ENABLED="true", DEV_API_PORT="18000"), state, dev
    )
    assert requested == ["http://127.0.0.1:18000/", "http://127.0.0.1:18000/ready/iam"]
    assert len(calls) >= 3
    api_results = [item for item in checks if item.component == "API/IAM"]
    assert api_results
    if identity_changes:
        assert all(item.status != "PASS" for item in api_results)
        assert any(item.status in {"FAIL", "BLOCKED"} for item in api_results)
    else:
        assert any(item.code == "API_HEALTH_VERIFIED" and item.status == "PASS" for item in api_results)


def test_bounded_readonly_probe_times_out_without_leaving_a_test_thread_or_printing(capsys):
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    threads = []

    def probe():
        threads.append(threading.current_thread())
        entered.set()
        try:
            assert release.wait(5), "Test did not release its synthetic read-only probe"
            return "fixture-readonly-result"
        finally:
            completed.set()

    try:
        with pytest.raises(dev_diagnostics.DiagnosticError) as caught:
            dev_diagnostics._bounded(probe, timeout=0.01)
        assert caught.value.code == "PROBE_TIMEOUT"
        assert entered.wait(2)
    finally:
        release.set()
        assert completed.wait(2)
        for thread in threads:
            thread.join(timeout=2)
            assert not thread.is_alive()
    output = capsys.readouterr()
    assert not output.out and not output.err


def test_native_optional_defaults_match_inert_settings_literals_without_importing_application(monkeypatch):
    names = {
        "native_jwt_audience",
        "native_jwt_algorithm",
        "native_jwt_active_kid",
        "native_auth_rate_limit_enabled",
    }
    source = Path(dev.__file__).resolve().parents[1] / "app/settings.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    declared = {
        node.target.id: ast.literal_eval(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names
    }
    assert set(declared) == names
    plan = prepared_plan(
        AUTH_ENABLED="true",
        DEV_DEFAULT_TENANT="false",
        NEXT_PUBLIC_AUTH_ENABLED="true",
        NATIVE_AUTH_ENABLED="true",
        NATIVE_JWT_ISSUER="https://fixture.local/native",
        AUTH_SESSION_STORE="redis",
        NATIVE_SECURITY_OUTBOX_KEY="fixture-independent-outbox",
        AUTH_SESSION_ENCRYPTION_KEY="fixture-independent-session",
        NATIVE_SECURITY_OUTBOX_ENABLED="true",
        EMAIL_DELIVERY_ENABLED="true",
    )
    before = dict(plan.environment)
    validate = Mock()
    monkeypatch.setattr(dev, "validate_secrets", validate)
    forbidden = Mock(
        side_effect=AssertionError("Native diagnostic defaults attempted application import or key generation")
    )
    monkeypatch.setattr(dev, "generate_keys", forbidden)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "app" or name.startswith("app."):
            forbidden()
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        checks = dev_diagnostics._authentication_checks(plan, dev)
    validate.assert_called_once()
    validated = validate.call_args.args[0]
    for name, value in declared.items():
        key = name.upper()
        assert key not in before
        assert validated[key] == (str(value).lower() if isinstance(value, bool) else value)
    assert dict(plan.environment) == before
    assert any(item.code == "NATIVE_KEYS_CONFIGURATION_VALID" and item.status == "PASS" for item in checks)
    forbidden.assert_not_called()


def valid_hcl_environment():
    return {
        "AUTH_ENABLED": "true",
        "DEV_DEFAULT_TENANT": "false",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "true",
        "NATIVE_AUTH_ENABLED": "false",
        "HCL_IAM_ISSUER": "https://fixture-idp.invalid",
        "HCL_IAM_AUDIENCE": "fixture-api",
        "HCL_IAM_CLIENT_ID": "fixture-client",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "fixture-client",
        "NEXT_PUBLIC_HCL_IAM_ISSUER": "https://fixture-idp.invalid",
        "APP_ORIGIN": "https://localhost:13000",
        "NEXT_PUBLIC_HCL_IAM_REDIRECT_URI": "https://localhost:13000/auth/callback",
        "NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI": "https://localhost:13000/logged-out",
    }


def test_hcl_relative_ca_cannot_claim_frontend_and_backend_trust_from_different_files(monkeypatch, tmp_path):
    env = {**valid_hcl_environment(), "HCL_IAM_CA_BUNDLE": "certificates/provider-ca.pem"}
    fetch = Mock(side_effect=AssertionError("Ambiguous component CA paths reached the provider"))
    monkeypatch.setattr(dev_diagnostics, "_json_get", fetch)
    with pytest.raises(dev_diagnostics.DiagnosticError) as caught:
        dev_diagnostics._hcl_check(env, tmp_path)
    assert caught.value.code == "HCL_CA_PATH_AMBIGUOUS"
    fetch.assert_not_called()


def public_jwk(algorithm="RS256"):
    def encode(number):
        return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    # Public test numbers only: no private key, signing operation or key generation.
    return {
        "kty": "RSA",
        "kid": "fixture-public-only",
        "use": "sig",
        "alg": algorithm,
        "n": encode((1 << 2047) + 1),
        "e": encode(65537),
    }


def test_hcl_public_jwks_checks_verified_tls_context_without_claiming_login_or_registration(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa

    env = valid_hcl_environment()
    requested = []
    discovery = env["HCL_IAM_ISSUER"] + "/.well-known/openid-configuration"
    jwks_url = env["HCL_IAM_ISSUER"] + "/.well-known/jwks"

    def json_get(url, context=None):
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        requested.append(url)
        if url == discovery:
            return {"issuer": env["HCL_IAM_ISSUER"], "jwks_uri": jwks_url, "code_challenge_methods_supported": ["S256"]}
        assert url == jwks_url
        return {"keys": [public_jwk()]}

    forbidden = Mock(side_effect=AssertionError("HCL diagnostics generated a private signing key"))
    monkeypatch.setattr(rsa, "generate_private_key", forbidden)
    monkeypatch.setattr(dev_diagnostics, "_json_get", json_get)
    checks = dev_diagnostics._authentication_checks(prepared_plan(**env), dev)
    assert requested == [discovery, jwks_url]
    matching = [item for item in checks if item.code == "HCL_CONFIGURATION_DISCOVERY_VALID"]
    assert len(matching) == 1 and matching[0].status == "PASS"
    assert "registration" in matching[0].guidance and "not verified" in matching[0].guidance
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "http://fixture-idp.invalid/keys",
        "https://user:fixture-secret@fixture-idp.invalid/keys",
        "https://fixture-idp.invalid/keys?host=other.invalid",
    ],
)
@pytest.mark.parametrize("explicit", [False, True])
def test_hcl_untrusted_jwks_target_is_refused_before_fetching_it(monkeypatch, url, explicit):
    env = valid_hcl_environment()
    if explicit:
        env["HCL_IAM_JWKS_URL"] = url
    requested = []

    def json_get(target, context=None):
        requested.append(target)
        assert target != url, "An invalid JWKS target was fetched"
        return {"issuer": env["HCL_IAM_ISSUER"], "jwks_uri": url}

    monkeypatch.setattr(dev_diagnostics, "_json_get", json_get)
    with pytest.raises(dev_diagnostics.DiagnosticError):
        dev_diagnostics._hcl_check(env, Path("fixture-root"))
    assert len(requested) == (0 if explicit else 1)


@pytest.mark.parametrize("algorithm", ["HS256", "RS512", "none"])
def test_hcl_jwks_requires_an_accepted_rs256_public_key(monkeypatch, algorithm):
    env = valid_hcl_environment()

    def json_get(url, context=None):
        if url.endswith("openid-configuration"):
            return {"issuer": env["HCL_IAM_ISSUER"], "jwks_uri": env["HCL_IAM_ISSUER"] + "/keys"}
        return {"keys": [public_jwk(algorithm)]}

    monkeypatch.setattr(dev_diagnostics, "_json_get", json_get)
    with pytest.raises(dev_diagnostics.DiagnosticError) as caught:
        dev_diagnostics._hcl_check(env, Path("fixture-root"))
    assert caught.value.code == "HCL_JWKS_INVALID"


@pytest.mark.parametrize("name", ["fixture%2Fdevelopment", "fixture%20development", "fixture%25development"])
def test_database_connect_uses_literal_selected_name_without_uri_decoding(monkeypatch, name):
    connection, connect = fake_database(monkeypatch, database=name)
    plan = dev_config.resolve_configuration(
        profile="legacy",
        family="env",
        inherited={},
        saved={"DATABASE_URL": DATABASE_URL.replace("/sbom_analyser_dev", "/" + name)},
        root="C:/fixture/repository",
        platform="win32",
    )
    checks = dev_diagnostics._database_checks(plan, dev)
    assert not connect.call_args.args
    assert connect.call_args.kwargs["dbname"] == plan.database.name == name
    assert any(item.code == "DATABASE_TARGET_CONFIRMED" and item.status == "PASS" for item in checks)
    assert connection.closed
