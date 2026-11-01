"""Native operator resolution/status only; use --noconftest, never live resources."""

from __future__ import annotations

import base64
import builtins
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_config, dev_operator, dev_prepared

SECRET = "fixture-operator-secret-never-log"
URL = f"postgresql+psycopg://fixture:{SECRET}@127.0.0.1:5432/sbom_analyser_dev"
SOURCE = Path(dev.__file__).resolve().parents[1]


def native_values():
    return {
        "DATABASE_URL": URL,
        "DEV_REDIS_PROVIDER": "local",
        "APP_ENVIRONMENT": "development",
        "AUTH_ENABLED": "true",
        "NATIVE_AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "ENTRA_ENABLED": "false",
        "DEV_DEFAULT_TENANT": "false",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NATIVE_JWT_PRIVATE_KEY": "fixture-private-signing-material",
        "NATIVE_JWT_PUBLIC_KEY": "fixture-public-material",
        "NATIVE_JWT_ISSUER": "https://localhost:13000/native",
        "NATIVE_SECURITY_OUTBOX_KEY": base64.b64encode(b"o" * 32).decode(),
        "AUTH_SESSION_ENCRYPTION_KEY": base64.b64encode(b"s" * 32).decode(),
        "AUTH_SESSION_STORE": "redis",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "AUTH_SESSION_REDIS_URL": "redis://127.0.0.1:6379/1",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": "redis://127.0.0.1:6379/2",
        "NATIVE_USER_CREATION_ENABLED": "true",
        "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
        "EMAIL_DELIVERY_ENABLED": "true",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": "1025",
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "false",
        "NATIVE_ACTIVATION_FRONTEND_URL": "https://localhost:13000/activate-account",
    }


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    root.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
    (root / "app").mkdir()
    (root / "app/settings.py").write_bytes((SOURCE / "app/settings.py").read_bytes())
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", tmp_path / "greenfield-state")
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development", "PATH": "fixture-path"})
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    values = native_values()
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in values.items()), encoding="utf-8")
    return root, values


def arguments(**updates):
    values = {"profile": "legacy", "legacy_config": "managed", "confirm_database": "sbom_analyser_dev"}
    values.update(updates)
    return SimpleNamespace(**values)


def context(checkout):
    return dev_operator.resolve_native_context(arguments(), dev)


def save(values):
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in values.items()), encoding="utf-8")


def test_managed_operator_uses_saved_url_without_shell_export_and_preserves_material(checkout):
    _, values = checkout
    before = dev.CONFIG.read_bytes()
    assert "DATABASE_URL" not in os.environ
    resolved = context(checkout)
    assert resolved.database == dev_config.DatabaseTarget("127.0.0.1", 5432, "sbom_analyser_dev")
    assert resolved.environment["DATABASE_URL"] == URL
    assert resolved.environment["NATIVE_JWT_PRIVATE_KEY"] == values["NATIVE_JWT_PRIVATE_KEY"]
    dev.validate_secrets.assert_called_once()
    assert dev.CONFIG.read_bytes() == before
    assert SECRET not in repr(resolved) and SECRET not in repr(resolved.environment)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        resolved.profile = "greenfield"
    with pytest.raises(TypeError):
        resolved.environment["DATABASE_URL"] = "changed"
    with pytest.raises(AttributeError):
        resolved.environment._values = {}


def test_managed_minimal_persistent_configuration_matches_prepared_startup_defaults(checkout, monkeypatch):
    _, values = checkout
    selected = {
        name: value
        for name, value in values.items()
        if name
        in {
            "DATABASE_URL",
            "NATIVE_JWT_PRIVATE_KEY",
            "NATIVE_JWT_PUBLIC_KEY",
            "NATIVE_SECURITY_OUTBOX_KEY",
            "AUTH_SESSION_ENCRYPTION_KEY",
        }
    }
    selected["DEV_REDIS_PROVIDER"] = "local"
    save(selected)
    before = dev.CONFIG.read_bytes()
    monkeypatch.setattr(dev, "legacy_https_context", Mock())
    resolved = context(checkout)
    prepared = dev_prepared.prepared_legacy_environment(dev, "managed")
    assert "DATABASE_URL" not in os.environ
    assert all(prepared[name] == value for name, value in resolved.environment.items())
    assert resolved.environment["AUTH_ENABLED"] == resolved.environment["NATIVE_AUTH_ENABLED"] == "true"
    assert resolved.environment["NATIVE_JWT_ISSUER"] == "https://localhost:13000/native"
    assert resolved.environment["SMTP_PORT"] == str(dev.MAILPIT_SMTP_PORT)
    assert resolved.environment["AUTH_SESSION_REDIS_URL"] == "redis://127.0.0.1:6379/1"
    assert resolved.environment["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert dev.CONFIG.read_bytes() == before


def test_operator_context_and_projection_have_no_application_import_or_mutator(checkout, monkeypatch):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert not (name == "app" or name.startswith("app.") or name in {"psycopg", "sqlalchemy"})
        return original_import(name, *args, **kwargs)

    forbidden = Mock(side_effect=AssertionError("Operator planning attempted preparation or process execution"))
    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        for name in ("run", "Popen", "check_call", "check_output"):
            guard.setattr(subprocess, name, forbidden)
        for name in (
            "ensure_virtualenv",
            "ensure_dependencies",
            "ensure_database",
            "generate_keys",
            "write_config",
            "start_process",
        ):
            guard.setattr(dev, name, forbidden)
        resolved = context(checkout)
        projected = dev_operator.native_child_environment(resolved)
    assert projected["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    forbidden.assert_not_called()


def test_wrong_database_confirmation_fails_before_snapshot_or_driver_import(checkout, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Wrong target read credentials or connected"))
    monkeypatch.setattr(dev_operator.dev_environment, "resolve_existing", forbidden)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.resolve_native_context(arguments(confirm_database="unapproved-target"), dev)
    assert caught.value.code == "OPERATOR_DATABASE_CONFIRMATION_REQUIRED"
    forbidden.assert_not_called()


@pytest.mark.parametrize("name", ["PGHOSTADDR", "PGSERVICE", "PGOPTIONS", "PGSSLMODE", "PGSSLROOTCERT"])
def test_ambient_libpq_routing_and_tls_overrides_require_review_without_exposure(checkout, name):
    os.environ[name] = SECRET
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_LIBPQ_REVIEW_REQUIRED"
    assert SECRET not in str(caught.value)
    assert os.environ[name] == SECRET


@pytest.mark.parametrize("scope", ["production", "staging"])
def test_operator_refuses_production_scope_before_database_access(checkout, scope):
    os.environ["APP_ENVIRONMENT"] = scope
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_DEVELOPMENT_SCOPE_REQUIRED"


@pytest.mark.parametrize(
    "updates",
    [
        {"NATIVE_AUTH_ENABLED": "false", "HCL_AUTH_ENABLED": "true"},
        {"AUTH_ENABLED": "false"},
        {"DEV_DEFAULT_TENANT": "true"},
        {"ENTRA_ENABLED": "true"},
    ],
)
def test_operator_never_switches_authentication_modes_or_enables_bypass(checkout, updates):
    _, values = checkout
    values.update(updates)
    save(values)
    before = dev.CONFIG.read_bytes()
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_NATIVE_MODE_REQUIRED"
    assert dev.CONFIG.read_bytes() == before


def test_independent_native_keys_are_required_without_key_generation(checkout):
    _, values = checkout
    values["NATIVE_SECURITY_OUTBOX_KEY"] = values["AUTH_SESSION_ENCRYPTION_KEY"]
    save(values)
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_NATIVE_KEYS_REQUIRED"


def test_status_ignores_unselected_dotenv_without_reading_or_applying_it_but_child_blocks(
    checkout, database, monkeypatch
):
    root, _ = checkout
    fallback = root / ".env"
    fallback.write_text(
        "DATABASE_URL=postgresql://unselected:wrong-secret@unselected.invalid/wrong-database\n"
        "NATIVE_PLATFORM_BOOTSTRAP_ENABLED=true\nUNSELECTED_SENTINEL=never-read\n",
        encoding="utf-8",
    )
    before = fallback.read_bytes()
    read = dev_operator.dev_environment.bounded_read_text
    original_import = builtins.__import__

    def guarded_read(path, *args, **kwargs):
        assert Path(path) != fallback, "Status read an unselected dotenv source"
        return read(path, *args, **kwargs)

    def guarded_import(name, *args, **kwargs):
        assert name != "app" and not name.startswith("app.")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(dev_operator.dev_environment, "bounded_read_text", guarded_read)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    resolved = context(checkout)
    assert resolved.environment["DATABASE_URL"] == URL
    assert "UNSELECTED_SENTINEL" not in resolved.environment
    assert resolved.database == dev_config.DatabaseTarget("127.0.0.1", 5432, "sbom_analyser_dev")
    assert (
        dev_operator.inspect_native_enrollment(resolved, confirm_database="sbom_analyser_dev").code
        == "ENROLLMENT_REQUIRED"
    )
    _, connect = database
    assert connect.call_args.kwargs["dbname"] == "sbom_analyser_dev"
    assert connect.call_args.kwargs["hostaddr"] == "127.0.0.1"
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.native_child_environment(resolved)
    assert caught.value.code == "OPERATOR_DOTENV_REVIEW_REQUIRED"
    assert fallback.read_bytes() == before


def test_selected_dotenv_is_fully_projected_without_pydantic_or_app_import(checkout):
    root, values = checkout
    (root / ".env").write_text("\n".join(f"{key}='{value}'" for key, value in values.items()), encoding="utf-8")
    resolved = dev_operator.resolve_native_context(arguments(legacy_config="env"), dev)
    assert all(resolved.environment[key] == value for key, value in values.items())
    projected = dev_operator.native_child_environment(resolved)
    assert projected["DATABASE_URL"] == URL
    assert projected["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"


@pytest.mark.parametrize("change", ["unprojected-key", "changed-target"])
def test_selected_dotenv_child_projection_rechecks_current_file_without_rewriting_it(checkout, change):
    root, values = checkout
    selected = root / ".env"
    selected.write_text("\n".join(f"{key}='{value}'" for key, value in values.items()), encoding="utf-8")
    resolved = dev_operator.resolve_native_context(arguments(legacy_config="env"), dev)
    changed = dict(values)
    if change == "unprojected-key":
        changed["UNREVIEWED_SETTING"] = "fixture-unreviewed"
    else:
        changed["DATABASE_URL"] = URL.replace("sbom_analyser_dev", "different_fixture_database")
    selected.write_text("\n".join(f"{key}='{value}'" for key, value in changed.items()), encoding="utf-8")
    before = selected.read_bytes()
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.native_child_environment(resolved)
    assert caught.value.code == "OPERATOR_DOTENV_REVIEW_REQUIRED"
    assert resolved.environment["DATABASE_URL"] == URL
    assert selected.read_bytes() == before


def test_case_alias_settings_are_not_silently_projected(checkout):
    _, values = checkout
    values["log_file"] = "fixture-logging-path"
    save(values)
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_SETTINGS_NAME_AMBIGUOUS"


def test_child_projection_is_fresh_redacted_bootstrap_disabled_and_does_not_mutate_sources(checkout):
    _, values = checkout
    values["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] = "true"
    save(values)
    os.environ["UNRELATED_PROCESS_SECRET"] = SECRET
    os.environ["NEXT_PUBLIC_UNAPPROVED_SECRET"] = SECRET
    resolved = context(checkout)
    projected = dev_operator.native_child_environment(resolved)
    assert projected["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert resolved.environment["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "true"
    assert projected["PYTHON_DOTENV_DISABLED"] == projected["PYTHONDONTWRITEBYTECODE"] == "1"
    assert projected["PYTHONPATH"] == str(dev.ROOT)
    assert "UNRELATED_PROCESS_SECRET" not in projected and "NEXT_PUBLIC_UNAPPROVED_SECRET" not in projected
    assert SECRET not in repr(projected)


def test_greenfield_trust_precedes_application_credentials(checkout, monkeypatch):
    select = Mock(return_value=("greenfield", "managed"))
    resolve = Mock(side_effect=AssertionError("Untrusted profile read application credentials"))
    trust = Mock(side_effect=RuntimeError(SECRET))
    monkeypatch.setattr(dev_operator.dev_environment, "select_profile", select)
    monkeypatch.setattr(dev_operator.dev_environment, "resolve_existing", resolve)
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", trust)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.resolve_native_context(
            arguments(profile="greenfield", confirm_database=dev.GreenfieldStack.DB), dev
        )
    assert caught.value.code == "OPERATOR_TRUST_REQUIRED"
    assert SECRET not in str(caught.value)
    trust.assert_called_once_with(dev.GreenfieldStack.STATE, prepare=False)
    resolve.assert_not_called()


class ReadOnlyConnection:
    def __init__(self):
        self.statements, self.rollbacks, self.closed = [], 0, False
        self.readonly, self.database = "on", "sbom_analyser_dev"
        self.revisions, self.users, self.admins, self.reservation = [("103_tenant_admin_governance",)], 0, 0, None
        self.error = None

    def execute(self, statement):
        self.statements.append(statement)
        normalized = statement.lower()
        assert normalized.startswith(("select", "show")), "Operator status attempted a mutating SQL statement"
        if self.error:
            raise RuntimeError(self.error)
        if "transaction_read_only" in normalized:
            row = (self.readonly,)
        elif "current_database()" in normalized:
            row = (self.database,)
        elif "platform_user_roles" in normalized:
            row = (self.admins,)
        elif "native_platform_bootstrap" in normalized:
            row = (self.reservation,) if self.reservation is not None else None
        else:
            row = (self.users,)
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: self.revisions)

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

    def commit(self):
        pytest.fail("Read-only status committed a transaction")


@pytest.fixture
def database(checkout, monkeypatch):
    connection = ReadOnlyConnection()
    connect = Mock(return_value=connection)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    monkeypatch.setattr(dev_operator, "discover", lambda root: SimpleNamespace(head="103_tenant_admin_governance"))
    return connection, connect


@pytest.mark.parametrize(
    ("admins", "reservation", "users", "code", "state"),
    [
        (0, None, 0, "ENROLLMENT_REQUIRED", "NOT_STARTED"),
        (0, None, 5, "ENROLLMENT_REQUIRED", "NOT_STARTED"),
        (0, "PENDING", 1, "PENDING_ACTIVATION", "PENDING"),
        (0, "COMPLETED", 1, "BOOTSTRAP_RESERVED", "COMPLETED"),
        (0, SECRET, 1, "BOOTSTRAP_RESERVED", "UNKNOWN"),
        (1, "COMPLETED", 1, "ADMIN_READY", "COMPLETED"),
        (1, "COMPLETED", 5, "ADMIN_READY", "COMPLETED"),
    ],
)
def test_status_classifies_admin_reservation_and_existing_users_without_granting_permission(
    checkout, database, admins, reservation, users, code, state
):
    connection, _ = database
    connection.admins, connection.reservation, connection.users = admins, reservation, users
    status = dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert (status.code, status.state) == (code, state)
    assert status.enrollment_required is (code == "ENROLLMENT_REQUIRED")
    assert status.platform_admin_available is bool(admins)
    assert status.existing_users_present is bool(users)
    assert status.live_readiness_verified is False
    assert SECRET not in repr(status)
    assert not hasattr(status, "email") and not hasattr(status, "user_id")
    assert connection.rollbacks == 1 and connection.closed


def test_status_pins_readonly_transport_and_never_imports_application(checkout, database, monkeypatch):
    connection, connect = database
    resolved = context(checkout)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != "app" and not name.startswith("app.")
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        dev_operator.inspect_native_enrollment(resolved, confirm_database="sbom_analyser_dev")
    kwargs = connect.call_args.kwargs
    assert not connect.call_args.args
    assert kwargs["dbname"] == "sbom_analyser_dev" and kwargs["hostaddr"] == "127.0.0.1"
    assert kwargs["host"] == "127.0.0.1" and kwargs["port"] == 5432
    assert kwargs["password"] == SECRET and kwargs["connect_timeout"] == 3 and kwargs["autocommit"] is False
    assert "default_transaction_read_only=on" in kwargs["options"] and "statement_timeout=3000" in kwargs["options"]
    assert "lock_timeout=250" in kwargs["options"] and "idle_in_transaction_session_timeout=5000" in kwargs["options"]
    target = next(i for i, sql in enumerate(connection.statements) if "current_database()" in sql)
    enrollment = next(i for i, sql in enumerate(connection.statements) if "iam_users" in sql)
    assert target < enrollment
    predicate = next(sql for sql in connection.statements if "platform_user_roles" in sql)
    assert (
        "verification_required=false" in predicate
        and "email_verified=true" in predicate
        and "MICROSOFT_ENTRA" in predicate
    )


@pytest.mark.parametrize("failure", ["readonly", "target", "schema", "multiple-heads"])
def test_unsafe_database_observation_blocks_enrollment_reads_and_closes(checkout, database, failure):
    connection, _ = database
    if failure == "readonly":
        connection.readonly = "off"
    elif failure == "target":
        connection.database = "unapproved-fixture-target"
    elif failure == "schema":
        connection.revisions = []
    else:
        connection.revisions.append(("fixture-unreviewed-head",))
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == {
        "readonly": "OPERATOR_DATABASE_NOT_READONLY",
        "target": "OPERATOR_DATABASE_TARGET_MISMATCH",
        "schema": "OPERATOR_SCHEMA_REQUIRED",
        "multiple-heads": "OPERATOR_SCHEMA_REQUIRED",
    }[failure]
    assert not any("iam_users" in sql or "bootstrap" in sql for sql in connection.statements)
    assert connection.rollbacks == 1 and connection.closed


def test_status_rechecks_exact_confirmation_before_driver_import_or_connection(checkout, database, monkeypatch):
    _, connect = database
    resolved = context(checkout)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert name != "psycopg"
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(builtins, "__import__", guarded_import)
        with pytest.raises(dev_operator.OperatorError) as caught:
            dev_operator.inspect_native_enrollment(resolved, confirm_database="wrong-fixture")
    assert caught.value.code == "OPERATOR_DATABASE_CONFIRMATION_REQUIRED"
    connect.assert_not_called()


def test_driver_error_is_redacted_without_commit_and_cleanup_is_attempted(checkout, database, capsys):
    connection, _ = database
    connection.error = SECRET
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_DATABASE_INSPECTION_FAILED"
    assert SECRET not in str(caught.value) and SECRET not in repr(caught.value)
    assert connection.rollbacks == 1 and connection.closed
    assert not capsys.readouterr().out


def test_cleanup_failure_is_an_explicit_error_not_success(checkout, database, monkeypatch):
    connection, _ = database
    monkeypatch.setattr(connection, "rollback", Mock(side_effect=RuntimeError(SECRET)))
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_DATABASE_CLEANUP_UNCONFIRMED"
    assert SECRET not in str(caught.value) and connection.closed


@pytest.mark.parametrize("crlf", [False, True])
def test_fresh_status_with_real_migration_discovery(checkout, database, monkeypatch, crlf):
    from scripts.greenfield_migration_graph import discover

    root, _ = checkout
    versions = root / "alembic/versions"
    versions.mkdir(parents=True)
    for source in (SOURCE / "alembic/versions").glob("*.py"):
        raw = source.read_bytes().replace(b"\r\n", b"\n")
        (versions / source.name).write_bytes(raw.replace(b"\n", b"\r\n") if crlf else raw)
    monkeypatch.setattr(dev_operator, "discover", discover)
    status = dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert status.code == "ENROLLMENT_REQUIRED"
    assert status.live_readiness_verified is False
    connection, _ = database
    assert connection.closed and connection.rollbacks == 1


def test_discovery_failure_is_redacted_and_never_connects(checkout, database, monkeypatch):
    _, connect = database
    monkeypatch.setattr(dev_operator, "discover", Mock(side_effect=RuntimeError(SECRET)))
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_MIGRATION_SOURCE_INVALID"
    assert "migration source discovery" in str(caught.value)
    assert SECRET not in str(caught.value)
    connect.assert_not_called()


@pytest.mark.parametrize("failure,code", [
    (ImportError(SECRET), "OPERATOR_NATIVE_DEPENDENCIES_REQUIRED"),
    (ValueError(SECRET), "OPERATOR_NATIVE_KEYS_REQUIRED"),
])
def test_missing_crypto_dependency_is_not_reported_as_invalid_keys(checkout, monkeypatch, failure, code):
    monkeypatch.setattr(dev, "validate_secrets", Mock(side_effect=failure))
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == code
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://fixture@127.0.0.1:5432/sbom_analyser_dev",
    "postgresql+psycopg://fixture:@127.0.0.1:5432/sbom_analyser_dev",
])
def test_missing_database_password_never_connects(checkout, database, url):
    _, values = checkout
    values["DATABASE_URL"] = url
    save(values)
    _, connect = database
    with pytest.raises(dev_operator.OperatorError) as caught:
        context(checkout)
    assert caught.value.code == "OPERATOR_DATABASE_CREDENTIALS_REQUIRED"
    connect.assert_not_called()


@pytest.mark.parametrize("statement,operation", [
    ("SHOW transaction_read_only", "read-only transaction verification"),
    ("SELECT pg_catalog.current_database()", "database identity verification"),
    ("SELECT version_num", "schema marker inspection"),
    ("SELECT count(*) FROM public.iam_users", "user count inspection"),
    ("SELECT count(*) FROM public.platform_user_roles", "administrator eligibility inspection"),
    ("SELECT state FROM public.native_platform_bootstrap", "bootstrap reservation inspection"),
])
def test_query_failures_identify_only_the_fixed_operation(checkout, database, monkeypatch, statement, operation):
    connection, _ = database
    execute = connection.execute

    def fail_selected(sql):
        if sql.startswith(statement):
            raise RuntimeError(SECRET)
        return execute(sql)

    monkeypatch.setattr(connection, "execute", fail_selected)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_DATABASE_INSPECTION_FAILED"
    assert operation in str(caught.value)
    assert SECRET not in str(caught.value)
    assert connection.closed and connection.rollbacks == 1


def test_invalid_postgres_credentials_report_connection_stage_without_private_details(checkout, database):
    _, connect = database
    connect.side_effect = RuntimeError(SECRET)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_DATABASE_INSPECTION_FAILED"
    assert "PostgreSQL connection" in str(caught.value)
    assert SECRET not in str(caught.value)


def test_missing_postgres_driver_is_not_reported_as_database_failure(checkout, database, monkeypatch):
    _, connect = database
    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_DATABASE_DRIVER_REQUIRED"
    connect.assert_not_called()


def test_status_reporting_deadline_remains_bounded(checkout, database, monkeypatch):
    _, connect = database
    bounded = Mock(side_effect=dev_operator.dev_diagnostics.DiagnosticError("PROBE_TIMEOUT"))
    monkeypatch.setattr(dev_operator.dev_diagnostics, "_bounded", bounded)
    with pytest.raises(dev_operator.OperatorError) as caught:
        dev_operator.inspect_native_enrollment(context(checkout), confirm_database="sbom_analyser_dev")
    assert caught.value.code == "OPERATOR_STATUS_TIMEOUT"
    assert bounded.call_args.kwargs == {"timeout": 8}
    connect.assert_not_called()
