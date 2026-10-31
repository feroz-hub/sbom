"""Prepared-start and credential-inspection guards; synthetic fixtures only."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_config, dev_environment, dev_prepared

SECRET = "fixture-prepared-secret-never-log"
DATABASE_URL = f"postgresql+psycopg://postgres:{SECRET}@127.0.0.1:5432/sbom_analyser_dev"


@pytest.fixture
def checkout(monkeypatch, tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "VENV", root / ".venv")
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", root / "fixture-greenfield")
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development"})
    return root


def snapshot(root):
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def write_managed(values):
    dev.CONFIG.write_text("\n".join(f"{key}={json.dumps(value)}" for key, value in values.items()), encoding="utf-8")


def saved_native(provider="local"):
    postgres = dev.POSTGRES_PORT if provider == "docker" else 5432
    redis = dev.REDIS_PORT if provider == "docker" else 6379
    return {
        "DATABASE_URL": DATABASE_URL.replace(":5432/", f":{postgres}/"),
        "DEV_POSTGRES_PROVIDER": provider,
        "DEV_REDIS_PROVIDER": provider,
        "AUTH_ENABLED": "true",
        "NATIVE_AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "DEV_DEFAULT_TENANT": "false",
        "REDIS_URL": f"redis://127.0.0.1:{redis}/0",
        "CELERY_BROKER_URL": f"redis://127.0.0.1:{redis}/0",
        "CELERY_RESULT_BACKEND": f"redis://127.0.0.1:{redis}/0",
        "AUTH_SESSION_REDIS_URL": f"redis://127.0.0.1:{redis}/1",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": f"redis://127.0.0.1:{redis}/2",
        "SMTP_PORT": str(dev.MAILPIT_SMTP_PORT),
        "NATIVE_JWT_PRIVATE_KEY": "fixture-existing-private",
        "NATIVE_JWT_PUBLIC_KEY": "fixture-existing-public",
        "NATIVE_SECURITY_OUTBOX_KEY": "fixture-existing-outbox",
        "AUTH_SESSION_ENCRYPTION_KEY": "fixture-existing-session",
    }


def forbidden_mutation(monkeypatch):
    forbidden = Mock(
        side_effect=AssertionError("prepared startup attempted installation, discovery or persistent mutation")
    )
    for name in (
        "ensure_virtualenv",
        "ensure_dependencies",
        "ensure_frontend",
        "ensure_database",
        "prepare_managed_legacy",
        "generate_keys",
        "write_config",
        "run_migrations",
        "select_service",
        "repository_database_url",
        "pgpass_database_urls",
        "default_database_url",
        "start_compose",
    ):
        if hasattr(dev, name):
            monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    return forbidden


@pytest.fixture
def prepared_project(checkout, monkeypatch):
    root = checkout
    requirements, package, lock = b"fixture==1\n", b'{"name":"fixture"}\n', b'{"lockfileVersion":3}\n'
    files = {
        root / "requirements.txt": requirements,
        root / "frontend/package.json": package,
        root / "frontend/package-lock.json": lock,
        dev.VENV / ".sbom-requirements-sha256": hashlib.sha256(requirements).hexdigest().encode(),
        root / "frontend/node_modules/.sbom-dependencies-sha256": hashlib.sha256(package + b"\0" + lock)
        .hexdigest()
        .encode(),
        root / "frontend/node_modules/next/dist/bin/next": b"fixture next CLI",
        dev.venv_python(): b"fixture interpreter",
        root / "bin/node": b"fixture node",
        root / "bin/npm": b"fixture npm entry point",
    }
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    npm = str(root / "bin/npm")
    monkeypatch.setattr(dev_prepared.importlib.util, "find_spec", lambda package: object())
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: root / "bin/node")
    monkeypatch.setattr(dev_prepared.shutil, "which", lambda *args, **kwargs: npm)
    monkeypatch.setattr(dev, "normalize_command", lambda command: list(command))
    return root, npm


def test_prepared_project_checks_stamps_and_entry_points_without_executing(prepared_project, monkeypatch):
    root, npm = prepared_project
    before = snapshot(root)
    forbidden = forbidden_mutation(monkeypatch)
    assert dev_prepared.require_project(dev) == npm
    assert snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("missing", ["python", "python-stamp", "frontend-stamp", "next-cli", "npm", "package"])
def test_missing_or_stale_preparation_refuses_without_installing(prepared_project, monkeypatch, missing):
    root, _ = prepared_project
    if missing == "python":
        dev.venv_python().unlink()
    elif missing == "python-stamp":
        (dev.VENV / ".sbom-requirements-sha256").write_text("stale", encoding="utf-8")
    elif missing == "frontend-stamp":
        (root / "frontend/node_modules/.sbom-dependencies-sha256").write_text("stale", encoding="utf-8")
    elif missing == "next-cli":
        (root / "frontend/node_modules/next/dist/bin/next").unlink()
    elif missing == "npm":
        monkeypatch.setattr(dev_prepared.shutil, "which", lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(dev_prepared.importlib.util, "find_spec", lambda package: None)
    before = snapshot(root)
    forbidden = forbidden_mutation(monkeypatch)
    with pytest.raises(dev.SetupError) as caught:
        dev_prepared.require_project(dev)
    assert "SETUP_REQUIRED" in str(caught.value)
    assert snapshot(root) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("provider", ["local", "docker"])
def test_prepared_managed_environment_preserves_provider_keys_and_tls_without_preparation(
    checkout, monkeypatch, provider
):
    saved = saved_native(provider)
    write_managed(saved)
    validate = Mock()
    tls = Mock(return_value=object())
    monkeypatch.setattr(dev, "validate_secrets", validate)
    monkeypatch.setattr(dev, "legacy_https_context", tls)
    before = snapshot(checkout)
    forbidden = forbidden_mutation(monkeypatch)
    env = dev_prepared.prepared_legacy_environment(dev, "managed")
    pg = dev.POSTGRES_PORT if provider == "docker" else 5432
    redis = dev.REDIS_PORT if provider == "docker" else 6379
    expected = {
        **os.environ,
        **dev.resolve_config(saved, pg, redis, dev.MAILPIT_SMTP_PORT, provider, provider),
        "PYTHONPATH": str(checkout),
    }
    assert env == expected
    assert env["DATABASE_URL"] == saved["DATABASE_URL"]
    assert env["NATIVE_JWT_PRIVATE_KEY"] == saved["NATIVE_JWT_PRIVATE_KEY"]
    validate.assert_called_once_with(saved)
    tls.assert_called_once_with()
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


def test_native_disabled_hcl_session_key_does_not_require_or_generate_native_keys(checkout, monkeypatch):
    values = {
        "DATABASE_URL": DATABASE_URL,
        "AUTH_ENABLED": "true",
        "DEV_DEFAULT_TENANT": "false",
        "NATIVE_AUTH_ENABLED": "false",
        "HCL_AUTH_ENABLED": "true",
        "AUTH_SESSION_ENCRYPTION_KEY": "fixture-existing-session",
        "HCL_IAM_ISSUER": "https://fixture-idp.invalid",
        "HCL_IAM_AUDIENCE": "fixture-api",
        "HCL_IAM_CLIENT_ID": "fixture-client",
    }
    (checkout / ".env").write_text("\n".join(f"{key}={value}" for key, value in values.items()), encoding="utf-8")
    before = snapshot(checkout)
    forbidden = forbidden_mutation(monkeypatch)
    monkeypatch.setattr(dev, "validate_secrets", forbidden)
    tls = Mock(return_value=object())
    monkeypatch.setattr(dev, "legacy_https_context", tls)
    env = dev_prepared.prepared_legacy_environment(dev, "env")
    assert env["NATIVE_AUTH_ENABLED"] == "false"
    assert env["HCL_AUTH_ENABLED"] == "true"
    assert env["AUTH_SESSION_ENCRYPTION_KEY"] == values["AUTH_SESSION_ENCRYPTION_KEY"]
    assert "NATIVE_JWT_PRIVATE_KEY" not in env
    assert snapshot(checkout) == before
    tls.assert_called_once_with()
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "override",
    [
        {"AUTH_ENABLED": "false"},
        {"DEV_DEFAULT_TENANT": "true"},
        {"APP_ENVIRONMENT": "production"},
        {"APP_ENVIRONMENT": "staging"},
        {"APP_ENVIRONMENT": "development", "APP_ENV": "test"},
    ],
)
def test_prepared_start_refuses_authentication_bypass_or_deployment_scope(checkout, monkeypatch, override):
    write_managed({**saved_native(), **override})
    before = snapshot(checkout)
    forbidden = forbidden_mutation(monkeypatch)
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    monkeypatch.setattr(dev, "legacy_https_context", Mock(return_value=object()))
    with pytest.raises(dev.SetupError) as caught:
        dev_prepared.prepared_legacy_environment(dev, "managed")
    assert SECRET not in str(caught.value)
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "key,value",
    [
        *(
            (key, value)
            for key in ("AUTH_ENABLED", "NATIVE_AUTH_ENABLED")
            for value in ("false", "0", "no", "off", "unknown")
        ),
        *(
            (key, value)
            for key in ("HCL_AUTH_ENABLED", "ENTRA_ENABLED", "DEV_DEFAULT_TENANT")
            for value in ("true", "1", "yes", "on", "unknown")
        ),
    ],
)
def test_prepared_managed_start_rejects_mode_conflicts_before_keys_or_tls(checkout, monkeypatch, key, value):
    write_managed({**saved_native(), key: value})
    before = snapshot(checkout)
    forbidden = forbidden_mutation(monkeypatch)
    monkeypatch.setattr(dev, "validate_secrets", forbidden)
    monkeypatch.setattr(dev, "legacy_https_context", forbidden)
    with pytest.raises(dev.SetupError, match="MANAGED_AUTHENTICATION_REVIEW_REQUIRED"):
        dev_prepared.prepared_legacy_environment(dev, "managed")
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


def test_saved_managed_mode_remains_authoritative_over_conflicting_ambient_flags(checkout, monkeypatch):
    for key, value in {
        "AUTH_ENABLED": "0",
        "NATIVE_AUTH_ENABLED": "off",
        "HCL_AUTH_ENABLED": "yes",
        "ENTRA_ENABLED": "on",
        "DEV_DEFAULT_TENANT": "1",
    }.items():
        monkeypatch.setitem(os.environ, key, value)
    saved = {**saved_native(), "ENTRA_ENABLED": "false"}
    write_managed(saved)
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    monkeypatch.setattr(dev, "legacy_https_context", Mock(return_value=object()))
    before = snapshot(checkout)
    forbidden = forbidden_mutation(monkeypatch)
    environment = dev_prepared.prepared_legacy_environment(dev, "managed")
    assert environment["AUTH_ENABLED"] == "true"
    assert environment["NATIVE_AUTH_ENABLED"] == "true"
    assert environment["HCL_AUTH_ENABLED"] == "false"
    assert environment["ENTRA_ENABLED"] == "false"
    assert environment["DEV_DEFAULT_TENANT"] == "false"
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("family", ["managed", "windows", "env"])
def test_shared_loader_preserves_selected_file_format_and_resolution_precedence(checkout, monkeypatch, family):
    saved = {"DATABASE_URL": DATABASE_URL, "SHARED": "saved", "VALUE": "literal=${HOME}"}
    frontend = {"SHARED": "frontend", "FRONTEND_ONLY": "kept"}
    (checkout / "frontend").mkdir()
    (checkout / "frontend/.env.local").write_text(
        "\n".join(f"{key}={value}" for key, value in frontend.items()), encoding="utf-8"
    )
    if family == "managed":
        write_managed(saved)
    elif family == "windows":
        (checkout / ".windows").mkdir()
        (checkout / ".windows/sbom.env.ps1").write_text(
            "\n".join(f"$env:{key} = '{value}'" for key, value in saved.items()), encoding="utf-8"
        )
    else:
        (checkout / ".env").write_text("\n".join(f"{key}={value}" for key, value in saved.items()), encoding="utf-8")
    monkeypatch.setattr(os, "environ", {"SHARED": "process", "PROCESS_ONLY": "kept"})
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: checkout))
    before = snapshot(checkout)
    actual_saved, actual_frontend = dev_environment.load_legacy_snapshots(family, dev)
    assert actual_saved == saved
    assert actual_frontend == ({} if family == "managed" else frontend)
    args = SimpleNamespace(profile="legacy", legacy_config=family)
    plan = dev_environment.resolve_existing(args, dev, None)
    expected = dev_config.resolve_configuration(
        profile="legacy",
        family=family,
        inherited=dict(os.environ),
        saved=saved,
        frontend=actual_frontend,
        root=str(checkout),
        platform=sys.platform,
    )
    assert dict(plan.environment) == dict(expected.environment)
    assert plan.environment["SHARED"] == "saved"
    assert snapshot(checkout) == before


def test_missing_selected_managed_file_never_falls_back_to_root_dotenv(checkout):
    (checkout / ".env").write_text("DATABASE_URL=" + DATABASE_URL, encoding="utf-8")
    before = snapshot(checkout)
    with pytest.raises(FileNotFoundError):
        dev_environment.load_legacy_snapshots("managed", dev)
    assert snapshot(checkout) == before


def test_bounded_reader_rejects_directory_oversize_and_hardlinks_without_changes(checkout):
    with pytest.raises(dev_environment.EnvironmentReadError):
        dev_environment.bounded_read_text(checkout)
    original = checkout / "fixture-file"
    original.write_bytes(b"x" * 32)
    with pytest.raises(dev_environment.EnvironmentReadError, match="OVERSIZED_FILE"):
        dev_environment.bounded_read_bytes(original, limit=16)
    link = checkout / "fixture-hardlink"
    try:
        os.link(original, link)
    except OSError:
        pytest.skip("This filesystem does not support owned-fixture hardlinks")
    before = snapshot(checkout)
    with pytest.raises(dev_environment.EnvironmentReadError, match="REDIRECTED_FILE"):
        dev_environment.bounded_read_bytes(link)
    assert snapshot(checkout) == before


class DriverError(Exception):
    def __init__(self, sqlstate):
        self.sqlstate = sqlstate
        super().__init__(SECRET)


class ReadOnlyConnection:
    def __init__(self, database="sbom_analyser_dev", readonly="on", populated=False):
        self.database, self.readonly, self.populated = database, readonly, populated
        self.statements = []
        self.rollbacks = 0
        self.closed = False

    def execute(self, statement, parameters=None):
        query = str(statement)
        self.statements.append((query, parameters))
        normalized = query.strip().lower()
        assert normalized.startswith(("show", "select")), "Credential inspection attempted mutating SQL"
        if "transaction_read_only" in normalized:
            row = (self.readonly,)
        elif "current_database()" in normalized:
            row = (self.database,)
        elif "pg_class" in normalized:
            row = (self.populated,)
        elif "pg_database" in normalized:
            row = None
        else:
            raise AssertionError("Unexpected credential-inspection query")
        return SimpleNamespace(fetchone=lambda: row)

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

    def commit(self):
        pytest.fail("Credential inspection committed a transaction")


def fake_psycopg(monkeypatch, responses):
    connect = Mock(side_effect=responses)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(Error=DriverError, connect=connect))
    return connect


def test_credential_validation_only_inspects_selected_target_readonly_and_closes(monkeypatch):
    connection = ReadOnlyConnection()
    connect = fake_psycopg(monkeypatch, [connection])
    assert dev.validate_database_credentials(DATABASE_URL) is True
    kwargs = connect.call_args.kwargs
    assert not connect.call_args.args
    assert kwargs["dbname"] == "sbom_analyser_dev"
    assert kwargs["hostaddr"] == "127.0.0.1"
    assert kwargs["connect_timeout"] <= 3 and kwargs["autocommit"] is False
    assert "default_transaction_read_only=on" in kwargs["options"]
    assert "statement_timeout=" in kwargs["options"] and "lock_timeout=" in kwargs["options"]
    assert [query for query, _ in connection.statements] == [
        "SHOW transaction_read_only",
        "SELECT pg_catalog.current_database()",
    ]
    assert connection.rollbacks == 1 and connection.closed


@pytest.mark.parametrize("allow_missing", [False, True])
def test_missing_database_uses_maintenance_only_when_explicitly_allowed(monkeypatch, allow_missing):
    maintenance = ReadOnlyConnection(database="postgres")
    responses = [DriverError("3D000"), maintenance] if allow_missing else [DriverError("3D000")]
    connect = fake_psycopg(monkeypatch, responses)
    if allow_missing:
        assert dev.validate_database_credentials(DATABASE_URL, allow_missing=True) is False
        assert [call.kwargs["dbname"] for call in connect.call_args_list] == ["sbom_analyser_dev", "postgres"]
        assert any(
            "pg_catalog.pg_database" in sql and parameters == ("sbom_analyser_dev",)
            for sql, parameters in maintenance.statements
        )
        assert maintenance.rollbacks == 1 and maintenance.closed
    else:
        with pytest.raises(dev.SetupError) as caught:
            dev.validate_database_credentials(DATABASE_URL)
        assert SECRET not in str(caught.value)
        assert connect.call_count == 1
    assert all("CREATE" not in sql.upper() for sql, _ in maintenance.statements)


@pytest.mark.parametrize("sqlstate", ["28P01", "42501", "08001", None])
def test_access_or_unknown_connection_failure_never_triggers_maintenance_fallback(monkeypatch, sqlstate):
    connect = fake_psycopg(monkeypatch, [DriverError(sqlstate)])
    with pytest.raises(dev.SetupError) as caught:
        dev.validate_database_credentials(DATABASE_URL, allow_missing=True)
    assert connect.call_count == 1
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("failure", ["readonly", "target"])
def test_failed_server_identity_or_readonly_proof_closes_and_refuses(monkeypatch, failure):
    connection = ReadOnlyConnection(
        database="wrong_fixture_target" if failure == "target" else "sbom_analyser_dev",
        readonly="off" if failure == "readonly" else "on",
    )
    fake_psycopg(monkeypatch, [connection])
    with pytest.raises(dev.SetupError):
        dev.validate_database_credentials(DATABASE_URL, allow_missing=True)
    assert connection.rollbacks == 1 and connection.closed
    assert not any("pg_database" in sql for sql, _ in connection.statements)


@pytest.mark.parametrize("populated", [False, True, None])
def test_initial_key_empty_database_proof_is_readonly_and_fail_closed(monkeypatch, populated):
    connection = ReadOnlyConnection(populated=populated)
    fake_psycopg(monkeypatch, [connection])
    forbidden = Mock(side_effect=AssertionError("Empty-schema inspection generated or persisted keys"))
    monkeypatch.setattr(dev, "generate_keys", forbidden)
    monkeypatch.setattr(dev, "write_config", forbidden)
    if populated is False:
        dev._require_empty_database_for_initial_keys(DATABASE_URL)
    else:
        with pytest.raises(dev.SetupError, match="ORIGINAL_KEYS_REQUIRED"):
            dev._require_empty_database_for_initial_keys(DATABASE_URL)
    assert any("pg_catalog.pg_class" in query for query, _ in connection.statements)
    assert connection.rollbacks == 1 and connection.closed
    forbidden.assert_not_called()


def test_maintenance_inspection_cannot_target_an_unapproved_database(monkeypatch):
    connect = fake_psycopg(monkeypatch, [])
    with pytest.raises(dev.SetupError):
        dev._readonly_local_database(DATABASE_URL, database="unapproved_fixture_target")
    connect.assert_not_called()


def setup_authority(*, initialize=False):
    return SimpleNamespace(
        initialize_database=initialize,
        confirm_database=dev.DB_NAME if initialize else None,
        postgres_provider=None,
        redis_provider=None,
        mailpit_provider=None,
        _setup_authorized_categories=frozenset({"configuration", "secrets", "database-initialize"})
        if initialize
        else frozenset({"project-dependencies"}),
    )


def mock_running_providers(monkeypatch, events, *, unavailable=False):
    def select(service, docker_port, local_port, *, check, env, preferred):
        assert check is True, "Managed setup attempted to start a dependency"
        events.append("provider:" + service)
        if unavailable:
            return "Docker (available to start)", docker_port
        return "local", local_port

    monkeypatch.setattr(dev, "select_service", select)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: True)


@pytest.mark.parametrize("populated", [False, True])
def test_fresh_managed_preparation_proves_empty_target_before_keys_and_create_only_publication(
    checkout, monkeypatch, populated
):
    events = []
    monkeypatch.setattr(dev, "read_config", lambda: {})
    mock_running_providers(monkeypatch, events)

    def configure(values, saved, port, **kwargs):
        assert not saved
        assert kwargs["allow_missing_database"] is True and kwargs["persist"] is False
        values["DATABASE_URL"] = DATABASE_URL
        events.append("credentials")

    def empty(url):
        assert url == DATABASE_URL
        events.append("empty-proof")
        if populated:
            raise dev.SetupError("ORIGINAL_KEYS_REQUIRED: fixture target has existing application state")

    def generate(values):
        assert events[-1] == "empty-proof"
        events.append("keys")
        values.update({key: value for key, value in saved_native().items() if "KEY" in key})

    def publish(values, **kwargs):
        assert kwargs == {"create_only": True}
        assert events[-1] == "keys"
        events.append("publication")

    monkeypatch.setattr(dev, "configure_local_database", configure)
    monkeypatch.setattr(dev, "ensure_database", lambda url: events.append("database"))
    monkeypatch.setattr(dev, "_require_empty_database_for_initial_keys", empty)
    generate_spy = Mock(side_effect=generate)
    publish_spy = Mock(side_effect=publish)
    monkeypatch.setattr(dev, "generate_keys", generate_spy)
    monkeypatch.setattr(dev, "write_config", publish_spy)
    monkeypatch.setattr(dev, "start_compose", Mock(side_effect=AssertionError("Legacy setup started a container")))
    if populated:
        with pytest.raises(dev.SetupError, match="ORIGINAL_KEYS_REQUIRED"):
            dev.prepare_managed_legacy(setup_args=setup_authority(initialize=True))
        generate_spy.assert_not_called()
        publish_spy.assert_not_called()
    else:
        env = dev.prepare_managed_legacy(setup_args=setup_authority(initialize=True))
        assert env["DATABASE_URL"] == DATABASE_URL
        assert (
            events.index("credentials")
            < events.index("database")
            < events.index("empty-proof")
            < events.index("keys")
            < events.index("publication")
        )
        generate_spy.assert_called_once()
        publish_spy.assert_called_once()
    assert not dev.CONFIG.exists()


def test_missing_dependency_is_refused_before_credentials_database_or_key_preparation(checkout, monkeypatch):
    events = []
    monkeypatch.setattr(dev, "read_config", lambda: {})
    mock_running_providers(monkeypatch, events, unavailable=True)
    forbidden = Mock(side_effect=AssertionError("an unavailable provider triggered configuration/database/key changes"))
    for name in (
        "configure_local_database",
        "validate_database_credentials",
        "ensure_database",
        "generate_keys",
        "write_config",
        "start_compose",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    with pytest.raises(dev.SetupError):
        dev.prepare_managed_legacy(setup_args=setup_authority(initialize=True))
    forbidden.assert_not_called()


def test_existing_managed_setup_never_regenerates_or_rewrites_persistent_keys(checkout, monkeypatch):
    saved = saved_native()
    write_managed(saved)
    before = snapshot(checkout)
    monkeypatch.setattr(dev, "read_config", lambda: dict(saved))
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    events = []
    mock_running_providers(monkeypatch, events)

    def configure(values, existing, port, **kwargs):
        assert existing == saved
        assert kwargs["persist"] is False
        assert kwargs["allow_missing_database"] is False
        assert values["DATABASE_URL"] == saved["DATABASE_URL"]

    monkeypatch.setattr(dev, "configure_local_database", configure)
    forbidden = Mock(side_effect=AssertionError("existing configuration was reset, rewritten or rotated"))
    for name in (
        "ensure_database",
        "_require_empty_database_for_initial_keys",
        "generate_keys",
        "write_config",
        "start_compose",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    env = dev.prepare_managed_legacy(setup_args=setup_authority())
    for key in (
        "DATABASE_URL",
        "NATIVE_JWT_PRIVATE_KEY",
        "NATIVE_JWT_PUBLIC_KEY",
        "NATIVE_SECURITY_OUTBOX_KEY",
        "AUTH_SESSION_ENCRYPTION_KEY",
    ):
        assert env[key] == saved[key]
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("reason", ["no-authority", "wrong-confirmation"])
def test_fresh_managed_preparation_refuses_before_provider_or_credential_operations(checkout, monkeypatch, reason):
    monkeypatch.setattr(dev, "read_config", lambda: {})
    args = setup_authority(initialize=True)
    if reason == "no-authority":
        args._setup_authorized_categories = frozenset()
    else:
        args.confirm_database = "unapproved_fixture_name"
    forbidden = Mock(side_effect=AssertionError("unapproved target entered provider or credential preparation"))
    for name in ("select_service", "configure_local_database", "ensure_database", "generate_keys", "write_config"):
        monkeypatch.setattr(dev, name, forbidden)
    with pytest.raises(dev.SetupError):
        dev.prepare_managed_legacy(setup_args=args)
    forbidden.assert_not_called()


def test_normal_start_uses_prepared_gates_without_install_generation_or_database_creation(checkout, monkeypatch):
    env = {"DEV_API_PORT": "18000", "DEV_FRONTEND_PORT": "13000", "DATABASE_URL": DATABASE_URL}
    monkeypatch.setattr(dev_prepared, "require_project", Mock(return_value="fixture-npm"))
    monkeypatch.setattr(dev_prepared, "prepared_legacy_environment", Mock(return_value=env))
    monkeypatch.setattr(dev, "verify_data_connectivity", Mock())
    monkeypatch.setattr(dev, "verify_existing_schema", Mock(return_value="fixture-current-head"))
    monkeypatch.setattr(dev, "ensure_mailpit_ready", Mock())
    monkeypatch.setattr(dev, "legacy_https_context", Mock(return_value=object()))
    monkeypatch.setattr(dev, "check_application_ports", Mock())
    launch = Mock(return_value=([], env))
    supervise = Mock()
    monkeypatch.setattr(dev, "launch_services", launch)
    monkeypatch.setattr(dev, "supervise_runtime", supervise)
    forbidden = forbidden_mutation(monkeypatch)
    before = snapshot(checkout)
    dev.start_application(SimpleNamespace(profile="legacy", check=False))
    dev_prepared.require_project.assert_called_once_with(dev)
    dev_prepared.prepared_legacy_environment.assert_called_once_with(dev, "managed")
    dev.verify_data_connectivity.assert_called_once_with(env)
    dev.verify_existing_schema.assert_called_once_with(env)
    dev.ensure_mailpit_ready.assert_called_once_with()
    launch.assert_called_once()
    supervise.assert_called_once_with(None, env, [])
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


def test_fresh_managed_docker_never_adopts_default_credentials_or_unknown_volumes(checkout, monkeypatch):
    monkeypatch.setattr(dev, "read_config", lambda: {})
    args = setup_authority(initialize=True)
    args.postgres_provider = "docker"
    forbidden = Mock(
        side_effect=AssertionError("fresh Legacy Docker attempted default credentials or unknown resources")
    )
    for name in (
        "select_service",
        "default_database_url",
        "validate_database_credentials",
        "configure_local_database",
        "ensure_database",
        "generate_keys",
        "write_config",
        "start_compose",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    with pytest.raises(dev.SetupError):
        dev.prepare_managed_legacy(setup_args=args)
    assert not dev.CONFIG.exists()
    forbidden.assert_not_called()


def test_existing_docker_setup_reuses_only_saved_pinned_credentials(checkout, monkeypatch):
    saved = saved_native("docker")
    write_managed(saved)
    before = snapshot(checkout)
    monkeypatch.setattr(dev, "read_config", lambda: dict(saved))
    monkeypatch.setattr(dev, "validate_secrets", Mock())
    monkeypatch.setattr(dev, "mailpit_ready", lambda: True)

    def select(service, docker_port, local_port, *, check, env, preferred):
        assert preferred == "docker" and check is True
        return "Docker", docker_port

    monkeypatch.setattr(dev, "select_service", select)
    validate = Mock(return_value=True)
    monkeypatch.setattr(dev, "validate_database_credentials", validate)
    forbidden = Mock(side_effect=AssertionError("existing Docker setup adopted credentials or rewrote private state"))
    for name in (
        "default_database_url",
        "configure_local_database",
        "read_postgres_credentials",
        "ensure_database",
        "generate_keys",
        "write_config",
        "start_compose",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    env = dev.prepare_managed_legacy(setup_args=setup_authority())
    assert env["DATABASE_URL"] == saved["DATABASE_URL"]
    validate.assert_called_once_with(saved["DATABASE_URL"], allow_missing=False)
    assert snapshot(checkout) == before
    forbidden.assert_not_called()


def test_bounded_reader_refuses_symlink_without_reading_or_changing_target(checkout):
    original = checkout / "fixture-original"
    original.write_text(SECRET, encoding="utf-8")
    link = checkout / "fixture-symlink"
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip("This host does not permit fixture-owned symlinks")
    with pytest.raises(dev_environment.EnvironmentReadError, match="REDIRECTED_FILE"):
        dev_environment.bounded_read_text(link)
    assert original.read_text(encoding="utf-8") == SECRET


def test_bounded_reader_revalidates_opened_file_identity(checkout, monkeypatch):
    path = checkout / "fixture-configuration"
    path.write_text(SECRET, encoding="utf-8")
    original_fstat = os.fstat

    def replaced(fd):
        actual = original_fstat(fd)
        return SimpleNamespace(
            st_mode=actual.st_mode, st_nlink=actual.st_nlink, st_dev=actual.st_dev + 1, st_ino=actual.st_ino
        )

    with monkeypatch.context() as guard:
        guard.setattr(os, "fstat", replaced)
        with pytest.raises(dev_environment.EnvironmentReadError, match="REDIRECTED_FILE"):
            dev_environment.bounded_read_text(path)
    assert path.read_text(encoding="utf-8") == SECRET


def test_missing_local_credentials_are_not_adopted_from_repository_pgpass_or_defaults(checkout, monkeypatch):
    repository = checkout / ".env"
    pgpass = checkout / "fixture-pgpass"
    repository.write_text("DATABASE_URL=" + DATABASE_URL, encoding="utf-8")
    pgpass.write_text("127.0.0.1:5432:*:fixture-other-user:fixture-other-password", encoding="utf-8")
    forbidden = Mock(side_effect=AssertionError("local setup adopted discovered/default credentials"))
    monkeypatch.setattr(dev, "validate_database_credentials", forbidden)
    monkeypatch.setattr(dev, "default_database_url", forbidden)
    with pytest.raises(dev.SetupError):
        dev.resolve_local_database_url(None, 5432, repository_env=repository, pgpass_path=pgpass, interactive=False)
    forbidden.assert_not_called()


@pytest.mark.parametrize("interactive", [False, True])
def test_failed_saved_credentials_never_fall_back_to_repository_or_pgpass(checkout, monkeypatch, interactive):
    repository = checkout / ".env"
    pgpass = checkout / "fixture-pgpass"
    repository.write_text("DATABASE_URL=" + DATABASE_URL.replace("postgres:", "unrelated-user:"), encoding="utf-8")
    pgpass.write_text("127.0.0.1:5432:*:fixture-other-user:fixture-other-password", encoding="utf-8")
    validate = Mock(side_effect=dev.SetupError("Fixture saved credentials were refused"))
    monkeypatch.setattr(dev, "validate_database_credentials", validate)
    with pytest.raises(dev.SetupError):
        dev.resolve_local_database_url(
            DATABASE_URL, 5432, repository_env=repository, pgpass_path=pgpass, interactive=interactive
        )
    validate.assert_called_once_with(DATABASE_URL, allow_missing=False)


def test_fresh_local_setup_validates_only_explicit_operator_credentials(checkout, monkeypatch, capsys):
    validate = Mock(return_value=True)
    monkeypatch.setattr(dev, "validate_database_credentials", validate)
    selected = dev.resolve_local_database_url(
        None,
        5432,
        repository_env=checkout / ".env",
        pgpass_path=checkout / "fixture-pgpass",
        interactive=True,
        input_fn=lambda prompt: "fixture-operator",
        password_fn=lambda prompt: SECRET,
    )
    assert selected == dev.local_database_url("fixture-operator", SECRET, 5432)
    validate.assert_called_once_with(selected, allow_missing=False)
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
