"""Local onboarding safety and recovery; synthetic credentials, --noconftest."""

from __future__ import annotations

import builtins
import json
import os
import struct
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_config, dev_private, dev_setup
from scripts import dev_acl_repair as repair
from scripts import dev_local_postgres as pg
from scripts import dev_local_services as services


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "environ", {})
    return SimpleNamespace(
        ROOT=tmp_path, CONFIG=tmp_path / ".env.dev.local", DB_NAME="sbom_analyser_dev",
        SetupError=dev.SetupError, sys=SimpleNamespace(platform=sys.platform, stdin=SimpleNamespace(isatty=lambda: True)),
        LocalHttps=dev.LocalHttps, _setup_requires=dev._setup_requires,
        _development_library=dev._development_library,
        read_postgres_credentials=Mock(return_value=("synthetic-admin", "synthetic-admin-password-never-save")),
        validate_database_url=dev.validate_database_url,
        validate_database_credentials=Mock(), verify_existing_schema=Mock(),
    )


def args(**overrides):
    values = dict(
        local_database="sbom_analyser_dev_fixture", local_postgres_port=5432,
        confirm_database="sbom_analyser_dev_fixture", initialize_database=True,
        _setup_authorized_categories={"local-postgres-provision", "database-credentials", "database-initialize"},
    )
    values.update(overrides)
    return SimpleNamespace(**values)


class Catalog:
    def __init__(self):
        self.roles, self.database, self.statements, self.failure = {}, None, [], None
        self.connects = []
        self.setup_sessions = False

    def connect(self, record, user, password, *, control=False):
        self.connects.append((user, control))
        self.record = record
        return self

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def transaction(self):
        return nullcontext()

    def close(self):
        pass

    def execute(self, query, parameters=()):
        query = query if isinstance(query, str) else query.as_string(None)
        self.statements.append(query)
        if self.failure and self.failure in query:
            raise RuntimeError("synthetic-private-failure-do-not-log")
        row = None
        if "pg_try_advisory_lock" in query:
            row = (True,)
        elif "rolsuper OR" in query:
            row = (True,)
        elif "SELECT datdba" in query:
            row = self.database
        elif "pg_auth_members" in query:
            row = (False,)
        elif "SELECT EXISTS" in query and "pg_stat_activity" in query:
            row = (self.setup_sessions,)
        elif query.startswith("CREATE ROLE"):
            for kind in ("setup", "runtime"):
                name = self.record[kind + "_user"]
                if '"' + name + '"' in query:
                    self.roles[name] = (kind == "runtime", *pg.ROLE_POLICY[1:], self.record["token"], 10 if kind == "setup" else 11)
        elif query.startswith("ALTER ROLE"):
            name = self.record["setup_user"]
            previous = self.roles[name]
            self.roles[name] = (" NOLOGIN " not in query, *previous[1:])
        elif query.startswith("CREATE DATABASE"):
            self.database = (10,)
        elif "has_schema_privilege" in query:
            row = (False,)
        elif "WHERE rolname=current_user" in query:
            row = (False,) * 5
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: [])


@pytest.fixture
def catalog(monkeypatch):
    state = Catalog()
    monkeypatch.setattr(pg, "_connect", state.connect)
    monkeypatch.setattr(pg, "_role", lambda connection, name: state.roles.get(name))
    return state


def test_provision_uses_separate_restricted_roles_and_never_saves_admin(launcher, catalog, capsys):
    record = pg.provision(args(), launcher)
    persisted = pg.record_path(launcher).read_text()
    assert "synthetic-admin" not in persisted
    assert record["setup_password"] != record["runtime_password"]
    assert record["runtime_password"] not in pg._url(record, "setup")
    assert record["setup_password"] not in pg.runtime_values(record)["DATABASE_URL"]
    assert all("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" in query
               for query in catalog.statements if query.startswith("CREATE ROLE"))
    assert all("DROP " not in query for query in catalog.statements)
    assert catalog.roles[record["setup_user"]][0] is False
    assert all(" NOLOGIN PASSWORD NULL " in query for query in catalog.statements if query.startswith("ALTER ROLE"))
    assert not launcher.CONFIG.exists()
    assert record["setup_password"] not in capsys.readouterr().out


@pytest.mark.parametrize("collision", ["database", "setup-role", "runtime-role"])
def test_unowned_existing_resources_are_never_adopted_or_changed(launcher, catalog, collision):
    if collision == "database":
        catalog.database = (99,)
    else:
        catalog.roles["sbom_analyser_dev_fixture_" + ("setup" if collision == "setup-role" else "app")] = (True,) * 9
    with pytest.raises(dev.SetupError, match="TARGET_EXISTS"):
        pg.provision(args(), launcher)
    assert not pg.record_path(launcher).exists()
    assert not any(q.startswith(("CREATE", "REVOKE", "GRANT", "COMMENT", "ALTER")) for q in catalog.statements)


def test_database_creation_failure_retains_credentials_and_resumes_without_rotation(launcher, catalog):
    catalog.failure = "CREATE DATABASE"
    with pytest.raises(dev.SetupError, match="PROVISION_FAILED"):
        pg.provision(args(), launcher)
    before = pg.record_path(launcher).read_bytes()
    assert "synthetic-admin" not in before.decode()
    roles = dict(catalog.roles)
    catalog.failure = None
    catalog.statements.clear()
    pg.provision(args(), launcher)
    assert pg.record_path(launcher).read_bytes() == before
    assert roles == catalog.roles
    assert not any(q.startswith("CREATE ROLE") for q in catalog.statements)


def test_repeat_provision_has_no_create_or_alter_role_operations(launcher, catalog):
    record = pg.provision(args(), launcher)
    catalog.statements.clear()
    repeated = pg.provision(args(), launcher)
    assert repeated == record
    assert not any(q.startswith("CREATE") for q in catalog.statements)
    assert all(" NOLOGIN PASSWORD NULL " in q for q in catalog.statements if q.startswith("ALTER ROLE"))


@pytest.mark.parametrize("change", ["owner", "role-policy", "token", "target"])
def test_recovery_refuses_record_or_catalog_drift(launcher, catalog, change):
    record = pg.provision(args(), launcher)
    if change == "owner":
        catalog.database = (99,)
    elif change in {"role-policy", "token"}:
        row = list(catalog.roles[record["runtime_user"]])
        row[1 if change == "role-policy" else 7] = True if change == "role-policy" else "wrong-token"
        catalog.roles[record["runtime_user"]] = tuple(row)
    catalog.statements.clear()
    with pytest.raises(dev.SetupError):
        pg.provision(args(local_postgres_port=5433) if change == "target" else args(), launcher)
    assert not any(q.startswith(("CREATE", "REVOKE", "GRANT", "ALTER")) for q in catalog.statements)


def test_missing_provisioning_consent_refuses_before_credential_entry(launcher, catalog):
    with pytest.raises(dev.SetupError, match="APPROVAL_REQUIRED"):
        pg.provision(args(_setup_authorized_categories=set()), launcher)
    launcher.read_postgres_credentials.assert_not_called()
    assert not catalog.statements


@pytest.mark.parametrize("name", ["postgres", "production", "sbom_analyser_dev_../x", "sbom_analyser_dev_;DROP", "sbom_analyser_dev_" + "x" * 25])
def test_database_target_validation_rejects_unrelated_and_unsafe_names(name):
    with pytest.raises(ValueError):
        pg.validate_target(name, 5432)


def test_ambient_libpq_redirect_is_refused_before_connection(monkeypatch):
    import psycopg

    monkeypatch.setenv("PGSERVICE", "unrelated")
    connect = Mock(side_effect=AssertionError("ambient override reached libpq"))
    monkeypatch.setattr(psycopg, "connect", connect)
    with pytest.raises(ValueError, match="AMBIENT"):
        pg._connect({"port": 5432, "database": "sbom_analyser_dev_fixture"}, "fixture", "fixture")
    connect.assert_not_called()


def test_credential_transition_preserves_exact_other_lines_and_private_backup(launcher, catalog):
    original = (b'# Keep this exact comment\r\nDATABASE_URL="postgresql+psycopg://old:old@127.0.0.1:5432/sbom_analyser_dev_fixture"\r\n'
                b'NATIVE_JWT_PRIVATE_KEY="original-private-key"\r\nAUTH_SESSION_ENCRYPTION_KEY="original-session-key"\r\nCUSTOM="preserve"\r\n')
    dev_private.create_private_file(launcher.CONFIG, original)
    launcher.read_postgres_credentials.return_value = ("new-app", "new-runtime-password")
    pg.transition_credentials(args(), launcher)
    updated = launcher.CONFIG.read_bytes()
    assert updated.splitlines()[0] == original.splitlines()[0]
    assert updated.splitlines()[2:] == original.splitlines()[2:]
    assert b"new-app:new-runtime-password" in updated
    backups = list(launcher.ROOT.glob(".env.dev.local.backup-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == original


def test_failed_credential_validation_preserves_configuration_without_backup(launcher, catalog):
    original = b'DATABASE_URL="postgresql+psycopg://old:old@127.0.0.1:5432/sbom_analyser_dev_fixture"\n'
    dev_private.create_private_file(launcher.CONFIG, original)
    launcher.validate_database_credentials.side_effect = dev.SetupError("fixture-rejected")
    with pytest.raises(dev.SetupError, match="fixture-rejected"):
        pg.transition_credentials(args(), launcher)
    assert launcher.CONFIG.read_bytes() == original
    assert not list(launcher.ROOT.glob("*.backup-*"))


def sid(number):
    return b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<I", number)


def make_acl(*entries):
    aces = b"".join(struct.pack("<BBHI", kind, 0, 8 + len(identity), mask) + identity for kind, mask, identity in entries)
    return struct.pack("<BBHHH", 2, 0, len(aces) + 8, len(entries), 0) + aces


def test_acl_narrowing_removes_only_untrusted_grants_and_never_adds_rights():
    owner, other = sid(1001), sid(1002)
    expected = make_acl((0, 0x1F01FF, owner), (1, 2, other))
    original = make_acl((0, 0x1F01FF, owner), (1, 2, other), (0, 0x120089, other))
    assert repair.narrowed_acl(original, [owner], owner) == expected
    with pytest.raises(ValueError, match="OWNER_ACCESS_REQUIRED"):
        repair.narrowed_acl(make_acl((0, 0x120089, owner)), [owner], owner)


@pytest.mark.parametrize("value", ["..\\.env.dev.local", ".env.dev.local:*", "*.pem", "frontend/certificates/localhost-key.pem.", "frontend/../.env.dev.local", ".git/config", "\\\\server\\share\\.env.dev.local"])
def test_acl_repair_requires_literal_allowlisted_exact_path(tmp_path, value):
    with pytest.raises((ValueError, OSError)):
        repair.exact_path(value, tmp_path)


def test_acl_repair_refuses_hardlink_without_changing_files(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"fixture")
    os.link(original, tmp_path / ".env.dev.local")
    with pytest.raises(ValueError, match="REDIRECTED"):
        repair.exact_path(".env.dev.local", tmp_path)
    assert original.read_bytes() == b"fixture"


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows DACL narrowing and descriptor backup")
def test_native_acl_plan_is_readonly_and_approved_repair_retains_content_and_backup(launcher, monkeypatch):
    path = launcher.CONFIG
    dev_private.create_private_file(path, b"fixture-private-content")
    result = subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:R"], capture_output=True)
    assert result.returncode == 0
    before = path.stat()
    options = SimpleNamespace(repair_private_file=[str(path)], plan=True)
    assert repair.run(options, launcher) == 0
    assert not list(launcher.ROOT.glob(".env.dev.acl-backup-*"))
    with pytest.raises(dev.LocalHttps.HttpsTrustError):
        dev.LocalHttps._windows_access(path, private=True)
    monkeypatch.setattr(builtins, "input", lambda prompt: str(path))
    options.plan = False
    assert repair.run(options, launcher) == 0
    dev.LocalHttps._windows_access(path, private=True)
    assert path.read_bytes() == b"fixture-private-content"
    assert (path.stat().st_ino, path.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    backups = list(launcher.ROOT.glob(".env.dev.acl-backup-*"))
    assert len(backups) == 1
    dev.LocalHttps._windows_access(backups[0], private=True)


@pytest.mark.parametrize("url", ["redis://remote:6379/0", "redis://127.0.0.1:6379/0?ssl_cert_reqs=none", "http://127.0.0.1:6379/0"])
def test_redis_probe_refuses_remote_or_tls_override_before_client_creation(url):
    factory = Mock()
    with pytest.raises(services.LocalServiceError, match="EXPOSURE"):
        services.redis_compatibility(url, client_factory=factory)
    factory.assert_not_called()


def test_redis_lua_failure_is_actionable_and_cleans_only_owned_disposable_keys():
    client = Mock()
    client.ping.return_value = True
    client.set.return_value = True
    client.eval.side_effect = RuntimeError("fixture disabled Lua")
    with pytest.raises(services.LocalServiceError, match="Lua EVAL.*Garnet.*--lua"):
        services.redis_compatibility("redis://127.0.0.1:6379/0", client_factory=lambda _: client)
    keys = client.delete.call_args.args
    assert len(keys) == 6 and all(key.startswith("sbom:dev:compat:") for key in keys)
    client.close.assert_called_once()
    client.flushdb.assert_not_called()
    client.flushall.assert_not_called()


def test_redis_claim_collision_does_not_delete_unowned_keys():
    client = Mock()
    client.ping.return_value, client.set.return_value = True, False
    with pytest.raises(services.LocalServiceError):
        services.redis_compatibility("redis://127.0.0.1:6379/0", client_factory=lambda _: client)
    client.delete.assert_not_called()


@pytest.mark.parametrize("address", ["0.0.0.0", "[::]", "192.0.2.1"])
def test_mailpit_exposure_is_flagged_without_service_changes(address):
    runner = Mock(return_value=SimpleNamespace(returncode=0, stdout=f"TCP {address}:1025 0.0.0.0:0 LISTENING 42\n"))
    with pytest.raises(services.LocalServiceError, match="MAILPIT_EXPOSED"):
        services.mailpit_bindings({1025}, runner=runner)
    assert runner.call_args.args[0] == ["netstat", "-ano", "-p", "tcp"]


def test_mailpit_loopback_listener_validation_is_observational():
    runner = Mock(return_value=SimpleNamespace(returncode=0, stdout="TCP 127.0.0.1:1025 0.0.0.0:0 LISTENING 42\nTCP [::1]:8025 [::]:0 LISTENING 42\n"))
    services.mailpit_bindings({1025, 8025}, runner=runner)


@pytest.mark.parametrize("command", ["start", "diagnose", "status", "stop"])
def test_local_setup_flags_cannot_mutate_via_other_commands(monkeypatch, command):
    monkeypatch.setattr(sys, "argv", ["dev.py", command, "--check-local-services"])
    probe = Mock(side_effect=AssertionError("non-setup ran disposable probes"))
    monkeypatch.setattr(services, "check_local_services", probe)
    with pytest.raises(dev.SetupError, match="only by setup"):
        dev.main()
    probe.assert_not_called()


def test_local_provision_plan_is_strictly_observational(launcher, monkeypatch):
    from scripts import dev_frontend

    launcher.GreenfieldStack = SimpleNamespace(STATE=launcher.ROOT / "absent-state", DB="sbom_greenfield_uuid")
    launcher.select_legacy_configuration = lambda _: "managed"
    launcher.validate_secrets = Mock(side_effect=AssertionError("fresh plan generated or validated nonexistent keys"))
    monkeypatch.setattr(dev_setup, "_dependencies", lambda snapshot, owner, actions, blockers: None)
    monkeypatch.setattr(dev_setup, "_certificates", lambda *unused: None)
    monkeypatch.setattr(dev_frontend, "inspect_workspace", lambda *unused: False)
    monkeypatch.setattr(dev_frontend, "configuration_inputs", lambda *unused: [])
    connection = Mock(side_effect=AssertionError("plan connected to PostgreSQL"))
    probes = Mock(side_effect=AssertionError("plan wrote disposable Redis resources"))
    monkeypatch.setattr(pg, "_connect", connection)
    monkeypatch.setattr(services, "check_local_services", probes)
    options = args(profile="legacy", legacy_config="managed", provision_local_postgres=True, plan=True,
                   migrate=False, provision_greenfield=False, frontend_build=False)
    before = list(launcher.ROOT.iterdir())
    callback = Mock(side_effect=AssertionError("plan prepared state"))
    assert dev_setup.run_setup(options, launcher, callback) == 0
    assert list(launcher.ROOT.iterdir()) == before
    connection.assert_not_called()
    probes.assert_not_called()
    launcher.read_postgres_credentials.assert_not_called()
    callback.assert_not_called()


def test_shared_database_zero_projection_preserves_selected_namespaces():
    from scripts import dev_config, dev_prepared

    saved = dev.resolve_config({}, 5432, 6379, 51025, pg_provider="local", redis_provider="local")
    saved.update(DATABASE_URL="postgresql+psycopg://fixture:fixture@127.0.0.1:5432/sbom_analyser_dev_fixture",
                 DEV_REDIS_DATABASE_MODE="shared-db0", DEV_MAILPIT_UI_PORT="58025",
                 SBOM_DEV_RESOURCE_ID="11111111-1111-4111-8111-111111111111")
    saved["AUTH_SESSION_REDIS_URL"] = saved["REDIS_URL"]
    saved["NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"] = saved["REDIS_URL"]
    snapshot = dict(saved)
    inspected = dev_config.resolve_configuration(profile="legacy", family="managed", inherited={}, saved=saved, root=str(dev.ROOT), platform="win32")
    ports = dev_prepared._managed_ports(saved, inspected, dev)
    plan = dev_config.resolve_configuration(profile="legacy", family="managed", inherited={}, saved=saved, ports=ports, purpose="startup", root=str(dev.ROOT), platform="win32")
    assert plan.environment["AUTH_SESSION_REDIS_URL"] == "redis://127.0.0.1:6379/0"
    assert plan.environment["NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"] == "redis://127.0.0.1:6379/0"
    assert plan.environment["SMTP_PORT"] == "51025"
    assert plan.environment["SBOM_DEV_RESOURCE_ID"] == saved["SBOM_DEV_RESOURCE_ID"]
    assert plan.environment["APP_ENVIRONMENT"] == "development"
    assert plan.environment["PYTHON_DOTENV_DISABLED"] == "1"
    assert saved == snapshot


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows exact-file consent")
def test_declined_acl_repair_does_not_write_backups_or_change_content(launcher, monkeypatch):
    dev_private.create_private_file(launcher.CONFIG, b"fixture")
    with repair.pinned_target(launcher.CONFIG) as (original, _, _):
        before = original
    monkeypatch.setattr(builtins, "input", lambda _: "yes")
    assert repair.run(SimpleNamespace(repair_private_file=[str(launcher.CONFIG)], plan=False), launcher) == 1
    assert not list(launcher.ROOT.glob(".env.dev.acl-backup-*"))
    with repair.pinned_target(launcher.CONFIG) as (original, _, _):
        assert original == before


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows backup failure recovery")
def test_acl_backup_failure_never_applies_permission_changes(launcher, monkeypatch):
    dev_private.create_private_file(launcher.CONFIG, b"fixture")
    with repair.pinned_target(launcher.CONFIG) as (original, _, _):
        before = original
    monkeypatch.setattr(builtins, "input", lambda _: str(launcher.CONFIG))
    monkeypatch.setattr(dev_private, "create_private_file", Mock(side_effect=OSError("fixture backup failure")))
    with pytest.raises(dev.SetupError, match="ACL_REPAIR_UNVERIFIED"):
        repair.run(SimpleNamespace(repair_private_file=[str(launcher.CONFIG)], plan=False), launcher)
    with repair.pinned_target(launcher.CONFIG) as (original, _, _):
        assert original == before


def test_completed_record_initialization_checks_schema_without_rebootstrapping(launcher, catalog, monkeypatch):
    record = pg.provision(args(), launcher)
    bootstrap = Mock(side_effect=AssertionError("completed database was bootstrapped again"))
    launcher._development_library = lambda name: SimpleNamespace(bootstrap=bootstrap)
    execute = catalog.execute

    def populated(query, parameters=()):
        if isinstance(query, str) and "SELECT EXISTS (SELECT 1 FROM pg_class" in query:
            return SimpleNamespace(fetchone=lambda: (True,))
        return execute(query, parameters)

    monkeypatch.setattr(catalog, "execute", populated)
    pg.bootstrap_record(record, launcher, args=args())
    bootstrap.assert_not_called()
    launcher.verify_existing_schema.assert_called_once_with({"DATABASE_URL": pg._url(record, "setup")})


def test_external_runtime_password_transition_retains_setup_recovery_and_target(launcher, catalog):
    record = pg.provision(args(), launcher)
    original_record = pg.record_path(launcher).read_bytes()
    dev_private.create_private_file(launcher.CONFIG, ('DATABASE_URL=' + json.dumps(pg.runtime_values(record)["DATABASE_URL"]) + '\nCUSTOM="preserve"\n').encode())
    launcher.read_postgres_credentials.return_value = (record["runtime_user"], "externally-renewed-fixture-password")
    pg.transition_credentials(args(), launcher)
    updated = dev_config.parse_managed(launcher.CONFIG.read_text())["DATABASE_URL"]
    assert pg.matches_runtime_target(updated, record)
    assert "externally-renewed-fixture-password" in updated
    assert pg.record_path(launcher).read_bytes() == original_record
    assert pg._url(record, "setup") != updated


def test_legacy_namespaced_heartbeat_requires_matching_runtime_config(tmp_path, monkeypatch):
    namespace = "11111111-1111-4111-8111-111111111111"
    database = "postgresql+psycopg://fixture:fixture@127.0.0.1:5432/sbom_analyser_dev_fixture"
    config = tmp_path / ".env.dev.local"
    dev_private.create_private_file(config, ''.join(f'{key}={json.dumps(value)}\n' for key, value in {
        "SBOM_DEV_RESOURCE_ID": namespace, "DATABASE_URL": database, "DEV_REDIS_DATABASE_MODE": "shared-db0",
    }.items()).encode())
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "CONFIG", config)
    writer = Mock()
    monkeypatch.setattr(dev, "atomic_json", writer)
    environment = {
        "SBOM_DEV_RESOURCE_ID": namespace, "SBOM_DEV_INSTANCE": "fixture-launch", "SBOM_DEV_STATE_DIR": str(tmp_path / ".dev-logs"),
        "SBOM_DEV_PROFILE": "legacy", "DATABASE_URL": database, "APP_ENVIRONMENT": "development", "PYTHON_DOTENV_DISABLED": "1",
    }
    dev.write_service_heartbeat(environment, "beat", scheduled_tasks=2)
    assert writer.call_args.args[0] == tmp_path / ".dev-logs/beat-health.json"
    writer.reset_mock()
    with pytest.raises(dev.OwnershipError, match="unverified"):
        dev.write_service_heartbeat({**environment, "DATABASE_URL": database.replace("fixture:fixture", "other:other")}, "beat")
    writer.assert_not_called()


def test_recovery_password_cannot_open_setup_outside_approved_window(launcher, catalog):
    record = pg.provision(args(), launcher)
    with pytest.raises(pg.LocalPostgresError, match="WINDOW_REQUIRED"):
        pg.setup_url(record)
    with pytest.raises(dev.SetupError, match="APPROVAL_REQUIRED"):
        with pg.setup_window(record, args(_setup_authorized_categories=set()), launcher):
            pytest.fail("unapproved window opened")
    assert catalog.roles[record["setup_user"]][0] is False


def test_approved_window_is_bounded_and_revokes_login_password_and_sessions(launcher, catalog):
    record = pg.provision(args(), launcher)
    before = pg.record_path(launcher).read_bytes()
    catalog.statements.clear()
    with pg.setup_window(record, args(), launcher):
        assert catalog.roles[record["setup_user"]][0] is True
        assert pg.setup_url(record) == pg._url(record, "setup")
        enable = next(q for q in catalog.statements if " LOGIN PASSWORD " in q)
        assert " VALID UNTIL " in enable and "::timestamptz" not in enable and "infinity" not in enable
    assert catalog.roles[record["setup_user"]][0] is False
    assert catalog.roles[record["runtime_user"]][0] is True
    assert pg.record_path(launcher).read_bytes() == before
    assert "NOLOGIN PASSWORD NULL" in catalog.statements[-2]
    assert "pg_terminate_backend(pid,2000)" in catalog.statements[-1]
    with pytest.raises(pg.LocalPostgresError, match="WINDOW_REQUIRED"):
        pg.setup_url(record)


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_or_cancelled_window_disables_setup_and_preserves_recovery(launcher, catalog, failure):
    record = pg.provision(args(), launcher)
    before = pg.record_path(launcher).read_bytes()
    expected = dev.SetupError if failure is RuntimeError else failure
    with pytest.raises(expected):
        with pg.setup_window(record, args(), launcher):
            raise failure("fixture-private-exception")
    assert catalog.roles[record["setup_user"]][0] is False
    assert pg.record_path(launcher).read_bytes() == before
    assert pg._ACTIVE_SETUP.get() is None


def test_cleanup_reconnects_after_losing_administrator_connection(launcher, catalog, monkeypatch):
    record = pg.provision(args(), launcher)
    execute = catalog.execute
    closing = False
    dropped = False

    def disconnect(query, parameters=()):
        nonlocal dropped
        text = query if isinstance(query, str) else query.as_string(None)
        if closing and "NOLOGIN PASSWORD NULL" in text and not dropped:
            dropped = True
            raise OSError("fixture dropped connection")
        return execute(query, parameters)

    monkeypatch.setattr(catalog, "execute", disconnect)
    with pg.setup_window(record, args(), launcher):
        closing = True
    assert dropped and catalog.roles[record["setup_user"]][0] is False
    assert sum(control for _, control in catalog.connects) >= 3


def test_uncertain_login_enable_still_runs_disable_cleanup(launcher, catalog, monkeypatch):
    record = pg.provision(args(), launcher)
    execute = catalog.execute

    def lost_ack(query, parameters=()):
        text = query if isinstance(query, str) else query.as_string(None)
        result = execute(query, parameters)
        if " LOGIN PASSWORD " in text:
            raise OSError("fixture enable committed but reply lost")
        return result

    monkeypatch.setattr(catalog, "execute", lost_ack)
    with pytest.raises(dev.SetupError, match="WINDOW_FAILED"):
        with pg.setup_window(record, args(), launcher):
            pytest.fail("uncertain enable yielded")
    assert catalog.roles[record["setup_user"]][0] is False


def test_migration_window_uses_setup_only_for_migration_and_cleans_failure(launcher, catalog):
    record = pg.provision(args(), launcher)
    original = {"DATABASE_URL": pg.runtime_values(record)["DATABASE_URL"], "CUSTOM": "preserve"}
    launcher.validate_existing_schema = Mock()
    launcher.run_migrations = Mock(side_effect=RuntimeError("fixture migration failed"))
    options = args(initialize_database=False, migrate=True, _setup_authorized_categories={"database-migrate"})
    with pytest.raises(dev.SetupError, match="WINDOW_FAILED"):
        pg.migrate_record(record, options, original, launcher)
    assert original["DATABASE_URL"] == pg.runtime_values(record)["DATABASE_URL"]
    assert launcher.run_migrations.call_args.args[0]["DATABASE_URL"] == pg._url(record, "setup")
    assert launcher.run_migrations.call_args.args[0]["APP_ENVIRONMENT"] == "development"
    assert launcher.run_migrations.call_args.args[0]["PYTHON_DOTENV_DISABLED"] == "1"
    assert catalog.roles[record["setup_user"]][0] is False


def test_legacy_login_is_closed_only_through_approved_recovery(launcher, catalog):
    record = pg.provision(args(), launcher)
    row = catalog.roles[record["setup_user"]]
    catalog.roles[record["setup_user"]] = (True, *row[1:])
    catalog.statements.clear()
    environment = pg.runtime_values(record)
    with pytest.raises(dev.SetupError, match="SETUP_UNLOCKED"):
        pg.verify_setup_locked(environment, launcher)
    assert not any(q.startswith("ALTER") for q in catalog.statements)
    with pg.setup_window(record, args(), launcher):
        pass
    pg.verify_setup_locked(environment, launcher)
    assert catalog.roles[record["setup_user"]][0] is False


def test_window_refuses_wrong_confirmation_and_ownership_before_unlock(launcher, catalog):
    record = pg.provision(args(), launcher)
    launcher.read_postgres_credentials.reset_mock()
    with pytest.raises(dev.SetupError, match="CONFIRMATION_REQUIRED"):
        with pg.setup_window(record, args(confirm_database="another"), launcher):
            pytest.fail("wrong confirmation opened window")
    launcher.read_postgres_credentials.assert_not_called()
    catalog.database = (999,)
    catalog.statements.clear()
    with pytest.raises(dev.SetupError, match="IDENTITY_CHANGED"):
        with pg.setup_window(record, args(), launcher):
            pytest.fail("foreign owner opened window")
    assert not any(q.startswith("ALTER") for q in catalog.statements)


def test_failed_cleanup_is_a_blocker_and_cannot_be_reported_as_success(launcher, catalog, monkeypatch):
    record = pg.provision(args(), launcher)
    execute = catalog.execute
    closing = False

    def fail_close(query, parameters=()):
        text = query if isinstance(query, str) else query.as_string(None)
        if closing and "NOLOGIN PASSWORD NULL" in text:
            raise OSError("fixture administrator unavailable")
        return execute(query, parameters)

    monkeypatch.setattr(catalog, "execute", fail_close)
    with pytest.raises(dev.SetupError, match="CLEANUP_UNCONFIRMED"):
        with pg.setup_window(record, args(), launcher):
            closing = True
    assert pg._ACTIVE_SETUP.get() is None
    with pytest.raises(dev.SetupError, match="SETUP_UNLOCKED"):
        pg.verify_setup_locked(pg.runtime_values(record), launcher)


def test_runtime_refuses_residual_setup_sessions_even_with_nologin(launcher, catalog):
    record = pg.provision(args(), launcher)
    catalog.setup_sessions = True
    catalog.statements.clear()
    with pytest.raises(dev.SetupError, match="SETUP_UNLOCKED"):
        pg.verify_setup_locked(pg.runtime_values(record), launcher)
    assert not any(q.startswith("ALTER") for q in catalog.statements)


def test_start_refuses_open_setup_access_before_launching_any_process(launcher, monkeypatch):
    from scripts import dev_prepared

    dev_private.create_private_file(pg.record_path(launcher), b"fixture existence marker only")
    monkeypatch.setattr(dev, "ROOT", launcher.ROOT)
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    monkeypatch.setattr(dev_prepared, "require_project", Mock(return_value="npm"))
    monkeypatch.setattr(dev_prepared, "prepared_legacy_environment", Mock(return_value={"DATABASE_URL": "fixture"}))
    monkeypatch.setattr(dev, "verify_data_connectivity", Mock())
    monkeypatch.setattr(pg, "verify_setup_locked", Mock(side_effect=dev.SetupError("LOCAL_POSTGRES_SETUP_UNLOCKED")))
    launch = Mock(side_effect=AssertionError("process launched with open setup access"))
    monkeypatch.setattr(dev, "launch_services", launch)
    with pytest.raises(dev.SetupError, match="SETUP_UNLOCKED"):
        dev.start_application(SimpleNamespace(profile="legacy", check=False))
    launch.assert_not_called()
