"""Safety improvements from main, adapted to the consolidated architecture."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from scripts import dev
from scripts.dev import Runtime

REPOSITORY = Path(dev.__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch, tmp_path):
    for name in dev.REQUIRED_FILES:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "CONFIG", tmp_path / ".env.dev.local")
    monkeypatch.setattr(dev, "Runtime", lambda root: Runtime(tmp_path))
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    monkeypatch.setattr(dev, "VERBOSE", False)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda: None)


def installation(monkeypatch, home):
    state = home / ".sbom-greenfield-uuid"
    state.mkdir()
    for name in ("environment.json", "runtime-password", "setup-password", "docker-identities.json"):
        (state / name).write_text("synthetic")
    monkeypatch.setattr(dev.Path, "home", lambda: home)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", state)
    return state


def test_cli_surface_is_unchanged() -> None:
    assert dev.parse_args([]).command == "start"
    assert dev.parse_args([]).profile == "auto"
    for command in ("start", "stop", "restart", "status"):
        assert dev.parse_args([command, "--profile", "legacy"]).command == command
    args = dev.parse_args(["--check", "--verbose", "--profile", "greenfield"])
    assert (args.check, args.verbose, args.profile) == (True, True, "greenfield")
    assert dev.parse_args(["doctor"]).command == "doctor"
    assert dev.parse_args(["diagnose"]).command == "diagnose"
    assert dev.parse_args(["setup"]).command == "setup"
    assert dev.parse_args(["logs"]).command == "logs"


@pytest.mark.parametrize("platform", ["win32", "linux", "darwin"])
def test_auto_profile_never_falls_back_when_greenfield_is_installed(monkeypatch, tmp_path, platform):
    installation(monkeypatch, tmp_path)
    monkeypatch.setattr(dev.sys, "platform", platform)
    assert dev.resolve_profile("auto") == "greenfield"


@pytest.mark.parametrize("platform", ["win32", "linux"])
@pytest.mark.parametrize("command", ["start", "restart", "status", "--check"])
def test_explicit_greenfield_selection_is_separate_from_native_trust_acceptance(
    monkeypatch, tmp_path, platform, command
):
    installation(monkeypatch, tmp_path)
    monkeypatch.setattr(dev.sys, "platform", platform)
    assert dev.resolve_profile("greenfield") == "greenfield"
    assert dev.control_profile("greenfield") == "greenfield"


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_greenfield_native_trust_failure_precedes_container_operations(monkeypatch, tmp_path, platform):
    installation(monkeypatch, tmp_path)
    monkeypatch.setattr(dev.sys, "platform", platform)
    monkeypatch.setattr(
        dev.LocalHttps, "ensure_certificate", MagicMock(side_effect=dev.LocalHttps.HttpsTrustError("unapproved trust"))
    )
    inventory = MagicMock(side_effect=AssertionError("container operation before trust"))
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", inventory)
    assert dev.doctor(dev.parse_args(["doctor", "--profile", "greenfield"])) == 1
    dev.LocalHttps.ensure_certificate.assert_called_once()
    inventory.assert_not_called()


def test_old_python_is_refused_before_virtualenv(monkeypatch, capsys) -> None:
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start", "--profile", "legacy"])
    monkeypatch.setattr(dev.sys, "version_info", (3, 10, 14, "final", 0))
    monkeypatch.setattr(dev.sys, "prefix", str(dev.ROOT / "system-python"))  # Not running inside .venv.
    monkeypatch.setattr(dev, "venv_python", lambda: dev.ROOT / "absent/python")  # No .venv to hand off to.
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: pytest.fail("venv created by an unsupported Python"))
    assert dev.cli() == 1
    assert "Python 3.10.14 is too old" in capsys.readouterr().err


def test_old_launcher_python_hands_off_to_an_existing_venv(monkeypatch, tmp_path) -> None:
    # A supported .venv checks its own interpreter after the handoff.
    python = tmp_path / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setattr(dev, "venv_python", lambda: python)
    monkeypatch.setattr(dev.sys, "prefix", str(tmp_path / "system-python"))
    monkeypatch.setattr(dev.sys, "version_info", (3, 9, 6, "final", 0))
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start", "--profile", "legacy"])
    handoff = MagicMock(side_effect=SystemExit(0))
    monkeypatch.setattr(dev, "ensure_virtualenv", handoff)
    with pytest.raises(SystemExit):
        dev.main()
    handoff.assert_called_once_with()


def test_old_python_inside_existing_venv_explains_recreation(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setattr(dev.sys, "prefix", str(tmp_path / ".venv"))
    with pytest.raises(dev.SetupError, match="existing .venv uses Python 3.10.0"):
        dev.validate_python_version((3, 10, 0))
    dev.validate_python_version((3, 11, 0))


def test_incomplete_checkout_is_refused_before_any_setup(monkeypatch, capsys) -> None:
    (dev.ROOT / "frontend/package-lock.json").unlink()
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "--check", "--profile", "legacy"])
    monkeypatch.setattr(dev, "start_application", lambda args: pytest.fail("setup started"))
    assert dev.main() == 1
    output = capsys.readouterr()
    assert "FAIL" in output.out
    assert not (dev.ROOT / ".venv").exists()


@pytest.mark.parametrize("command", ["stop", "status"])
def test_stop_and_status_do_not_require_a_complete_checkout(monkeypatch, command) -> None:
    (dev.ROOT / "requirements.txt").unlink()
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", command, "--profile", "legacy"])
    calls = []
    monkeypatch.setattr(dev, "stop_application", lambda: calls.append("stop"))
    monkeypatch.setattr(dev, "application_status", lambda *args: calls.append("status"))
    dev.main()
    assert calls == [command]


def test_cli_maps_outcomes_to_exit_codes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(dev, "main", lambda: None)
    assert dev.cli() == 0
    monkeypatch.setattr(dev, "main", MagicMock(side_effect=KeyboardInterrupt))
    assert dev.cli() == 130
    monkeypatch.setattr(dev, "main", MagicMock(side_effect=dev.SetupError("readable reason")))
    assert dev.cli() == 1
    assert "[ERROR] readable reason" in capsys.readouterr().err


def test_failed_setup_command_tail_is_redacted(capsys) -> None:
    secret = "super-secret-password"
    output = "\n".join(f"line {number}" for number in range(50)) + f"\nconnecting with {secret}"
    dev.explain_failed_command(SimpleNamespace(returncode=1, stdout=output, stderr=""), {"POSTGRES_PASSWORD": secret})
    error = capsys.readouterr().err
    assert secret not in error and "[REDACTED]" in error
    assert "line 16" in error and "line 15" not in error  # Only the last 35 lines.


def test_failed_setup_command_tail_is_silent_on_success_or_verbose(monkeypatch, capsys) -> None:
    dev.explain_failed_command(SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(dev, "VERBOSE", True)  # Verbose mode already streamed the output.
    dev.explain_failed_command(SimpleNamespace(returncode=1, stdout="failed", stderr=""))
    assert capsys.readouterr().err == ""


def test_pip_failure_reports_detail_and_keeps_stamp_unset(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setitem(dev.sys.modules, "celery", None)  # A missing import forces installation.
    failure = SimpleNamespace(returncode=1, stdout="", stderr="No matching distribution")
    monkeypatch.setattr(dev, "run", lambda command: failure)
    with pytest.raises(dev.SetupError, match="Python dependency installation failed"):
        dev.ensure_dependencies()
    assert "No matching distribution" in capsys.readouterr().err
    assert not (tmp_path / ".venv/.sbom-requirements-sha256").exists()


def test_service_logs_stay_behind_verbose(capsys) -> None:
    path = dev.log_path("API")
    path.parent.mkdir()
    path.write_text("Authorization: Bearer runtime-token")
    dev.show_log("API", {})
    assert "runtime-token" not in capsys.readouterr().err


def test_child_output_is_decoded_as_utf8(monkeypatch) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(dev.subprocess, "run", fake_run)
    dev.run(["tool"])
    assert (captured["encoding"], captured["errors"]) == ("utf-8", "replace")


@pytest.mark.parametrize(
    ("output", "expected"),
    [("v22.11.0\n", (22, 11, 0)), ("v20.9.0", (20, 9, 0)), ("v23.0.0-rc.1", (23, 0, 0)), ("garbage", None)],
)
def test_node_version_is_parsed(monkeypatch, output, expected) -> None:
    monkeypatch.setattr(dev.shutil, "which", lambda name: "node")
    monkeypatch.setattr(dev, "run", lambda command: SimpleNamespace(returncode=0, stdout=output, stderr=""))
    assert dev.node_version() == expected


def test_node_requirement_matches_locked_next_release() -> None:
    import json

    lock = json.loads((REPOSITORY / "frontend/package-lock.json").read_text(encoding="utf-8"))
    engines = lock["packages"]["node_modules/next"]["engines"]["node"]
    assert engines == ">=" + ".".join(str(part) for part in dev.MIN_NODE)
    assert dev.node_problem((20, 8, 1)) and dev.node_problem(None)
    assert dev.node_problem((20, 9, 0)) is None and dev.node_problem((24, 0, 0)) is None


@pytest.mark.parametrize(
    "result", [OSError("synthetic missing runtime"), SimpleNamespace(returncode=1, stdout="v24.0.0")]
)
def test_unusable_node_is_an_actionable_prerequisite_failure(monkeypatch, result):
    run = MagicMock(side_effect=result) if isinstance(result, Exception) else MagicMock(return_value=result)
    monkeypatch.setattr(dev, "run", run)
    assert dev.node_version() is None
    assert "Install Node.js" in dev.node_problem(dev.node_version())


def test_old_node_is_refused_before_npm_ci(monkeypatch) -> None:
    monkeypatch.setattr(dev.shutil, "which", lambda name: name)
    monkeypatch.setattr(dev, "node_version", lambda: (20, 5, 1))
    monkeypatch.setattr(dev, "run", lambda command: pytest.fail("npm ci ran with an unsupported Node.js"))
    with pytest.raises(dev.SetupError, match="Node.js 20.5.1 is too old"):
        dev.ensure_frontend()


def test_legacy_worker_matches_production_queue_set(monkeypatch):
    compose = (REPOSITORY / "docker-compose.server.yml").read_text()
    assert '"--queues=celery,reports"' in compose
    routes = (REPOSITORY / "app/workers/celery_app.py").read_text()
    assert '"report_notifications.*": {"queue": "reports"}' in routes
    for platform, pool in (("linux", "prefork"), ("win32", "solo"), ("darwin", "solo")):
        monkeypatch.setattr(dev.sys, "platform", platform)
        commands = dev.background_commands(
            {"SBOM_DEV_INSTANCE": "synthetic", "SBOM_DEV_PROFILE": "legacy", "SBOM_DEV_STATE_DIR": str(dev.ROOT)}
        )
        assert "--queues=celery" in commands["Celery worker"]
        assert "--queues=reports" in commands["Celery reports worker"]
        assert "--pool=" + pool in commands["Celery worker"]
        assert "beat" in commands["Celery Beat"]
        assert not any("--beat" in value for value in commands.values())


def test_untrusted_env_cannot_add_identity_providers_or_keys() -> None:
    saved = {"ENTRA_ENABLED": "true", "NATIVE_JWT_VERIFICATION_KEYS_JSON": '{"other": "key"}'}
    values = dev.resolve_config(saved, dev.POSTGRES_PORT, dev.REDIS_PORT, dev.MAILPIT_SMTP_PORT)
    assert values["ENTRA_ENABLED"] == "false"
    assert values["NATIVE_JWT_VERIFICATION_KEYS_JSON"] == "{}"
    assert values["HCL_AUTH_ENABLED"] == "false" and values["NATIVE_AUTH_ENABLED"] == "true"


def test_beat_lock_never_signals_a_recorded_pid(monkeypatch, tmp_path) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("4242")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev.os, "kill", lambda *args: pytest.fail("os.kill is not a liveness probe on Windows"))
    monkeypatch.setattr(dev, "process_info", lambda pid: None)  # Exited: the stale lock is reclaimed.
    dev.acquire_beat_lock()
    assert lock.read_text() == str(dev.os.getpid())


@pytest.mark.parametrize("probe", [lambda pid: {"pid": pid}, MagicMock(side_effect=dev.OwnershipError("denied"))])
def test_live_or_uninspectable_beat_owner_is_kept(monkeypatch, tmp_path, probe) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("4242")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev, "process_info", probe)
    with pytest.raises(dev.SetupError, match="already owns Celery Beat"):
        dev.acquire_beat_lock()
    assert lock.read_text() == "4242"


def test_malformed_beat_lock_is_reclaimed(monkeypatch, tmp_path) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("not-a-pid")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev, "process_info", lambda pid: pytest.fail("no lookup for a malformed PID"))
    dev.acquire_beat_lock()
    assert lock.read_text() == str(dev.os.getpid())


@pytest.mark.parametrize(
    ("platform", "hint"),
    [("win32", "netstat -ano | findstr :18000"), ("darwin", "lsof -nP -iTCP:18000 -sTCP:LISTEN")],
)
def test_port_conflicts_suggest_read_only_inspection(monkeypatch, platform, hint) -> None:
    monkeypatch.setattr(dev.sys, "platform", platform)
    assert hint in dev.port_diagnostic(18000)
    assert "ownership: unrelated/unknown" in dev.port_diagnostic(18000)


@pytest.mark.parametrize(
    ("platform", "command"), [("nt", "python scripts/dev.py"), ("posix", "python3 scripts/dev.py")]
)
def test_launcher_hint_uses_platform_python(platform, command) -> None:
    assert dev.launcher_command(platform) == command


def test_identity_tables_match_revision_100_guard() -> None:
    from app.public_identity import TABLES

    assert dev.PUBLIC_IDENTITY_TABLES == TABLES


def test_pre_uuid_revisions_are_strict_ancestors_of_revision_100() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(REPOSITORY / "alembic.ini")))
    ancestors = dev.pre_uuid_revisions(script)
    assert {"079_lifecycle_provider_verification", "078_finding_reconciliation"} <= ancestors
    assert dev.GREENFIELD_UUID_BASELINE not in ancestors
    assert not {"101_iam_user_public_uuid", "103_tenant_admin_governance"} & ancestors


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0]

    def __iter__(self):
        return iter(self.rows)


class FakeConnection:
    """Catalogue double: records every statement and fails on anything but a read-only SELECT."""

    def __init__(self, revision, populated):
        self.revision = revision
        self.populated = populated
        self.statements = []
        self.read_only = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, params=None):
        assert self.read_only, "schema inspection must use a read-only session"
        assert statement.lstrip().upper().startswith("SELECT"), statement
        self.statements.append(statement)
        if "pg_class" in statement:
            tables = ["alembic_version", "iam_users", *dev.PUBLIC_IDENTITY_TABLES]
            return FakeCursor([("public", table) for table in tables])
        if "alembic_version" in statement:
            return FakeCursor([(self.revision,)])
        table = statement.split('public."')[1].split('"')[0]
        return FakeCursor([(table in self.populated,)])


def inspect_schema(monkeypatch, revision, populated):
    connection = FakeConnection(revision, populated)
    monkeypatch.setitem(dev.sys.modules, "psycopg", SimpleNamespace(connect=lambda url: connection, Error=Exception))
    monkeypatch.setattr(dev, "ROOT", REPOSITORY)
    dev.validate_existing_schema("postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_dev")
    return connection


@pytest.mark.parametrize("revision", ["079_lifecycle_provider_verification", "078_finding_reconciliation"])
def test_populated_pre_uuid_database_is_refused_before_alembic(monkeypatch, revision) -> None:
    with pytest.raises(dev.SetupError, match=rf"pre-UUID revision {revision} and has rows in tenants, sbom_component"):
        inspect_schema(monkeypatch, revision, {"tenants", "sbom_component"})


def test_empty_pre_uuid_identity_tables_may_continue(monkeypatch) -> None:
    connection = inspect_schema(monkeypatch, "079_lifecycle_provider_verification", set())
    assert sum("SELECT EXISTS" in statement for statement in connection.statements) == len(dev.PUBLIC_IDENTITY_TABLES)


@pytest.mark.parametrize("revision", ["100_greenfield_uuid_final", "103_tenant_admin_governance"])
def test_uuid_databases_skip_the_row_probe(monkeypatch, revision) -> None:
    connection = inspect_schema(monkeypatch, revision, {"tenants"})
    assert not any("SELECT EXISTS" in statement for statement in connection.statements)


def test_refused_pre_uuid_database_never_reaches_migrations(monkeypatch):
    env = {"DATABASE_URL": "postgresql+psycopg://test:synthetic@127.0.0.1:55439/sbom_analyser_dev"}
    for name in ("ensure_virtualenv", "ensure_dependencies", "ensure_frontend", "legacy_https_context"):
        monkeypatch.setattr(dev, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(dev, "prepare_managed_legacy", lambda: env)
    monkeypatch.setattr(
        dev, "validate_existing_schema", MagicMock(side_effect=dev.SetupError("pre-UUID revision refused"))
    )
    upgrade = MagicMock(side_effect=AssertionError("Alembic after refusal"))
    monkeypatch.setattr(dev, "run_migrations", upgrade)
    with pytest.raises(dev.SetupError, match="pre-UUID revision refused"):
        dev.setup_application(
            dev.parse_args(["setup", "--profile", "legacy", "--migrate", "--confirm-database", "sbom_analyser_dev"])
        )
    upgrade.assert_not_called()


def test_compose_failure_detail_only_when_no_local_fallback(monkeypatch, capsys) -> None:
    failure = SimpleNamespace(returncode=1, stdout="", stderr="pull access denied")
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "compose_container", lambda service: False)
    monkeypatch.setattr(dev, "reachable", lambda host, port: False)
    monkeypatch.setattr(dev, "run", lambda command, env=None: failure)
    monkeypatch.setattr(dev.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(dev, "service_available", lambda service, port: port == 5432)
    assert dev.select_service("postgres", 55439, 5432, check=False, env={}, preferred=None) == ("local", 5432)
    assert "pull access denied" not in capsys.readouterr().err  # Fallback succeeded: no dump.
    monkeypatch.setattr(dev, "service_available", lambda service, port: False)
    with pytest.raises(dev.SetupError, match="Could not start project postgres"):
        dev.select_service("postgres", 55439, 5432, check=False, env={}, preferred="docker")
    assert "pull access denied" in capsys.readouterr().err
