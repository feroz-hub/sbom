"""Canonical launcher contracts; no installers, containers or application data.

Run this file with the other launcher-only tests and ``--noconftest``. Platform
parameters exercise adapters on the current host, not native OS acceptance.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev


@pytest.fixture
def checkout(monkeypatch, tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    for name in ("requirements.txt", "alembic.ini", "frontend/package.json", "frontend/package-lock.json"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.suffix == ".json" else "synthetic\n")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "VENV", root / ".venv")
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "BEAT_LOCK", root / ".dev-beat.pid")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return root, home


@pytest.fixture
def greenfield_installation(checkout, monkeypatch):
    """Only the metadata guard's required files; all external checks are mocked."""
    root, home = checkout
    state = home / ".sbom-greenfield-uuid"
    state.mkdir(mode=0o700)
    for name, content in {
        "environment.json": "{}",
        "runtime-password": "synthetic-runtime-password",
        "setup-password": "synthetic-setup-password",
    }.items():
        path = state / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", state)
    return state


@pytest.mark.parametrize("command", ["start", "stop", "restart", "status", "diagnose", "doctor", "logs"])
def test_one_public_parser_accepts_all_lifecycle_commands(command):
    assert dev.parse_args([command]).command == command


def test_default_start_and_explicit_profile_are_stable():
    args = dev.parse_args([])
    assert args.command == "start"
    assert dev.parse_args(["--profile", "legacy"]).profile == "legacy"
    assert dev.parse_args(["start", "--profile", "greenfield"]).profile == "greenfield"


def test_public_help_is_available_from_a_clone_without_a_virtualenv(checkout):
    root, _ = checkout
    script = root / "scripts" / "dev.py"
    script.parent.mkdir()
    script.write_bytes(Path(dev.__file__).read_bytes())
    result = subprocess.run(
        [dev.sys.executable, str(script), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "diagnose" in result.stdout and "doctor" in result.stdout
    assert "logs" in result.stdout
    assert "--profile" in result.stdout
    assert not (root / ".venv").exists()


def test_fresh_clone_auto_selects_legacy_without_creating_state(checkout):
    _, home = checkout
    before = list(home.iterdir())
    assert dev.resolve_profile("auto") == "legacy"
    assert list(home.iterdir()) == before


def test_installed_greenfield_auto_selection_reads_no_credentials(checkout, monkeypatch):
    _, home = checkout
    state = home / ".sbom-greenfield-uuid"
    state.mkdir(mode=0o700)
    for name in ("environment.json", "runtime-password", "setup-password"):
        (state / name).write_text("synthetic-private-value")
    monkeypatch.setattr(Path, "read_text", Mock(side_effect=AssertionError("credential contents read")))
    assert dev.resolve_profile("auto") == "greenfield"


@pytest.mark.parametrize("requested", ["auto", "greenfield"])
def test_incomplete_greenfield_never_falls_back_to_legacy(checkout, requested):
    _, home = checkout
    (home / ".sbom-greenfield-uuid").mkdir()
    with pytest.raises(dev.SetupError, match="(?i)(greenfield|incomplete)"):
        dev.resolve_profile(requested)


def test_explicit_greenfield_does_not_bootstrap_an_absent_installation(checkout):
    _, home = checkout
    with pytest.raises(dev.SetupError, match="(?i)(greenfield|install)"):
        dev.resolve_profile("greenfield")
    assert not (home / ".sbom-greenfield-uuid").exists()


def test_explicit_legacy_remains_legacy_with_incomplete_greenfield_state(checkout):
    _, home = checkout
    (home / ".sbom-greenfield-uuid").mkdir()
    assert dev.resolve_profile("legacy") == "legacy"


@pytest.mark.parametrize("active,requested", [("greenfield", "legacy"), ("legacy", "greenfield")])
def test_cross_profile_control_is_refused_before_any_stop(active, requested):
    runtime = Mock()
    runtime.load.return_value = {"profile": active, "services": {"API": {"pid": 123}}}
    with pytest.raises(dev.SetupError, match="(?i)profile"):
        dev.check_profile_ownership(runtime, requested)
    runtime.terminate.assert_not_called()
    runtime.stop_services.assert_not_called()


@pytest.mark.parametrize("profile", ["greenfield", "legacy"])
def test_matching_profile_control_and_empty_state_are_allowed(profile):
    runtime = Mock()
    runtime.load.return_value = {"profile": profile, "services": {}}
    dev.check_profile_ownership(runtime, profile)
    runtime.load.return_value = None
    dev.check_profile_ownership(runtime, profile)


@pytest.mark.parametrize("profile", ["greenfield", "legacy"])
def test_new_runtime_records_its_profile_without_environment(checkout, monkeypatch, profile):
    root, _ = checkout
    monkeypatch.setattr(dev, "process_info", lambda pid: {"pid": pid, "birth": "synthetic", "exe": "/python"})
    monkeypatch.setenv("PRIVATE_TOKEN", "never-persist-this")
    runtime = dev.Runtime(root)
    runtime.begin(profile)
    content = runtime.path.read_text()
    assert json.loads(content)["profile"] == profile
    assert "never-persist-this" not in content


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_posix_spawn_uses_isolated_session(monkeypatch, platform):
    monkeypatch.setattr(dev.sys, "platform", platform)
    options = dev.platform_spawn_options()
    assert options.get("start_new_session") is True
    assert not options.get("creationflags")
    assert not options.get("shell")


def test_windows_spawn_uses_new_process_group_without_posix_session(monkeypatch):
    monkeypatch.setattr(dev.sys, "platform", "win32")
    options = dev.platform_spawn_options()
    assert options.get("creationflags", 0) & 0x200  # CREATE_NEW_PROCESS_GROUP
    assert not options.get("start_new_session")
    assert not options.get("shell")


def test_windows_npm_wrapper_is_replaced_by_node_cli_without_a_shell(checkout, monkeypatch):
    root, _ = checkout
    tools = root / "Program Files" / "nodejs"
    tools.mkdir(parents=True)
    npm = tools / "npm.cmd"
    cli = tools / "node_modules/npm/bin/npm-cli.js"
    cli.parent.mkdir(parents=True)
    cli.touch()
    node = tools / "node.exe"
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: node)
    command = [str(npm), "run", "dev:https", "--", "argument & literal"]
    assert dev.normalize_command(command) == [str(node), str(cli), *command[1:]]


def test_windows_missing_npm_cli_fails_with_repair_instructions(checkout, monkeypatch):
    root, _ = checkout
    monkeypatch.setattr(dev.sys, "platform", "win32")
    with pytest.raises(dev.SetupError, match="(?i)(npm-cli.js|repair)"):
        dev.normalize_command([str(root / "nodejs/npm.cmd"), "ci"])


def test_windows_arbitrary_batch_wrapper_is_not_executed(checkout, monkeypatch):
    root, _ = checkout
    monkeypatch.setattr(dev.sys, "platform", "win32")
    with pytest.raises(dev.SetupError, match="(?i)(native executable|batch)"):
        dev.normalize_command([str(root / "unrelated.bat")])


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_posix_command_arguments_remain_literal(monkeypatch, platform):
    monkeypatch.setattr(dev.sys, "platform", platform)
    command = ["/opt/node/bin/npm", "run", "dev:https", "--", "argument & literal"]
    assert dev.normalize_command(command) == command


@pytest.mark.parametrize("error,code", [(KeyboardInterrupt(), 130), (dev.SetupError("actionable problem"), 1),
                                        (dev.OwnershipError("cannot verify owner"), 1), (RuntimeError("private diagnostics"), 1)])
def test_cli_failure_exit_codes_do_not_expose_secret_values(monkeypatch, capsys, error, code):
    monkeypatch.setattr(dev, "main", Mock(side_effect=error))
    assert dev.cli() == code
    assert "private diagnostics" not in capsys.readouterr().err


def test_cli_actionable_failure_redacts_environment_secret(monkeypatch, capsys):
    monkeypatch.setenv("PRIVATE_TOKEN", "opaque-sensitive-value")
    monkeypatch.setattr(dev, "main", Mock(side_effect=dev.SetupError("failed opaque-sensitive-value")))
    assert dev.cli() == 1
    output = capsys.readouterr().err
    assert "opaque-sensitive-value" not in output
    assert "[REDACTED]" in output


@pytest.fixture
def python_dependencies(checkout, monkeypatch):
    root, _ = checkout
    dev.VENV.mkdir()
    for name in ("alembic", "cryptography", "psycopg", "uvicorn"):
        monkeypatch.setitem(dev.sys.modules, name, SimpleNamespace())
    calls = []

    def install(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dev, "run", install)
    return root, calls, dev.VENV / ".sbom-requirements-sha256"


def test_python_dependency_install_is_reused_when_requirements_unchanged(python_dependencies):
    _, calls, stamp = python_dependencies
    dev.ensure_dependencies()
    assert stamp.is_file()
    dev.ensure_dependencies()
    assert len(calls) == 1
    assert "pip" in calls[0]


def test_changed_requirements_trigger_exactly_one_new_install(python_dependencies):
    root, calls, stamp = python_dependencies
    dev.ensure_dependencies()
    (root / "requirements.txt").write_text("changed-synthetic-requirement\n")
    dev.ensure_dependencies()
    dev.ensure_dependencies()
    assert len(calls) == 2
    assert stamp.read_text().strip() == hashlib.sha256((root / "requirements.txt").read_bytes()).hexdigest()


def test_failed_python_install_does_not_stamp_and_next_run_retries(python_dependencies, monkeypatch):
    _, calls, stamp = python_dependencies
    original = dev.run
    monkeypatch.setattr(dev, "run", lambda command: subprocess.CompletedProcess(command, 1, "", "failed"))
    with pytest.raises(dev.SetupError, match="(?i)(dependency|dependencies|pip)"):
        dev.ensure_dependencies()
    assert not stamp.exists()
    monkeypatch.setattr(dev, "run", original)
    dev.ensure_dependencies()
    assert stamp.is_file()
    assert len(calls) == 1


def test_legacy_logs_tail_is_bounded_and_redacts_saved_credentials(checkout, monkeypatch, capsys):
    root, _ = checkout
    log = root / "api.log"
    log.write_text("old-line\nprivate-password\nrecent-line\n")
    monkeypatch.setattr(dev, "profile_log_paths", lambda profile: {"API": log})
    monkeypatch.setattr(dev, "read_config", lambda *args, **kwargs: {"POSTGRES_PASSWORD": "private-password"})
    dev.display_logs(SimpleNamespace(profile="legacy", lines=2, service="API"))
    output = capsys.readouterr().out
    assert "recent-line" in output
    assert "old-line" not in output
    assert "private-password" not in output
    assert "[REDACTED]" in output


def test_absent_log_is_actionable_without_creating_files(checkout, monkeypatch, capsys):
    root, _ = checkout
    absent = root / "absent.log"
    monkeypatch.setattr(dev, "profile_log_paths", lambda profile: {"API": absent})
    monkeypatch.setattr(dev, "read_config", lambda *args, **kwargs: {})
    dev.display_logs(SimpleNamespace(profile="legacy", lines=5, service="API"))
    output = capsys.readouterr().out
    assert "API" in output
    assert not absent.exists()


def test_logs_reads_only_the_requested_service(checkout, monkeypatch, capsys):
    root, _ = checkout
    api = root / "api.log"
    frontend = root / "frontend.log"
    api.write_text("selected-api-output\n")
    frontend.write_text("unselected-frontend-output\n")
    paths = Mock(return_value={"API": api, "Frontend": frontend})
    monkeypatch.setattr(dev, "profile_log_paths", paths)
    monkeypatch.setattr(dev, "read_config", lambda *args, **kwargs: {})
    dev.display_logs(SimpleNamespace(profile="legacy", lines=5, service="API"))
    output = capsys.readouterr().out
    paths.assert_called_once_with("legacy")
    assert "selected-api-output" in output
    assert "unselected-frontend-output" not in output


@pytest.mark.parametrize("payload", [
    '{"api_key": "synthetic-sensitive-value"}',
    '{"password":"synthetic-sensitive-value"}',
    "{'client_secret': 'synthetic-sensitive-value'}",
    '{"access_token": "synthetic-sensitive-value"}',
    '{"refresh_token": "synthetic-sensitive-value"}',
    '{"api_key_encrypted": "synthetic-sensitive-value"}',
])
def test_quoted_json_and_mapping_secrets_are_redacted_without_environment_values(payload):
    output = dev.redact(payload, {})
    assert "synthetic-sensitive-value" not in output
    assert "[REDACTED]" in output


@pytest.mark.parametrize("large_prefix", [False, True])
def test_log_tail_redacts_multiline_private_key_before_selecting_lines(checkout, monkeypatch, capsys, large_prefix):
    root, _ = checkout
    log = root / "api.log"
    # The large case makes the bounded byte read begin inside the PEM body.
    padding = ("synthetic-private-material\n" * 45000) if large_prefix else "earlier-private-material\n"
    log.write_text("-----BEGIN PRIVATE KEY-----\n" + padding + "sensitive-last-key-line\n-----END PRIVATE KEY-----\nrecent-safe-line\n")
    monkeypatch.setattr(dev, "profile_log_paths", lambda profile: {"API": log})
    monkeypatch.setattr(dev, "read_config", lambda *args, **kwargs: {})
    dev.display_logs(SimpleNamespace(profile="legacy", lines=2, service="API"))
    output = capsys.readouterr().out
    assert "recent-safe-line" in output
    assert "sensitive-last-key-line" not in output
    assert "synthetic-private-material" not in output
    assert "earlier-private-material" not in output
    assert "[REDACTED PRIVATE KEY]" in output


@pytest.mark.parametrize("lines", ["0", "-1", "100001"])
def test_log_tail_rejects_unbounded_or_invalid_line_count(lines):
    with pytest.raises(SystemExit) as error:
        dev.parse_args(["logs", "--lines", lines])
    assert error.value.code == 2


def test_doctor_missing_dependencies_never_installs_or_reads_passwords(checkout, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("doctor attempted mutation or password prompt"))
    for name in ("ensure_virtualenv", "ensure_dependencies", "ensure_frontend", "generate_keys", "ensure_database", "start_process", "read_postgres_credentials"):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev, "read_config", lambda: {})
    monkeypatch.setattr(dev.shutil, "which", lambda name, **kwargs: None)
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", Mock(side_effect=dev.SetupError("Node.js is missing; install Node.js LTS")))
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    assert dev.doctor(dev.parse_args(["doctor", "--profile", "legacy"])) == 1
    forbidden.assert_not_called()


def test_legacy_https_context_verifies_hostname_and_preserves_generated_pair(checkout):
    root, _ = checkout
    cert = root / "frontend/certificates/localhost.pem"
    key = root / "frontend/certificates/localhost-key.pem"
    dev.create_local_certificate(cert, key)
    original = cert.read_bytes(), key.read_bytes()
    context = dev.legacy_https_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.cert_store_stats()["x509"] >= 1
    assert (cert.read_bytes(), key.read_bytes()) == original


def test_legacy_https_incomplete_pair_preserves_existing_key(checkout, monkeypatch):
    root, _ = checkout
    cert = root / "frontend/certificates/localhost.pem"
    key = root / "frontend/certificates/localhost-key.pem"
    key.parent.mkdir()
    key.write_bytes(b"existing-private-key-placeholder")
    modules = root / "frontend/node_modules"
    modules.mkdir()
    manifest = root / "frontend/package.json"
    lock = root / "frontend/package-lock.json"
    digest = hashlib.sha256(manifest.read_bytes() + b"\0" + lock.read_bytes()).hexdigest()
    (modules / ".sbom-dependencies-sha256").write_text(digest)
    monkeypatch.setattr(dev.shutil, "which", lambda name, **kwargs: "npm")
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: root / "node")
    forbidden = Mock(side_effect=AssertionError("existing key replacement attempted"))
    monkeypatch.setattr(dev, "create_local_certificate", forbidden)
    monkeypatch.setattr(dev, "run", forbidden)
    with pytest.raises(dev.SetupError, match="(?i)(incomplete|pair)"):
        dev.ensure_frontend()
    assert key.read_bytes() == b"existing-private-key-placeholder"
    assert not cert.exists()
    forbidden.assert_not_called()


def test_legacy_https_mismatched_pair_is_refused_without_replacement(checkout):
    root, _ = checkout
    cert = root / "frontend/certificates/localhost.pem"
    key = root / "frontend/certificates/localhost-key.pem"
    other_cert = root / "other/localhost.pem"
    other_key = root / "other/localhost-key.pem"
    dev.create_local_certificate(cert, key)
    dev.create_local_certificate(other_cert, other_key)
    key.write_bytes(other_key.read_bytes())
    original = cert.read_bytes(), key.read_bytes()
    with pytest.raises(dev.SetupError, match="(?i)(mismatched|certificate)"):
        dev.legacy_https_context()
    assert (cert.read_bytes(), key.read_bytes()) == original


def test_canonical_greenfield_port_failure_precedes_secret_reads_and_processes(monkeypatch):
    error = dev.GreenfieldStack.ServicePortError("synthetic port conflict")
    monkeypatch.setattr(dev.GreenfieldStack, "check_service_ports", Mock(side_effect=error))
    forbidden = Mock(side_effect=AssertionError("side effect before port conflict"))
    for name in ("verify_resources", "settings", "frontend_workspace", "node_binary", "read_private"):
        monkeypatch.setattr(dev.GreenfieldStack, name, forbidden)
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", forbidden)
    monkeypatch.setattr(dev, "start_process", forbidden)
    with pytest.raises(dev.GreenfieldStack.ServicePortError, match="port conflict"):
        dev.GreenfieldProfile.start_services(Mock())
    forbidden.assert_not_called()


def test_greenfield_application_port_failure_precedes_dependency_install(monkeypatch):
    monkeypatch.setattr(dev, "check_application_ports", Mock(side_effect=dev.SetupError("synthetic occupied port")))
    forbidden = Mock(side_effect=AssertionError("setup before port conflict"))
    monkeypatch.setattr(dev, "ensure_dependencies", forbidden)
    monkeypatch.setattr(dev, "ensure_frontend", forbidden)
    monkeypatch.setattr(dev.GreenfieldProfile, "start", forbidden)
    with pytest.raises(dev.SetupError, match="occupied port"):
        dev.start_application(SimpleNamespace(profile="greenfield", check=False))
    forbidden.assert_not_called()


def test_canonical_greenfield_tls_failure_precedes_container_resume(greenfield_installation, monkeypatch):
    certificate = Mock(side_effect=dev.LocalHttps.HttpsTrustError("untrusted local CA"))
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", certificate)
    forbidden = Mock(side_effect=AssertionError("container operation before trust validation"))
    for name in ("settings", "read_private", "verify_resources", "docker_command"):
        monkeypatch.setattr(dev.GreenfieldStack, name, forbidden)
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", forbidden)
    monkeypatch.setattr(dev.GreenfieldProfile, "start_services", forbidden)
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    monkeypatch.setattr(dev.subprocess, "Popen", forbidden)
    with pytest.raises(dev.LocalHttps.HttpsTrustError, match="untrusted"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), Mock())
    certificate.assert_called_once_with(greenfield_installation, prepare=True)
    forbidden.assert_not_called()


def test_canonical_greenfield_inventory_checks_recorded_identity_before_inspection(monkeypatch):
    monkeypatch.setattr(dev.GreenfieldStack, "verify_resources", Mock(side_effect=dev.SetupError("recorded identity changed")))
    forbidden = Mock(side_effect=AssertionError("inventory before identity check"))
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    with pytest.raises(dev.SetupError, match="identity changed"):
        dev.GreenfieldProfile.inventory()
    forbidden.assert_not_called()


def test_canonical_greenfield_check_is_read_only_and_does_not_read_passwords(greenfield_installation, monkeypatch):
    from scripts import greenfield_migrations

    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in greenfield_installation.iterdir()}
    certificate = Mock()
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", certificate)
    inventory = Mock(return_value=[])
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", inventory)
    forbidden = Mock(side_effect=AssertionError("mutation or password read during check"))
    for name in (
        "settings", "read_private", "private_file", "initialize_private_state", "provision",
        "bootstrap", "frontend_workspace", "docker_command", "verify_resources",
    ):
        monkeypatch.setattr(dev.GreenfieldStack, name, forbidden)
    monkeypatch.setattr(dev.GreenfieldProfile, "start_services", forbidden)
    monkeypatch.setattr(dev, "start_process", forbidden)
    monkeypatch.setattr(dev, "run", forbidden)
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    monkeypatch.setattr(dev.subprocess, "Popen", forbidden)
    monkeypatch.setattr(dev.subprocess, "check_output", forbidden)
    monkeypatch.setattr(greenfield_migrations, "ensure_current", forbidden)
    dev.GreenfieldProfile.start(SimpleNamespace(check=True), None)
    certificate.assert_called_once_with(greenfield_installation, prepare=False)
    inventory.assert_called_once_with()
    forbidden.assert_not_called()
    after = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in greenfield_installation.iterdir()}
    assert after == before


@pytest.mark.parametrize("missing", ["environment.json", "runtime-password", "setup-password"])
def test_canonical_greenfield_incomplete_state_fails_before_tls_or_container_checks(greenfield_installation, monkeypatch, missing):
    (greenfield_installation / missing).unlink()
    forbidden = Mock(side_effect=AssertionError("incomplete installation bypassed"))
    monkeypatch.setattr(dev.LocalHttps, "ensure_certificate", forbidden)
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", forbidden)
    monkeypatch.setattr(dev.GreenfieldStack, "settings", forbidden)
    monkeypatch.setattr(dev.GreenfieldStack, "read_private", forbidden)
    with pytest.raises(dev.SetupError, match="Greenfield installation is incomplete"):
        dev.GreenfieldProfile.start(SimpleNamespace(check=True), None)
    forbidden.assert_not_called()


def test_legacy_reports_worker_crash_after_readiness_names_the_failed_service(checkout, monkeypatch):
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    processes = {name: SimpleNamespace(poll=Mock(return_value=None), returncode=None) for name in
                 ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")}
    processes["Celery reports worker"] = SimpleNamespace(poll=Mock(return_value=1), returncode=1)
    runtime = Mock(state={"ready": True}, path=dev.ROOT / "crash-state.json")
    with pytest.raises(dev.SetupError, match="Celery reports worker.*code 1.*Log:"):
        dev.supervise_runtime(runtime, {}, processes)
    assert runtime.state["ready"] is False
