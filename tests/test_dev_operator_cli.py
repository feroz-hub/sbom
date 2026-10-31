"""Opt-in Native status CLI boundaries; use --noconftest, never live resources."""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import bootstrap_native_platform_user as native_cli
from scripts import dev, dev_operator

SECRET = "fixture-native-cli-secret-never-log"
DATABASE = "sbom_analyser_dev"


@pytest.fixture
def readonly_boundary(tmp_path, monkeypatch):
    """No project preparation, SQL/app imports, subprocesses or runtime locks."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "CONFIG", tmp_path / ".env.dev.local")
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", tmp_path / "greenfield-state")
    monkeypatch.setattr(
        os,
        "environ",
        {"APP_ENVIRONMENT": "development", "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "true"},
    )
    forbidden = Mock(side_effect=AssertionError("Read-only Native status crossed a mutable boundary"))
    for name in (
        "Runtime",
        "validate_repository_layout",
        "validate_python_version",
        "validate_prerequisites",
        "venv_python",
        "ensure_virtualenv",
        "require_virtualenv",
        "ensure_dependencies",
        "ensure_frontend",
        "setup_application",
        "_apply_setup_application",
        "_prepare_authorized_setup",
        "prepare_managed_legacy",
        "configure_local_database",
        "ensure_database",
        "run_migrations",
        "generate_keys",
        "write_config",
        "start_application",
        "stop_application",
        "start_process",
        "start_background",
        "check_profile_ownership",
        "acquire_beat_lock",
        "atomic_json",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    for name in ("run", "Popen", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        assert not (name == "app" or name.startswith("app.") or name.split(".", 1)[0] in {"sqlalchemy", "psycopg"}), (
            "Native status imported an application or database driver before validation"
        )
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    return forbidden


def status_result(code="ENROLLMENT_REQUIRED", state="NOT_STARTED"):
    return dev_operator.NativeEnrollmentStatus(
        code=code,
        state=state,
        platform_admin_available=code == "ADMIN_READY",
        enrollment_required=code == "ENROLLMENT_REQUIRED",
        existing_users_present=True,
        bootstrap_enabled=False,
    )


def stub_operator(monkeypatch, *, result=None):
    context = object()
    operator = SimpleNamespace(
        OperatorError=dev_operator.OperatorError,
        resolve_native_context=Mock(return_value=context),
        inspect_native_enrollment=Mock(return_value=result or status_result()),
    )
    library = Mock(return_value=operator)
    monkeypatch.setattr(dev, "_development_library", library)
    return operator, context, library


def launcher_command(monkeypatch, *arguments):
    monkeypatch.setattr(sys, "argv", ["dev.py", *arguments])
    return dev.cli()


def test_setup_native_status_dispatches_before_mutable_setup_and_reports_observation(
    readonly_boundary, monkeypatch, capsys
):
    operator, context, library = stub_operator(monkeypatch)
    before = dict(os.environ)
    assert (
        launcher_command(
            monkeypatch,
            "setup",
            "--native-admin-status",
            "--profile",
            "legacy",
            "--legacy-config",
            "managed",
            "--confirm-database",
            DATABASE,
        )
        == 0
    )
    args, launcher = operator.resolve_native_context.call_args.args
    assert (args.profile, args.legacy_config, args.confirm_database) == ("legacy", "managed", DATABASE)
    assert launcher is dev
    operator.inspect_native_enrollment.assert_called_once_with(context, confirm_database=DATABASE)
    library.assert_called_once_with("dev_operator")
    output = capsys.readouterr()
    observed = json.loads(output.out)
    assert observed == {
        "code": "ENROLLMENT_REQUIRED",
        "state": "NOT_STARTED",
        "platform_admin_available": False,
        "enrollment_required": True,
        "existing_users_present": True,
        "bootstrap_enabled": False,
        "live_readiness_verified": False,
    }
    assert all(type(value) is bool for name, value in observed.items() if name not in {"code", "state"})
    assert not {"email", "user_id", "password", "token", "activation_url"} & set(observed)
    assert not output.err and SECRET not in output.out
    assert os.environ == before
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        ["--plan"],
        ["--provision-greenfield"],
        ["--initialize-database"],
        ["--migrate"],
        ["--frontend-build"],
        ["--repair-dependencies"],
        ["--postgres-provider", "local"],
        ["--redis-provider", "docker"],
        ["--mailpit-provider", "local"],
    ],
)
def test_native_status_refuses_preparation_flags_before_operator_or_mutator(
    readonly_boundary, monkeypatch, capsys, options
):
    inspect = Mock(side_effect=AssertionError("Mixed status invocation resolved configuration"))
    monkeypatch.setattr(dev, "native_admin_status", inspect)
    assert (
        launcher_command(monkeypatch, "setup", "--native-admin-status", "--confirm-database", DATABASE, *options) == 2
    )
    output = capsys.readouterr()
    assert "NATIVE_STATUS_OPTIONS" in output.err
    assert SECRET not in output.out + output.err
    inspect.assert_not_called()
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize("command", ["start", "stop", "restart", "status", "logs", "diagnose", "doctor"])
def test_native_status_is_exclusive_to_setup_and_never_controls_lifecycle(
    readonly_boundary, monkeypatch, capsys, command
):
    inspect = Mock(side_effect=AssertionError("Invalid command entered Native status"))
    monkeypatch.setattr(dev, "native_admin_status", inspect)
    monkeypatch.setattr(dev, "diagnose", readonly_boundary)
    monkeypatch.setattr(dev, "doctor", readonly_boundary)
    assert launcher_command(monkeypatch, command, "--native-admin-status") == 2
    output = capsys.readouterr()
    code = "DIAGNOSTIC_OPTIONS" if command in {"diagnose", "doctor"} else "NATIVE_STATUS_OPTIONS"
    assert code in output.err
    inspect.assert_not_called()
    readonly_boundary.assert_not_called()


def test_native_status_cannot_be_combined_with_readonly_check_alias(readonly_boundary, monkeypatch, capsys):
    monkeypatch.setattr(dev, "native_admin_status", readonly_boundary)
    monkeypatch.setattr(dev, "diagnose", readonly_boundary)
    assert launcher_command(monkeypatch, "setup", "--check", "--native-admin-status") == 2
    assert "DIAGNOSTIC_OPTIONS" in capsys.readouterr().err
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize("confirmation", [None, "different-database"])
def test_wrapper_requires_exact_database_confirmation_before_driver_or_private_snapshot(
    readonly_boundary, monkeypatch, capsys, confirmation
):
    selected = Mock(side_effect=AssertionError("Unconfirmed status inspected private snapshots"))
    driver = Mock(side_effect=AssertionError("Unconfirmed status inspected the database"))
    monkeypatch.setattr(dev_operator, "_managed_plan", selected)
    monkeypatch.setattr(dev_operator, "inspect_native_enrollment", driver)
    args = dev.parse_args(
        ["setup", "--native-admin-status", "--profile", "legacy", "--legacy-config", "managed"]
        + (["--confirm-database", confirmation] if confirmation is not None else [])
    )
    assert dev.native_admin_status(args) == 1
    output = capsys.readouterr()
    assert "OPERATOR_DATABASE_CONFIRMATION_REQUIRED" in output.out
    assert SECRET not in output.out + output.err
    selected.assert_not_called()
    driver.assert_not_called()
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize("initial", [False, True])
def test_wrapper_restores_bytecode_flag_and_prints_only_safe_operator_reason(
    readonly_boundary, monkeypatch, capsys, initial
):
    operator, _, _ = stub_operator(monkeypatch)
    failure = dev_operator.OperatorError("OPERATOR_DATABASE_INSPECTION_FAILED", "Review the selected target safely.")
    failure.__cause__ = RuntimeError(SECRET)
    operator.inspect_native_enrollment.side_effect = failure
    monkeypatch.setattr(sys, "dont_write_bytecode", initial)
    assert dev.native_admin_status(SimpleNamespace(confirm_database=DATABASE)) == 1
    assert sys.dont_write_bytecode is initial
    output = capsys.readouterr()
    assert "[BLOCKED]" in output.out and failure.code in output.out
    assert SECRET not in output.out + output.err
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize("code", ["ENROLLMENT_REQUIRED", "PENDING_ACTIVATION", "BOOTSTRAP_RESERVED", "ADMIN_READY"])
def test_valid_status_observation_returns_zero_without_claiming_enrollment_authority(
    readonly_boundary, monkeypatch, capsys, code
):
    stub_operator(monkeypatch, result=status_result(code))
    assert dev.native_admin_status(SimpleNamespace(confirm_database=DATABASE)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == code and payload["live_readiness_verified"] is False
    readonly_boundary.assert_not_called()


def test_standalone_profile_status_delegates_before_sqlalchemy_and_application_imports(readonly_boundary, monkeypatch):
    delegated = Mock(return_value=0)
    monkeypatch.setattr(dev, "native_admin_status", delegated)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bootstrap_native_platform_user.py",
            "--profile",
            "legacy",
            "--legacy-config",
            "managed",
            "--confirm-database",
            DATABASE,
            "status",
        ],
    )
    before = dict(os.environ)
    assert native_cli.main() == 0
    args = delegated.call_args.args[0]
    assert (args.action, args.profile, args.legacy_config, args.confirm_database) == (
        "status",
        "legacy",
        "managed",
        DATABASE,
    )
    assert os.environ == before
    readonly_boundary.assert_not_called()


@pytest.mark.parametrize(
    "selection, action",
    [
        (["--profile", "legacy"], ["resend-activation"]),
        (["--profile", "legacy", "--legacy-config", "managed"], ["create"]),
        (["--legacy-config", "managed"], ["status"]),
    ],
)
def test_profile_selection_cannot_enable_privileged_enrollment_or_implicit_profile(
    readonly_boundary, monkeypatch, capsys, selection, action
):
    identity = (
        [
            "--email",
            "fixture@example.test",
            "--first-name",
            "Fixture",
            "--last-name",
            "Operator",
            "--phone",
            "fixture-phone",
            "--operator-reference",
            "fixture-reference",
        ]
        if action == ["create"]
        else []
    )
    delegated = Mock(side_effect=AssertionError("Privileged profile invocation entered status"))
    monkeypatch.setattr(dev, "native_admin_status", delegated)
    monkeypatch.setattr(
        sys,
        "argv",
        ["bootstrap_native_platform_user.py", *selection, "--confirm-database", DATABASE, *action, *identity],
    )
    before = dict(os.environ)
    with pytest.raises(SystemExit) as caught:
        native_cli.main()
    assert caught.value.code == 2
    assert "read-only status only" in capsys.readouterr().err
    assert os.environ == before
    delegated.assert_not_called()
    readonly_boundary.assert_not_called()


def _snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _run_owned_stub(command, *, root, environment):
    """Bound and clean up only the exact synthetic child handle created here."""
    child = subprocess.Popen(
        command, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        try:
            stdout, stderr = child.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=3)
            pytest.fail("Copied Native status stub exceeded its deadline; owned child was stopped")
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=3)


@pytest.mark.parametrize("entrypoint", ["dev.py", "bootstrap_native_platform_user.py"])
def test_copied_status_cli_suppresses_bytecode_before_optional_imports_and_preserves_checkout(tmp_path, entrypoint):
    root = tmp_path / "copied-checkout"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source = Path(dev.__file__).parent / entrypoint
    (scripts / entrypoint).write_bytes(source.read_bytes())
    common = ["--profile", "legacy", "--legacy-config", "managed", "--confirm-database", DATABASE]
    if entrypoint == "dev.py":
        (scripts / "dev_operator.py").write_text(
            "import sys\nassert sys.dont_write_bytecode\n"
            "from dataclasses import dataclass\n"
            "class OperatorError(ValueError): pass\n"
            "@dataclass(frozen=True)\nclass Status:\n"
            "    code: str = 'ENROLLMENT_REQUIRED'\n"
            "    live_readiness_verified: bool = False\n"
            "def resolve_native_context(args, launcher):\n"
            "    assert args.confirm_database == 'sbom_analyser_dev'\n"
            "    return object()\n"
            "def inspect_native_enrollment(context, *, confirm_database):\n"
            "    return Status()\n",
            encoding="utf-8",
        )
        arguments = ["setup", "--native-admin-status", *common]
    else:
        (scripts / "dev.py").write_text(
            "import sys\nassert sys.dont_write_bytecode\n"
            "def native_admin_status(args):\n"
            "    assert args.action == 'status'\n"
            "    assert args.confirm_database == 'sbom_analyser_dev'\n"
            "    return 0\n",
            encoding="utf-8",
        )
        arguments = [*common, "status"]
    before = _snapshot(root)
    transport = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
    environment = {name: value for name, value in os.environ.items() if name.upper() in transport}
    environment.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    result = _run_owned_stub(
        [sys.executable, "-S", str(scripts / entrypoint), *arguments], root=root, environment=environment
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _snapshot(root) == before
    assert not list(root.rglob("__pycache__"))
