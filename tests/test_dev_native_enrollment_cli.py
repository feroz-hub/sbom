"""Gated Native enrollment CLI boundaries; use --noconftest, never live resources."""

from __future__ import annotations

import builtins
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev

SECRET = "fixture-enrollment-cli-secret-never-print"
EMAIL = "private-enrollment-cli@example.test"
DATABASE = "sbom_analyser_dev"
FLAGS = (("--native-admin-create", "create"), ("--native-admin-resend", "resend-activation"))


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    """All real configuration, lifecycle, application and driver paths are forbidden."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "CONFIG", tmp_path / ".env.dev.local")
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", tmp_path / "greenfield-state")
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development", "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false"})
    forbidden = Mock(side_effect=AssertionError("Enrollment CLI crossed the isolated adapter boundary"))
    for name in (
        "Runtime",
        "validate_repository_layout",
        "validate_python_version",
        "validate_prerequisites",
        "venv_python",
        "pin_legacy_configuration",
        "resolve_profile",
        "control_profile",
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
        assert not (name == "app" or name.startswith("app.") or name.split(".", 1)[0] in {"psycopg", "sqlalchemy"}), (
            "Enrollment CLI imported a real application or database driver"
        )
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    return forbidden


def outcome(code="ENROLLMENT_READINESS_CONTRACT_REQUIRED", *, exit_code=1, committed=False, cleanup=True, pid=None):
    return SimpleNamespace(
        code=code, exit_code=exit_code, committed=committed, cleanup_confirmed=cleanup, helper_pid=pid
    )


def stub_adapter(monkeypatch, result=None):
    run = Mock(return_value=result or outcome())
    adapter = SimpleNamespace(run_enrollment=run)

    def load(name):
        assert name == "dev_native_enrollment"
        assert sys.dont_write_bytecode is True
        return adapter

    library = Mock(side_effect=load)
    monkeypatch.setattr(dev, "_development_library", library)
    return run, library


def launcher_command(monkeypatch, *arguments):
    monkeypatch.setattr(sys, "argv", ["dev.py", *arguments])
    return dev.cli()


@pytest.mark.parametrize("flag, action", FLAGS)
def test_setup_enrollment_dispatches_only_to_default_gated_adapter(boundary, monkeypatch, capsys, flag, action):
    run, library = stub_adapter(monkeypatch)
    before = dict(os.environ)
    assert (
        launcher_command(
            monkeypatch,
            "setup",
            flag,
            "--profile",
            "legacy",
            "--legacy-config",
            "managed",
            "--confirm-database",
            DATABASE,
        )
        == 1
    )
    args, launcher = run.call_args.args
    assert (args.profile, args.legacy_config, args.confirm_database) == ("legacy", "managed", DATABASE)
    assert launcher is dev
    assert run.call_args.kwargs == {"action": action}
    assert run.call_count == 1
    library.assert_called_once_with("dev_native_enrollment")
    output = capsys.readouterr()
    assert "ENROLLMENT_READINESS_CONTRACT_REQUIRED" in output.out
    assert "gated" in output.out and "attestations" in output.out
    assert SECRET not in output.out + output.err and EMAIL not in output.out + output.err
    assert os.environ == before
    boundary.assert_not_called()


@pytest.mark.parametrize("flag, action", FLAGS)
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
        ["--native-admin-status"],
    ],
)
def test_enrollment_rejects_setup_combinations_before_any_adapter_or_mutator(
    boundary, monkeypatch, capsys, flag, action, options
):
    monkeypatch.setattr(dev, "_development_library", boundary)
    monkeypatch.setattr(dev, "native_admin_status", boundary)
    assert launcher_command(monkeypatch, "setup", flag, "--confirm-database", DATABASE, *options) == 2
    assert "NATIVE_ENROLLMENT_OPTIONS" in capsys.readouterr().err
    boundary.assert_not_called()


def test_create_and_resend_are_mutually_exclusive_before_the_adapter(boundary, monkeypatch, capsys):
    monkeypatch.setattr(dev, "_development_library", boundary)
    assert launcher_command(monkeypatch, "setup", "--native-admin-create", "--native-admin-resend") == 2
    assert "NATIVE_ENROLLMENT_OPTIONS" in capsys.readouterr().err
    boundary.assert_not_called()


@pytest.mark.parametrize("flag, action", FLAGS)
@pytest.mark.parametrize("command", [[], ["start"], ["stop"], ["restart"], ["status"], ["logs"]])
def test_enrollment_is_exclusive_to_setup_before_runtime_or_lifecycle(
    boundary, monkeypatch, capsys, flag, action, command
):
    monkeypatch.setattr(dev, "_development_library", boundary)
    assert launcher_command(monkeypatch, *command, flag) == 2
    assert "NATIVE_ENROLLMENT_OPTIONS" in capsys.readouterr().err
    boundary.assert_not_called()


@pytest.mark.parametrize("flag, action", FLAGS)
@pytest.mark.parametrize(
    "command", [["diagnose"], ["doctor"], ["--check"], ["setup", "--check"], ["restart", "--check"]]
)
def test_diagnostic_aliases_refuse_enrollment_without_running_checks_or_adapter(
    boundary, monkeypatch, capsys, flag, action, command
):
    monkeypatch.setattr(dev, "_development_library", boundary)
    monkeypatch.setattr(dev, "diagnose", boundary)
    monkeypatch.setattr(dev, "doctor", boundary)
    assert launcher_command(monkeypatch, *command, flag) == 2
    assert "DIAGNOSTIC_OPTIONS" in capsys.readouterr().err
    boundary.assert_not_called()


@pytest.mark.parametrize("command", [["diagnose"], ["doctor"], ["--check"], ["setup", "--check"]])
def test_uncombined_diagnostic_aliases_keep_readonly_dispatch(boundary, monkeypatch, capsys, command):
    checked = Mock(return_value=1)
    monkeypatch.setattr(dev, "diagnose", checked)
    monkeypatch.setattr(dev, "_development_library", boundary)
    assert launcher_command(monkeypatch, *command) == 1
    checked.assert_called_once()
    if command == ["doctor"]:
        assert "deprecated" in capsys.readouterr().err
    boundary.assert_not_called()


def test_existing_native_status_retains_its_separate_readonly_handler(boundary, monkeypatch):
    inspect = Mock(return_value=0)
    monkeypatch.setattr(dev, "native_admin_status", inspect)
    monkeypatch.setattr(dev, "_development_library", boundary)
    assert launcher_command(monkeypatch, "setup", "--native-admin-status", "--confirm-database", DATABASE) == 0
    assert inspect.call_args.args[0].confirm_database == DATABASE
    inspect.assert_called_once()
    boundary.assert_not_called()


@pytest.mark.parametrize("initial", [False, True])
def test_lazy_adapter_import_disables_bytecode_and_restores_it_on_blocked_result(boundary, monkeypatch, initial):
    monkeypatch.setattr(sys, "dont_write_bytecode", initial)
    run, library = stub_adapter(monkeypatch)
    args = dev.parse_args(["setup", "--native-admin-create"])
    assert dev.native_admin_enrollment(args, action="create") == 1
    assert sys.dont_write_bytecode is initial
    run.assert_called_once_with(args, dev, action="create")
    library.assert_called_once()
    boundary.assert_not_called()


@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize("failure", ["import", "run"])
def test_unexpected_failures_print_only_fixed_safe_error_and_restore_bytecode(
    boundary, monkeypatch, capsys, initial, failure
):
    monkeypatch.setattr(sys, "dont_write_bytecode", initial)
    run, library = stub_adapter(monkeypatch)
    if failure == "import":
        library.side_effect = RuntimeError(SECRET + EMAIL)
    else:
        run.side_effect = RuntimeError(SECRET + EMAIL)
    assert dev.native_admin_enrollment(SimpleNamespace(), action="create") == 1
    assert sys.dont_write_bytecode is initial
    output = capsys.readouterr()
    assert "ENROLLMENT_ADAPTER_FAILED" in output.out and "Do not retry automatically" in output.out
    assert SECRET not in output.out + output.err and EMAIL not in output.out + output.err
    assert "Traceback" not in output.out + output.err
    boundary.assert_not_called()


@pytest.mark.parametrize(
    "result, expected",
    [
        (outcome("ACTIVATION_QUEUED", exit_code=0, committed=True), 0),
        (outcome("ENROLLMENT_APPROVAL_DECLINED"), 1),
        (outcome("ENROLLMENT_CANCELLED", exit_code=130), 130),
        (outcome("ENROLLMENT_REFUSED"), 1),
    ],
)
def test_known_outcomes_propagate_exit_code_without_printing_identity(boundary, monkeypatch, capsys, result, expected):
    run, _ = stub_adapter(monkeypatch, result)
    assert dev.native_admin_enrollment(SimpleNamespace(), action="create") == expected
    output = capsys.readouterr()
    assert result.code in output.out
    assert SECRET not in output.out + output.err and EMAIL not in output.out + output.err
    run.assert_called_once()
    boundary.assert_not_called()


@pytest.mark.parametrize("cleanup, pid", [(True, None), (False, 4567), (False, SECRET), (False, True), (False, -1)])
def test_uncertain_commit_warns_without_retry_and_reports_only_valid_owned_helper_pid(
    boundary, monkeypatch, capsys, cleanup, pid
):
    run, _ = stub_adapter(monkeypatch, outcome("OUTCOME_UNCONFIRMED", committed=None, cleanup=cleanup, pid=pid))
    assert dev.native_admin_enrollment(SimpleNamespace(), action="resend-activation") == 1
    output = capsys.readouterr()
    assert "Commit outcome is uncertain" in output.out and "Do not retry automatically" in output.out
    assert "--native-admin-status" in output.out and "--confirm-database" in output.out
    if cleanup:
        assert "cleanup is unconfirmed" not in output.out
    else:
        assert "Helper cleanup is unconfirmed" in output.out and "Verify ownership" in output.out
        assert ("owned helper PID" in output.out) is (type(pid) is int and pid > 0)
        if type(pid) is int and pid > 0:
            assert str(pid) in output.out
    assert SECRET not in output.out + output.err
    run.assert_called_once()
    boundary.assert_not_called()


@pytest.mark.parametrize(
    "result",
    [
        outcome(SECRET),
        outcome("ACTIVATION_QUEUED", exit_code=0, committed=None),
        outcome("ENROLLMENT_REFUSED", exit_code=True),
        outcome("ENROLLMENT_REFUSED", cleanup=False, pid=SECRET),
    ],
)
def test_malformed_adapter_outcomes_fail_closed_without_relaying_arbitrary_values(
    boundary, monkeypatch, capsys, result
):
    stub_adapter(monkeypatch, result)
    assert dev.native_admin_enrollment(SimpleNamespace(), action="create") == 1
    output = capsys.readouterr()
    assert "ENROLLMENT_ADAPTER_FAILED" in output.out
    assert SECRET not in output.out + output.err
    assert "[OK]" not in output.out
    boundary.assert_not_called()


def test_help_explains_gate_without_identity_or_attestation_override_flags(boundary, capsys):
    with pytest.raises(SystemExit) as caught:
        dev.parse_args(["--help"])
    assert caught.value.code == 0
    output = capsys.readouterr().out
    assert "--native-admin-create" in output and "--native-admin-resend" in output
    assert "BLOCKED" in output and "gated future" in output and "attestation" in output
    for flag in (
        "--email",
        "--first-name",
        "--last-name",
        "--phone",
        "--operator-reference",
        "--attestation",
        "--readiness-checker",
    ):
        assert flag not in output
    assert dev.parse_args([]).command == "start"
    boundary.assert_not_called()


@pytest.mark.parametrize("flag", ["--email", "--readiness-checker", "--approve-readiness", "--skip-readiness"])
def test_identity_and_readiness_override_options_are_not_public_cli_flags(boundary, capsys, flag):
    with pytest.raises(SystemExit) as caught:
        dev.parse_args(["setup", "--native-admin-create", flag])
    assert caught.value.code == 2
    capsys.readouterr()
    boundary.assert_not_called()
