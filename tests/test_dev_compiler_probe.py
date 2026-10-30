"""Synthetic compiler/repair boundaries; no Node, installers or data services run."""

from __future__ import annotations

import builtins
import hashlib
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_components, dev_config, dev_diagnostics, dev_frontend, dev_setup

SECRET = "fixture-private-probe-error-and-credential"
PROBE_PID = 424242


class ProbeError(RuntimeError):
    pass


@pytest.fixture
def compiler_workspace(tmp_path):
    root = tmp_path / "repository"
    source = root / "frontend"
    source.mkdir(parents=True)
    for name in ("src", "public", "node_modules"):
        (source / name).mkdir()
    for name, content in {
        "package.json": '{"name":"synthetic-probe"}',
        "package-lock.json": '{"lockfileVersion":3}',
        "tsconfig.json": "{}",
    }.items():
        (source / name).write_text(content, encoding="utf-8")
    state = tmp_path / "synthetic-greenfield"
    state.mkdir(mode=0o700)
    launcher = SimpleNamespace(
        ROOT=root,
        ACTIVE_PROFILE="legacy",
        GreenfieldStack=SimpleNamespace(STATE=state, node_binary=lambda: root / "synthetic-bin/node"),
        LocalHttps=SimpleNamespace(private_directory=Mock()),
        SetupError=ProbeError,
        sys=SimpleNamespace(platform=sys.platform),
    )
    return launcher


def probe_environment(**overrides):
    values = {
        "PATH": "synthetic-path",
        "HOME": "synthetic-home",
        "SYSTEMROOT": "synthetic-systemroot",
        "TEMP": "synthetic-temp",
        "NODE_ENV": "development",
        "NODE_OPTIONS": "--use-openssl-ca",
        "SSL_CERT_FILE": "certificates/synthetic-ca.pem",
        "APP_ORIGIN": "https://localhost:13000",
        "DATABASE_URL": SECRET,
        "NATIVE_JWT_PRIVATE_KEY": SECRET,
        "NATIVE_SECURITY_OUTBOX_KEY": SECRET,
        "AUTH_SESSION_ENCRYPTION_KEY": SECRET,
        "AUTH_SESSION_REDIS_URL": "redis://fixture:" + SECRET + "@127.0.0.1:6379/1",
        "SMTP_PASSWORD": SECRET,
        "NEXT_PUBLIC_UNREVIEWED_SECRET": SECRET,
        "CI": "0",
        "NEXT_DISABLE_SWC_WASM": "0",
        "NEXT_TELEMETRY_DISABLED": "0",
    }
    values.update(overrides)
    return values


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def child_process(*, output='{"ready":true}', returncode=0, first_error=None, kill_error=None, cleanup_error=None):
    child = SimpleNamespace(pid=PROBE_PID, returncode=None if first_error is not None else returncode)

    def kill():
        if kill_error is not None:
            raise kill_error
        child.returncode = -9

    child.kill = Mock(side_effect=kill)
    child.poll = Mock(side_effect=lambda: child.returncode)
    if first_error is None:
        child.communicate = Mock(return_value=(output, SECRET))
    else:
        child.communicate = Mock(side_effect=[first_error, cleanup_error or ("", "")])
    return child


def forbid_unowned_actions(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("probe used a PID, shell, installer or service operation"))
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("ensure_dependencies", "ensure_frontend", "start_process", "start_background"):
        monkeypatch.setattr(dev, name, forbidden)
    for name in ("terminate", "stop_services"):
        monkeypatch.setattr(dev.Runtime, name, forbidden)
    return forbidden


@pytest.mark.parametrize("profile", ["legacy", "greenfield"])
def test_probe_loads_only_existing_native_package_with_transport_environment(compiler_workspace, monkeypatch, profile):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, profile)
    environment = probe_environment()
    original, before = dict(environment), snapshot(launcher.ROOT)
    child = child_process()
    popen = Mock(return_value=child)
    monkeypatch.setattr(subprocess, "Popen", popen)
    forbidden = forbid_unowned_actions(monkeypatch)

    assert dev_components.verify_compiler(launcher, environment, workspace, profile=profile) is None

    command = popen.call_args.args[0]
    options = popen.call_args.kwargs
    assert command[0] == str(launcher.GreenfieldStack.node_binary()) and command[1] == "-e"
    assert command[-1] == str(launcher.ROOT / "frontend/node_modules")
    script = command[2]
    assert "@next" in script and "process.platform" in script and "process.arch" in script
    assert "require(p.join(root,'@next/swc-'+t.platformArchABI))" in script
    assert "next/dist/compiled/@napi-rs/triples" in script
    assert not any(
        value in script for value in ("next/dist/build/swc", "loadBindings", "download", "npm", "child_process")
    )
    assert options["cwd"] == workspace
    assert options["stdout"] == subprocess.PIPE and options["stderr"] == subprocess.PIPE
    assert options["text"] is True and not options.get("shell")
    assert options["env"] == {
        "PATH": "synthetic-path",
        "HOME": "synthetic-home",
        "SYSTEMROOT": "synthetic-systemroot",
        "TEMP": "synthetic-temp",
        "CI": "1",
        "NEXT_TELEMETRY_DISABLED": "1",
        "NEXT_DISABLE_SWC_WASM": "1",
    }
    assert SECRET not in repr(options) and SECRET not in repr(command)
    child.communicate.assert_called_once_with(timeout=8)
    child.kill.assert_not_called()
    assert environment == original and snapshot(launcher.ROOT) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "[]",
        "null",
        '{"ready":false}',
        '{"ready":1}',
        '{"ready":true,"extra":1}',
        '{"ready":true}' + " " * 129,
        None,
    ],
)
def test_malformed_or_oversize_probe_result_fails_closed_and_redacted(compiler_workspace, monkeypatch, output):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, "legacy")
    child = child_process(output=output)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    before = snapshot(launcher.ROOT)
    with pytest.raises(ProbeError, match="FRONTEND_NATIVE_BINDING_REQUIRED") as caught:
        dev_components.verify_compiler(launcher, probe_environment(), workspace, profile="legacy")
    assert SECRET not in str(caught.value)
    assert "--repair-dependencies" in str(caught.value)
    assert snapshot(launcher.ROOT) == before
    child.kill.assert_not_called()


def test_nonzero_probe_exit_does_not_claim_native_binding_readiness(compiler_workspace, monkeypatch):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, "legacy")
    child = child_process(returncode=7)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    with pytest.raises(ProbeError, match="FRONTEND_NATIVE_BINDING_REQUIRED"):
        dev_components.verify_compiler(launcher, probe_environment(), workspace, profile="legacy")
    child.kill.assert_not_called()


def test_probe_creation_error_does_not_expose_private_exception(compiler_workspace, monkeypatch):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, "legacy")
    popen = Mock(side_effect=OSError(SECRET))
    monkeypatch.setattr(subprocess, "Popen", popen)
    forbidden = forbid_unowned_actions(monkeypatch)
    with pytest.raises(ProbeError, match="FRONTEND_NATIVE_BINDING_REQUIRED") as caught:
        dev_components.verify_compiler(launcher, probe_environment(), workspace, profile="legacy")
    assert SECRET not in str(caught.value)
    forbidden.assert_not_called()


@pytest.mark.parametrize("cancellation", ["timeout", "interrupt", "io-error"])
def test_failed_probe_cleans_only_original_owned_handle_with_bounded_wait(
    compiler_workspace, monkeypatch, cancellation
):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, "legacy")
    error = {
        "timeout": subprocess.TimeoutExpired(SECRET, 8),
        "interrupt": KeyboardInterrupt(),
        "io-error": OSError(SECRET),
    }[cancellation]
    child = child_process(first_error=error)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    forbidden = forbid_unowned_actions(monkeypatch)
    expected = KeyboardInterrupt if cancellation == "interrupt" else ProbeError
    with pytest.raises(expected) as caught:
        dev_components.verify_compiler(launcher, probe_environment(), workspace, profile="legacy")
    child.kill.assert_called_once_with()
    assert [call.kwargs["timeout"] for call in child.communicate.call_args_list] == [8, 3]
    assert SECRET not in str(caught.value)
    if cancellation == "timeout":
        assert "FRONTEND_COMPILER_TIMEOUT" in str(caught.value)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "cleanup",
    ["kill-error", "wait-timeout", "wait-error", "poll-and-kill-error", "still-running", "interrupt", "poll-interrupt"],
)
def test_uncertain_owned_probe_cleanup_reports_exact_pid_without_private_exception(
    compiler_workspace, monkeypatch, cleanup
):
    launcher = compiler_workspace
    workspace = dev_frontend.prepare_workspace(launcher, "legacy")
    child = child_process(
        first_error=subprocess.TimeoutExpired(SECRET, 8),
        kill_error=OSError(SECRET) if cleanup in {"kill-error", "poll-and-kill-error"} else None,
        cleanup_error=(
            subprocess.TimeoutExpired(SECRET, 3)
            if cleanup == "wait-timeout"
            else OSError(SECRET)
            if cleanup == "wait-error"
            else KeyboardInterrupt()
            if cleanup == "interrupt"
            else None
        ),
    )
    if cleanup == "poll-and-kill-error":
        child.poll.side_effect = OSError(SECRET)
    elif cleanup == "poll-interrupt":
        child.poll.side_effect = KeyboardInterrupt()
        child.kill.side_effect = OSError(SECRET)
    elif cleanup == "still-running":
        child.kill = Mock()  # No exit observation must not be reported as completed cleanup.
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=child))
    forbidden = forbid_unowned_actions(monkeypatch)
    with pytest.raises(ProbeError, match="FRONTEND_PROBE_CLEANUP_UNCONFIRMED") as caught:
        dev_components.verify_compiler(launcher, probe_environment(), workspace, profile="legacy")
    assert str(PROBE_PID) in str(caught.value) and SECRET not in str(caught.value)
    child.kill.assert_called_once_with()
    forbidden.assert_not_called()


def test_workspace_diagnosis_does_not_execute_compiler_probe(compiler_workspace, monkeypatch):
    launcher = compiler_workspace
    dev_frontend.prepare_workspace(launcher, "legacy")
    forbidden = Mock(side_effect=AssertionError("read-only workspace diagnosis executed a compiler process"))
    monkeypatch.setattr(dev_components, "verify_compiler", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = dev_diagnostics._workspace_check("legacy", launcher, probe_environment())
    assert (result.status, result.code) == ("PASS", "FRONTEND_WORKSPACE_VERIFIED")
    forbidden.assert_not_called()


def test_frontend_policy_prevents_implicit_next_repairs_without_altering_server_context():
    environment = probe_environment()
    for role in ("api", "worker", "beat"):
        assert dict(dev_config.component_environment(environment, role)) == environment
    frontend = dev_config.component_environment(environment, "frontend")
    assert (frontend["CI"], frontend["NEXT_DISABLE_SWC_WASM"], frontend["NEXT_TELEMETRY_DISABLED"]) == ("1", "1", "0")
    public = dev_config.component_environment(environment, "public")
    assert not {"CI", "NEXT_DISABLE_SWC_WASM", "NEXT_TELEMETRY_DISABLED"} & public.keys()


@pytest.mark.parametrize("command", [["diagnose"], ["doctor"], ["setup", "--check"], ["--check"]])
def test_repair_flag_is_rejected_before_readonly_dispatch_or_any_setup_action(monkeypatch, capsys, command):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", *command, "--repair-dependencies"])
    forbidden = Mock(side_effect=AssertionError("read-only repair invocation reached a mutable or probe path"))
    for name in (
        "diagnose",
        "doctor",
        "setup_application",
        "Runtime",
        "venv_python",
        "ensure_dependencies",
        "ensure_frontend",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev_components, "verify_compiler", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert dev.main() == 2
    assert "DIAGNOSTIC_OPTIONS" in capsys.readouterr().err
    forbidden.assert_not_called()


@pytest.fixture
def repair_checkout(tmp_path, monkeypatch):
    root, home = tmp_path / "checkout", tmp_path / "home"
    root.mkdir()
    home.mkdir()
    for name in dev.REQUIRED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}" if path.suffix == ".json" else "synthetic manifest\n", encoding="utf-8")
    venv = root / ".venv"
    venv.mkdir()
    python = venv / "synthetic-python"
    python.touch()
    (venv / ".sbom-requirements-sha256").write_text(
        hashlib.sha256((root / "requirements.txt").read_bytes()).hexdigest()
    )
    cli = root / "frontend/node_modules/next/dist/bin/next"
    cli.parent.mkdir(parents=True)
    cli.touch()
    (root / "frontend/node_modules/.sbom-dependencies-sha256").write_text(
        hashlib.sha256(
            (root / "frontend/package.json").read_bytes() + b"\0" + (root / "frontend/package-lock.json").read_bytes()
        ).hexdigest()
    )
    monkeypatch.setattr(dev, "ROOT", root)
    monkeypatch.setattr(dev, "VENV", venv)
    monkeypatch.setattr(dev, "CONFIG", root / ".env.dev.local")
    monkeypatch.setattr(dev, "venv_python", lambda: python)
    monkeypatch.setattr(dev.GreenfieldStack, "ROOT", root)
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", home / "synthetic-greenfield")
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: root / "synthetic-bin/node")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development", "HOME": str(home), "USERPROFILE": str(home)})
    monkeypatch.setattr(dev_setup, "_in_project_venv", lambda launcher: True)
    monkeypatch.setattr(dev_setup.importlib.util, "find_spec", lambda name: SimpleNamespace())
    return root


def repair_args(**overrides):
    args = dev.parse_args(["setup", "--profile", "legacy", "--legacy-config", "managed", "--repair-dependencies"])
    for name, value in overrides.items():
        setattr(args, name, value)
    return args


def repair_plan():
    return dev_setup.SetupPlan(
        "legacy",
        "managed",
        (
            dev_setup.SetupAction(
                "project-dependencies", "Repair only pinned synthetic project dependencies after explicit consent."
            ),
        ),
        (),
        "a" * 64,
    )


def test_repair_plan_is_observational_and_fingerprint_includes_request(repair_checkout, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("repair planning reached installation, compiler or services"))
    for name in (
        "ensure_virtualenv",
        "ensure_dependencies",
        "ensure_frontend",
        "generate_keys",
        "write_config",
        "create_local_certificate",
        "ensure_database",
        "start_process",
        "start_background",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev_components, "verify_compiler", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(builtins, "input", forbidden)
    before = snapshot(repair_checkout)
    normal = dev_setup.inspect_setup(repair_args(repair_dependencies=False), dev)
    requested = dev_setup.inspect_setup(repair_args(), dev)
    actions = {action.category: action.description for action in requested.actions}
    assert "project-dependencies" not in {action.category for action in normal.actions}
    assert "Repair" in actions["project-dependencies"]
    assert "frontend-workspace" in actions
    assert normal.fingerprint != requested.fingerprint
    assert dev_setup.run_setup(repair_args(plan=True), dev, forbidden) == int(bool(requested.blockers))
    assert snapshot(repair_checkout) == before
    forbidden.assert_not_called()


@pytest.mark.parametrize("authorization", [None, frozenset()])
def test_direct_repair_apply_requires_reviewed_categories_before_any_mutator(
    repair_checkout, monkeypatch, authorization
):
    args = repair_args()
    if authorization is not None:
        args._setup_authorized_categories = authorization
    forbidden = Mock(side_effect=AssertionError("unapproved dependency repair entered preparation"))
    for name in ("Runtime", "ensure_virtualenv", "ensure_dependencies", "ensure_frontend"):
        monkeypatch.setattr(dev, name, forbidden)
    with pytest.raises(dev.SetupError, match="SETUP_APPROVAL_REQUIRED"):
        dev._apply_setup_application(args)
    forbidden.assert_not_called()


@pytest.mark.parametrize("consent", ["yes", "no"])
def test_pinned_installers_are_forced_only_after_reviewed_category_consent(repair_checkout, monkeypatch, consent):
    events = []
    monkeypatch.setattr(dev_setup, "inspect_setup", Mock(return_value=repair_plan()))
    monkeypatch.setattr(dev.sys, "stdin", SimpleNamespace(isatty=lambda: True))

    def approve(prompt):
        assert "project-dependencies" in prompt and not events
        events.append("consent:" + consent)
        return consent

    monkeypatch.setattr(builtins, "input", approve)
    for name in ("alembic", "celery", "cryptography", "dotenv", "psycopg", "redis", "uvicorn"):
        monkeypatch.setitem(sys.modules, name, SimpleNamespace())
    monkeypatch.setattr(dev, "validate_repository_layout", Mock())
    monkeypatch.setattr(dev, "validate_prerequisites", Mock())
    monkeypatch.setattr(dev, "ensure_virtualenv", Mock())
    monkeypatch.setattr(dev, "prepare_managed_legacy", Mock(return_value={}))
    monkeypatch.setattr(dev, "legacy_https_context", Mock())
    monkeypatch.setattr(dev, "node_version", lambda: (20, 9, 0))
    monkeypatch.setattr(dev.shutil, "which", lambda name, **kwargs: "synthetic-npm")
    runtime = SimpleNamespace(load=Mock(return_value=None), acquire=Mock(return_value=True), release=Mock())
    monkeypatch.setattr(dev, "Runtime", Mock(return_value=runtime))
    forbidden = Mock(
        side_effect=AssertionError("dependency repair crossed data, secret, certificate or process boundary")
    )
    for name in (
        "generate_keys",
        "write_config",
        "create_local_certificate",
        "ensure_database",
        "run_migrations",
        "start_process",
    ):
        monkeypatch.setattr(dev, name, forbidden)
    monkeypatch.setattr(dev_components, "verify_compiler", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    def install(command):
        assert events and events[0] == "consent:yes"
        if command == [str(dev.venv_python()), "-m", "pip", "install", "-r", "requirements.txt"]:
            events.append("pinned-python-install")
        else:
            assert command == ["synthetic-npm", "ci", "--prefix", "frontend"]
            events.append("pinned-npm-install")
        return SimpleNamespace(returncode=0)

    runner = Mock(side_effect=install)
    monkeypatch.setattr(dev, "run", runner)
    # Valid stamps alone remain reusable without an explicit repair request.
    dev.ensure_dependencies()
    dev.ensure_frontend(certificate=False)
    runner.assert_not_called()
    before = snapshot(repair_checkout)
    result = dev_setup.run_setup(repair_args(), dev, dev._apply_setup_application)
    if consent == "yes":
        assert result == 0 and events == ["consent:yes", "pinned-python-install", "pinned-npm-install"]
        runtime.acquire.assert_called_once_with()
        runtime.release.assert_called_once_with()
    else:
        assert result == 1 and events == ["consent:no"]
        runner.assert_not_called()
        runtime.acquire.assert_not_called()
    assert snapshot(repair_checkout) == before
    forbidden.assert_not_called()
