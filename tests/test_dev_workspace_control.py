"""Synthetic public orchestration; never generate keys or start live services."""

from __future__ import annotations

import builtins
import json
import os
import signal
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_workspace_control as control

from tests.test_dev_workspace_certificates import fake_crypto as fake_crypto
from tests.test_dev_workspace_certificates import material
from tests.test_dev_workspace_dependencies import candidate as candidate
from tests.test_dev_workspace_dependencies import private_directory
from tests.test_dev_workspace_setup import FakeIO

PRIVATE = "synthetic-private-control-input-never-display"
_PORT_CHECK = control.frontend_port_available


def args(**options):
    return SimpleNamespace(
        **{
            "command": "setup",
            "mode": "mock",
            "auth": "native",
            "provider": None,
            "generation": None,
            "family": "instance",
            "existing_family": None,
            "worktree": None,
            "instance_id": None,
            "json": False,
            "check": False,
            **options,
        }
    )


@pytest.mark.parametrize("generation", [0, -1, True])
def test_explicit_invalid_generation_is_not_silently_replaced(fixture, generation):
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    with pytest.raises(control.setup.SetupError, match="^SETUP_INPUT_INVALID$"):
        session.selection(args(generation=generation))


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Control test attempted real process/network/application"))
    original = builtins.__import__

    def guarded(name, *arguments, **keywords):
        if name.split(".")[0] in {"app", "psycopg", "sqlalchemy", "celery", "redis", "docker", "alembic"}:
            return forbidden(name)
        return original(name, *arguments, **keywords)

    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(control.certificates, "generate_material", forbidden)
    yield forbidden
    forbidden.assert_not_called()


@pytest.fixture
def fixture(candidate, monkeypatch):
    root = candidate.root
    for path in (root / "scripts", root / "frontend/src", root / "frontend/src/app"):
        private_directory(path)
    (root / "scripts/dev_next_guard.cjs").write_text("// synthetic guard; never run", encoding="utf-8")
    controller = Path(control.__file__).resolve().parent
    for name in (
        "dev.py",
        "dev_workspace.py",
        "dev_workspace_cli.py",
        "dev_instance_plan.py",
        "dev_instance_registry.py",
        "dev_instance_storage.py",
    ):
        (root / "scripts" / name).write_bytes((controller / name).read_bytes())
    (root / "frontend/src/app/globals.css").write_text(":root{--color-foreground:#123456;}", encoding="utf-8")
    monkeypatch.setattr(control.workspace, "discover_workspaces", lambda _root, runner=None: candidate.snapshot)
    original = control.workspace._identifier
    monkeypatch.setattr(
        control.workspace,
        "_identifier",
        lambda kind, identity, repository_id=None: (
            candidate.snapshot.repository_id if kind == "repo" else original(kind, identity, repository_id)
        ),
    )
    initial = candidate.runner

    def installer(command, **options):
        result = initial(command, **options)
        if "ci" in command and result.returncode == 0:
            project = Path(command[command.index("--prefix") + 1]) / "node_modules"
            for name in (
                "react",
                "react-dom",
                "next/dist",
                "next/dist/bin",
                "next/dist/lib",
                "next/dist/compiled",
                "next/dist/compiled/@napi-rs",
                "next/dist/compiled/@napi-rs/triples",
                "@next",
                "@next/swc-"
                + {"win32": "win32-x64-msvc", "darwin": "darwin-x64", "linux": "linux-x64-gnu"}[sys.platform],
            ):
                private_directory(project / name)
            for name in ("react", "react-dom"):
                (project / name / "package.json").write_text('{"version":"16.3.4"}', encoding="utf-8")
            for name in (
                "next/dist/bin/next",
                "next/dist/lib/download-swc.js",
                "next/dist/compiled/@napi-rs/triples/index.js",
            ):
                (project / name).write_text("// synthetic; never executed", encoding="utf-8")
        return result

    candidate.control_options = {**candidate.tools, "dependency_runner": installer}
    candidate.install = installer
    return candidate


def run(fixture, monkeypatch, *, selected=("registry", "dependencies", "certificates", "preview"), check=False):
    io = FakeIO(selected=selected)
    monkeypatch.setattr(control.certificates, "generate_material", lambda plan, *, consent: material(plan))
    result = control.run_setup(
        args(check=check), fixture.root, home=fixture.home, io=io, observe_options=fixture.control_options
    )
    return result, io


@pytest.mark.parametrize("check,interactive", [(True, True), (False, False)])
def test_setup_check_or_non_tty_is_readonly_even_with_real_adapters(fixture, monkeypatch, check, interactive):
    forbidden = Mock(side_effect=AssertionError("Read-only control attempted preparation"))
    monkeypatch.setattr(control.certificates, "prepare_certificates", forbidden)
    monkeypatch.setattr(control.preview, "prepare_preview", forbidden)
    monkeypatch.setattr(control.bindings.BindingStore, "publish", forbidden)
    monkeypatch.setattr(control.setup.dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(control.storage, "initialize_private_directory", forbidden)
    io = FakeIO(interactive=interactive)
    result = control.run_setup(
        args(check=check), fixture.root, home=fixture.home, io=io, observe_options=fixture.control_options
    )
    assert result == 1 and "approval" not in io.events
    assert not (fixture.home / ".sbom-dev").exists() and not (fixture.root / ".venv").exists()
    forbidden.assert_not_called()


def test_setup_json_is_readonly_and_secret_redacted(fixture, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", PRIVATE)
    io = FakeIO(selected=("registry", "dependencies", "certificates", "preview"))
    result = control.run_setup(
        args(json=True), fixture.root, home=fixture.home, io=io, observe_options=fixture.control_options
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 1 and payload["application_ready"] is False
    assert payload["plan"]["rows"] and payload["outcome"]["code"] == payload["code"] == "SETUP_READ_ONLY"
    assert PRIVATE not in json.dumps(payload) and not io.events
    assert not (fixture.home / ".sbom-dev").exists()


def test_cli_arguments_without_family_select_new_instance_only_when_mode_and_auth_are_explicit(fixture):
    # Integration review: the public parser defines no family/existing_family.
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    parsed = vars(args())
    del parsed["family"], parsed["existing_family"]
    selection = session.selection(SimpleNamespace(**parsed))
    assert (selection.mode, selection.auth_mode, selection.family, selection.existing_family) == (
        "mock",
        "native",
        "instance",
        None,
    )
    rows = {row.category: row for row in session.plan(selection).rows}
    assert rows["selection"].code == "SETUP_SELECTION_READY"
    parsed["auth"] = None
    assert session.selection(SimpleNamespace(**parsed)).family is None


def test_full_mock_preparation_uses_separate_consents_and_persists_known_tls(fixture, fake_crypto, monkeypatch):
    before = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    inspected = before.plan(before.selection(args()))
    assert {row.category for row in inspected.rows if row.executable} >= {
        "registry",
        "dependencies",
        "certificates",
        "preview",
    }, (inspected.to_dict(), before.diagnostics)
    result, io = run(fixture, monkeypatch)
    assert result == 0
    assert io.events.count("plan") == io.events.count("approval") == 1
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    selection = session.selection(args(mode=None, auth=None, family=None))
    plan = session.plan(selection)
    rows = {row.category: row for row in plan.rows}
    assert (
        rows["registry"].status
        == rows["dependencies"].status
        == rows["certificates"].status
        == rows["preview"].status
        == "READY"
    )
    assert rows["onboarding"].status == "SKIPPED" and rows["provider-resources"].status == "SKIPPED"
    known = session.known(plan.instance_plan.descriptor)[1]
    assert known.binding.certificate_receipt is not None and known.revision == 1
    assert control.preview.require_preview(session.preview_plan(plan)).is_dir()
    assert not plan.to_dict()["application_ready"]


def test_repeated_setup_reuses_known_tls_without_rotation_or_new_preparation(fixture, fake_crypto, monkeypatch):
    result, _io = run(fixture, monkeypatch)
    assert result == 0
    before = sorted(str(path.relative_to(fixture.home)) for path in fixture.home.rglob("*"))
    forbidden = Mock(side_effect=AssertionError("Prepared setup attempted mutation or rotation"))
    monkeypatch.setattr(control.certificates, "prepare_certificates", forbidden)
    monkeypatch.setattr(control.preview, "prepare_preview", forbidden)
    monkeypatch.setattr(control.bindings.BindingStore, "publish", forbidden)
    io = FakeIO()
    result = control.run_setup(
        args(mode=None, auth=None, family=None),
        fixture.root,
        home=fixture.home,
        io=io,
        observe_options=fixture.control_options,
    )
    assert result == 1  # Browser trust has no approved adapter; preparation remains explicit.
    assert sorted(str(path.relative_to(fixture.home)) for path in fixture.home.rglob("*")) == before
    forbidden.assert_not_called()


def test_certificate_approval_alone_never_prepares_preview_files(fixture, fake_crypto, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Certificate consent silently prepared preview"))
    monkeypatch.setattr(control.preview, "prepare_preview", forbidden)
    result, _io = run(fixture, monkeypatch, selected=("registry", "certificates"))
    assert result == 0
    assert not (fixture.home / ".sbom-dev/previews").exists()
    forbidden.assert_not_called()


def test_dependency_only_setup_needs_no_auth_or_private_configuration(fixture, monkeypatch):
    io = FakeIO(selected=("dependencies",))
    result = control.run_setup(
        args(mode=None, auth=None, family=None),
        fixture.root,
        home=fixture.home,
        io=io,
        observe_options=fixture.control_options,
    )
    assert result == 0 and (fixture.root / ".venv").exists()
    assert not (fixture.home / ".sbom-dev/tls").exists()
    assert "selection" in io.events


def test_unknown_tls_directory_is_not_adopted_or_overwritten(fixture, fake_crypto, monkeypatch):
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    selected = session.selection(args())
    plan = session.plan(selected)
    cert, _expected = session.certificate_plan(plan)
    control.storage.initialize_private_directory(cert.directory, anchor=fixture.home)
    marker = cert.directory / "unknown-key"
    control.certificates.private.dev_private.create_private_file(marker, PRIVATE.encode())
    forbidden = Mock(side_effect=AssertionError("Unknown TLS material was regenerated"))
    monkeypatch.setattr(control.certificates, "prepare_certificates", forbidden)
    fresh = session.plan(selected)
    assert next(row for row in fresh.rows if row.category == "certificates").status == "BLOCKED"
    assert marker.read_bytes() == PRIVATE.encode()
    forbidden.assert_not_called()


@pytest.mark.parametrize("filename", ["frontend/src/app/globals.css", "scripts/dev_next_guard.cjs"])
def test_public_source_drift_changes_consolidated_approval_target(fixture, filename):
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    selected = session.selection(args())
    before = session.plan(selected)
    (fixture.root / filename).write_text(
        ":root{--changed:#111;}" if filename.endswith("css") else "// changed", encoding="utf-8"
    )
    assert session.plan(selected).target_fingerprint != before.target_fingerprint


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ready":true}',
        b'{"ready":1}',
        b'{"ready":false}',
        b'{"ready":true,"token":"private"}',
        b'{"ready":true,"ready":true}',
        b"not-json",
        b" " * 129,
    ],
)
def test_compiler_probe_uses_exact_owned_runner_and_strict_boolean_payload(monkeypatch, raw):
    run_owned = Mock(return_value=raw)
    monkeypatch.setattr(control.engine, "_owned_run", run_owned)
    plan = SimpleNamespace(workspace=Path("C:/synthetic" if os.name == "nt" else "/synthetic"))
    argv = ("selected-node", "--require", "guard", "-e", "native-only", "selected-modules")
    environment = {"CI": "1"}
    if raw == b'{"ready":true}':
        assert control.compiler_probe(plan, argv, environment) is True
    else:
        with pytest.raises(control.ControlError, match="^CONTROL_COMPILER_UNVERIFIED$"):
            control.compiler_probe(plan, argv, environment)
    run_owned.assert_called_once_with(argv, cwd=plan.workspace, environment=environment, timeout=8)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("ENGINE_CHILD_TIMEOUT", "CONTROL_COMPILER_UNVERIFIED"),
        ("ENGINE_CHILD_CLEANUP_UNCONFIRMED", "CONTROL_COMPILER_CLEANUP_UNCONFIRMED"),
    ],
)
def test_compiler_timeout_and_cleanup_uncertainty_are_actionable_and_redacted(monkeypatch, code, expected):
    monkeypatch.setattr(control.engine, "_owned_run", Mock(side_effect=control.engine.EngineError(code, child_pid=44)))
    with pytest.raises(control.ControlError, match="^" + expected + "$") as raised:
        control.compiler_probe(SimpleNamespace(workspace=Path.cwd()), (), {})
    if code.endswith("CLEANUP_UNCONFIRMED"):
        assert raised.value.pid == 44


def test_scoped_signal_handlers_raise_cancellation_and_restore_all_originals(monkeypatch):
    state = {
        number: object()
        for number in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if hasattr(signal, "SIGBREAK") else []))
    }
    initial = dict(state)
    monkeypatch.setattr(signal, "getsignal", lambda number: state[number])
    monkeypatch.setattr(signal, "signal", lambda number, handler: state.__setitem__(number, handler))
    with control.scoped_signals():
        with pytest.raises(KeyboardInterrupt):
            state[signal.SIGTERM](signal.SIGTERM, None)
    assert state == initial


class FakeSupervisor:
    def __init__(self, descriptor, anchor):
        self.location = SimpleNamespace(
            descriptor=descriptor, anchor=anchor, root=anchor / ".sbom-dev/instances" / descriptor.instance_id
        )
        self.runtime, self.events, self.fail_start, self.interrupt = None, [], False, False

    def start(self, specs, *, preflight, probes, timeout):
        self.events.append("start")
        assert timeout == 90
        if preflight(specs, 5) is not True:
            return control.runtime.RuntimeOutcome("INSTANCE_PREFLIGHT_VERIFICATION_REQUIRED", 1)
        if self.fail_start:
            return control.runtime.RuntimeOutcome("INSTANCE_RUNTIME_BUSY", 1, records_retained=True)
        self.runtime = object()
        assert probes["Frontend"](specs[0], 3) is True
        return control.runtime.RuntimeOutcome("INSTANCE_READY", 0, ready=True)

    def restart(self, specs, **options):
        self.events.append("restart")
        self.stop(timeout=45)
        return self.start(specs, **options)

    def supervise(self, probes):
        self.events.append("supervise")
        if self.interrupt:
            raise KeyboardInterrupt
        return self.stop(timeout=45)

    def stop(self, *, timeout):
        self.events.append("verified-stop")
        assert timeout == 45
        self.runtime = None
        return control.runtime.RuntimeOutcome("INSTANCE_STOPPED", 0)

    def release(self):
        self.events.append("release")
        self.runtime = None


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    descriptor = control.setup.instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="mock", auth_mode="native"
    ).descriptor
    anchor = tmp_path.resolve()
    selected = SimpleNamespace(root=anchor, status="PASS", head=descriptor.commit)
    entry = SimpleNamespace(descriptor=descriptor)
    supervisor = FakeSupervisor(descriptor, anchor)
    reader = SimpleNamespace(results={}, frontend=Mock(return_value=True))
    planned = SimpleNamespace(descriptor=descriptor, tls=object())
    session = SimpleNamespace(
        known=Mock(return_value=(None, SimpleNamespace(binding=SimpleNamespace(certificate_receipt=object()))))
    )
    monkeypatch.setattr(control, "registered", lambda *_args, **_kwargs: (anchor, object(), selected, entry))
    monkeypatch.setattr(control, "_launcher", lambda: object())
    monkeypatch.setattr(control, "_runtime", lambda *_args: supervisor)
    monkeypatch.setattr(control, "frontend_port_available", Mock(return_value=True))
    monkeypatch.setattr(control, "_mock_prepared", lambda *_args: (session, object(), planned))
    monkeypatch.setattr(control.preview, "require_preview", Mock())
    monkeypatch.setattr(control.readiness, "validate_tls_material", Mock(return_value=object()))
    monkeypatch.setattr(control.readiness, "ReadinessContext", lambda *_args: object())
    monkeypatch.setattr(control.readiness, "WorkspaceReadiness", lambda *_args: reader)
    monkeypatch.setattr(control.runtime, "preview_launch", lambda *_args: (object(),))

    def launch(candidate, environment, *, verify_tls, verify_compiler):
        assert candidate is planned and PRIVATE not in repr(environment)
        assert verify_compiler is control.compiler_probe and verify_tls(candidate, environment) is True
        return SimpleNamespace(environment=environment)

    monkeypatch.setattr(control.preview, "validate_launch", launch)
    return SimpleNamespace(supervisor=supervisor, descriptor=descriptor, reader=reader)


@pytest.mark.parametrize("command", ["start", "restart"])
def test_mock_lifecycle_reaches_foreground_supervision_and_verified_stop(lifecycle, capsys, command):
    assert control.run_lifecycle(args(command=command), Path.cwd()) == 0
    assert "supervise" in lifecycle.supervisor.events and lifecycle.supervisor.events[-1] == "verified-stop"
    output = capsys.readouterr().out
    assert "INSTANCE_READY" in output and "application readiness not claimed" in output


def test_busy_start_does_not_stop_somebody_elses_runtime(lifecycle):
    lifecycle.supervisor.fail_start = True
    assert control.run_lifecycle(args(command="start"), Path.cwd()) == 1
    assert lifecycle.supervisor.events == ["start"]


def test_controller_cancellation_cleans_up_only_its_active_supervisor(lifecycle):
    lifecycle.supervisor.interrupt = True
    assert control.run_lifecycle(args(command="start"), Path.cwd()) == 130
    assert lifecycle.supervisor.events == ["start", "supervise", "verified-stop", "release"]


def test_stop_needs_no_source_dependency_tls_or_compiler(lifecycle, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Stop inspected mutable/private startup configuration"))
    monkeypatch.setattr(control, "_mock_prepared", forbidden)
    monkeypatch.setattr(control, "compiler_probe", forbidden)
    monkeypatch.setattr(control.certificates, "prepare_certificates", forbidden)
    assert control.run_lifecycle(args(command="stop"), Path.cwd()) == 0
    assert lifecycle.supervisor.events == ["verified-stop"]
    forbidden.assert_not_called()


@pytest.mark.parametrize("mode", ["isolated", "shared-backend"])
def test_real_backend_start_is_blocked_before_runtime_or_private_setup(lifecycle, monkeypatch, mode):
    descriptor = control.setup.instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode=mode, auth_mode="native"
    ).descriptor
    monkeypatch.setattr(
        control,
        "registered",
        lambda *_args, **_kwargs: (Path.cwd(), object(), None, SimpleNamespace(descriptor=descriptor)),
    )
    forbidden = Mock(side_effect=AssertionError("Unapproved real backend reached runtime"))
    monkeypatch.setattr(control, "_runtime", forbidden)
    assert control.run_lifecycle(args(command="start", json=True), Path.cwd()) == 1
    forbidden.assert_not_called()


def test_status_uses_readonly_inspector_without_compiler_or_preparation(lifecycle, monkeypatch, capsys):
    report = control.inspect.InspectionReport("STOPPED", ())
    observe = Mock(return_value=report)
    monkeypatch.setattr(control.inspect, "inspect_instance", observe)
    forbidden = Mock(side_effect=AssertionError("Status attempted preparation"))
    monkeypatch.setattr(control, "_runtime", forbidden)
    monkeypatch.setattr(control, "compiler_probe", forbidden)
    assert control.run_status(args(command="status", json=True), Path.cwd()) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["process_status"] == "STOPPED" and payload["readiness_verified"] is False
    observe.assert_called_once()
    forbidden.assert_not_called()


def test_diagnose_adds_required_blocked_categories_without_trusting_a_running_pid(lifecycle, monkeypatch, capsys):
    monkeypatch.setattr(
        control.inspect, "inspect_instance", Mock(return_value=control.inspect.InspectionReport("RUNNING", ()))
    )
    forbidden = Mock(side_effect=AssertionError("Diagnose started a runtime, compiler or network check"))
    monkeypatch.setattr(control, "_runtime", forbidden)
    monkeypatch.setattr(control, "compiler_probe", forbidden)
    assert control.run_status(args(command="diagnose", json=True), Path.cwd()) == 1
    public = json.loads(capsys.readouterr().out)
    assert public["process_status"] == "RUNNING" and public["readiness_verified"] is False
    checks = {row["category"]: row for row in public["required_checks"]["results"]}
    assert len(checks) == 9 and all(row["status"] in {"BLOCKED", "SKIPPED"} for row in checks.values())
    assert checks["dependencies"]["status"] == "BLOCKED" and checks["database"]["status"] == "SKIPPED"
    assert not public["required_checks"]["acceptance_verified"] and not public["application_ready"]
    forbidden.assert_not_called()


def test_registered_instance_recovery_uses_protected_registry_with_deleted_selected_source(fixture, monkeypatch):
    session = control.SetupSession(fixture.root, home=fixture.home, observe_options=fixture.control_options)
    plan = session.plan(session.selection(args()))
    store = plan.observation.registry_store
    control.storage.initialize_private_directory(store.root, anchor=fixture.home)
    store.publish(control.registry.RegistryEntry(plan.instance_plan.descriptor), expected_revision=0)
    gone = replace(
        fixture.selected, root=fixture.home / "gone-checkout", identity=None, worktree_id=None, status="BLOCKED"
    )
    snapshot = replace(fixture.snapshot, worktrees=(gone,), status="BLOCKED")
    monkeypatch.setattr(control.workspace, "discover_workspaces", lambda *_args, **_kwargs: snapshot)
    anchor, observed, selected, entry = control.registered(
        args(instance_id=plan.instance_plan.descriptor.instance_id), fixture.root, home=fixture.home
    )
    assert (
        anchor == fixture.home
        and observed is snapshot
        and selected is None
        and entry.descriptor == plan.instance_plan.descriptor
    )
    supervisor = FakeSupervisor(entry.descriptor, anchor)
    monkeypatch.setattr(control, "_runtime", lambda *_args: supervisor)
    monkeypatch.setattr(control, "_launcher", lambda: object())
    forbidden = Mock(side_effect=AssertionError("Source-loss stop attempted source/config adoption"))
    monkeypatch.setattr(control, "SetupSession", forbidden)
    assert (
        control.run_lifecycle(
            args(command="stop", instance_id=entry.descriptor.instance_id), fixture.root, home=fixture.home
        )
        == 0
    )
    assert supervisor.events == ["verified-stop"]
    forbidden.assert_not_called()


def test_final_cleanup_cancellation_reports_retained_records_and_restores_handlers(lifecycle, monkeypatch, capsys):
    lifecycle.supervisor.interrupt = True

    def cancelled_stop(*, timeout):
        assert timeout == 45
        raise KeyboardInterrupt

    monkeypatch.setattr(lifecycle.supervisor, "stop", cancelled_stop)
    assert control.run_lifecycle(args(command="start", json=True), Path.cwd()) == 130
    public = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert public[-1]["code"] == "CONTROL_RUNTIME_UNCONFIRMED" and public[-1]["records_retained"] is True
    assert lifecycle.supervisor.events[-1] == "release"


def test_raw_exceptions_and_untrusted_runtime_diagnostics_are_redacted(lifecycle, monkeypatch, capsys):
    monkeypatch.setattr(control, "registered", Mock(side_effect=OSError(PRIVATE)))
    assert control.run_status(args(command="status", json=True), Path.cwd()) == 1
    assert PRIVATE not in capsys.readouterr().out
    outcome = control.runtime.RuntimeOutcome(
        PRIVATE, 1, (control.runtime.ServiceDiagnostic("Frontend", "UNKNOWN", 19, PRIVATE),)
    )
    public = control._runtime_payload(outcome, lifecycle.descriptor, Path.cwd())
    assert PRIVATE not in json.dumps(public) and public["code"] == "CONTROL_RUNTIME_UNCONFIRMED"


@pytest.mark.parametrize(
    "category,operation,winerror",
    [("OWNER_MISMATCH", "EqualSid", None), ("UNTRUSTED_GRANT", "GetAce", None), ("API_FAILURE", "GetSecurityInfo", 5)],
)
def test_setup_check_reports_known_acl_policy_failure_without_mutation(
    fixture, monkeypatch, capsys, category, operation, winerror
):
    original = control.storage._verify

    def refused(path, *, private):
        if path == fixture.home:
            try:
                raise control.windows_acl.AclVerificationError(operation, winerror, category)
            except control.windows_acl.AclVerificationError as error:
                raise control.storage.DirectoryInitializationError(
                    "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED", error.winerror, windows=True
                ) from None
        return original(path, private=private)

    monkeypatch.setattr(control.storage, "_verify", refused)
    forbidden = Mock(side_effect=AssertionError("ACL-refused read-only setup attempted mutation"))
    monkeypatch.setattr(control.storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(control.bindings.BindingStore, "publish", forbidden)
    monkeypatch.setattr(control.certificates, "prepare_certificates", forbidden)
    monkeypatch.setattr(control.preview, "prepare_preview", forbidden)
    monkeypatch.setattr(control.setup.dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(control.bindings.dev_private, "create_private_file", forbidden)
    assert (
        control.run_setup(
            args(check=True, json=True), fixture.root, home=fixture.home, observe_options=fixture.control_options
        )
        == 1
    )
    payload = json.loads(capsys.readouterr().out)
    diagnostic = payload["diagnostic"]
    assert payload["code"] == "CONTROL_HOME_ACCESS_UNVERIFIED" and payload["plan"] is None
    assert payload["outcome"]["code"] == payload["code"]
    assert diagnostic["component"] == "private-home" and diagnostic["code"] == "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED"
    assert (diagnostic["category"], diagnostic["operation"], diagnostic["winerror"]) == (category, operation, winerror)
    assert "permission review" in diagnostic["guidance"] and str(fixture.home) not in json.dumps(payload)
    assert not (fixture.home / ".sbom-dev").exists()
    forbidden.assert_not_called()


def test_unknown_acl_details_are_not_exposed_as_diagnostics(fixture, monkeypatch, capsys):
    def refused(*_args, **_kwargs):
        try:
            raise control.windows_acl.AclVerificationError(PRIVATE, 5, PRIVATE)
        except control.windows_acl.AclVerificationError as error:
            raise control.storage.DirectoryInitializationError(
                "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED", error.winerror, windows=True
            ) from None

    monkeypatch.setattr(control.storage, "_verify", refused)
    assert control.run_setup(args(check=True, json=True), fixture.root, home=fixture.home) == 1
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert PRIVATE not in output
    assert (
        payload["diagnostic"]["category"] == "INSPECTION_UNAVAILABLE"
        and payload["diagnostic"]["operation"] == "InspectDirectory"
    )
    assert payload["diagnostic"]["winerror"] == 5


@pytest.mark.parametrize(
    "error,owned",
    [
        (SimpleNamespace(code="CONTROL_COMPILER_CLEANUP_UNCONFIRMED", pid=77), False),
        (control.ControlError("CONTROL_INPUT_INVALID", pid=77), False),
        (control.ControlError("CONTROL_COMPILER_CLEANUP_UNCONFIRMED", pid=77), True),
        (control.readiness.ReadinessError("LISTENER_PROBE_CLEANUP_UNCONFIRMED", probe_pid=77), True),
    ],
)
def test_numeric_pid_on_unknown_exception_never_becomes_owned_proof(error, owned, monkeypatch, capsys):
    forbidden = Mock(side_effect=AssertionError("Error rendering attempted process control"))
    monkeypatch.setattr(os, "kill", forbidden)
    assert control._error(args(command="status", json=True), error) == 1
    payload = json.loads(capsys.readouterr().out)
    assert ("owned_probe_pid" in payload) is owned
    forbidden.assert_not_called()


class PortSocket:
    def __init__(self, *, occupied=False):
        self.occupied, self.closed, self.options, self.targets = occupied, False, [], []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def settimeout(self, value):
        assert 0 < value <= 0.5

    def setsockopt(self, level, option, value):
        assert option != socket.SO_REUSEADDR and value == 1
        self.options.append((level, option, value))

    def bind(self, target):
        self.targets.append(target)
        if self.occupied:
            raise OSError(98, PRIVATE)


@pytest.mark.parametrize("occupied", [True, False])
def test_port_preflight_owns_only_a_temporary_exclusive_loopback_socket(lifecycle, monkeypatch, occupied):
    temporary = PortSocket(occupied=occupied)
    factory = Mock(return_value=temporary)
    monkeypatch.setattr(control.socket, "socket", factory)
    if occupied:
        with pytest.raises(control.ControlError, match="^CONTROL_PORT_UNAVAILABLE$"):
            _PORT_CHECK(lifecycle.descriptor)
    else:
        assert _PORT_CHECK(lifecycle.descriptor) is True
    factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    assert temporary.closed and temporary.targets == [("127.0.0.1", lifecycle.descriptor.ports["frontend"])]
    if os.name == "nt":
        assert temporary.options == [(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)]
    else:
        assert not temporary.options


def test_occupied_frontend_port_preserves_listener_and_prevents_all_children(lifecycle, monkeypatch, capsys):
    temporary = PortSocket(occupied=True)
    monkeypatch.setattr(control.socket, "socket", Mock(return_value=temporary))
    monkeypatch.setattr(control, "frontend_port_available", _PORT_CHECK)
    forbidden = Mock(side_effect=AssertionError("Occupied frontend port reached compiler/runtime/app spawn"))
    monkeypatch.setattr(control, "_launcher", forbidden)
    monkeypatch.setattr(control.engine, "_owned_run", forbidden)
    monkeypatch.setattr(control, "_runtime", forbidden)
    assert control.run_lifecycle(args(command="start", json=True), Path.cwd()) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "CONTROL_PORT_UNAVAILABLE" and payload["component"] == "Frontend"
    assert temporary.occupied is True and temporary.closed and not lifecycle.supervisor.events
    assert PRIVATE not in json.dumps(payload)
    forbidden.assert_not_called()


def test_late_bind_collision_is_specific_and_refuses_frontend_spawn(lifecycle, monkeypatch, capsys):
    monkeypatch.setattr(
        control, "frontend_port_available", Mock(side_effect=[True, control.ControlError("CONTROL_PORT_UNAVAILABLE")])
    )
    assert control.run_lifecycle(args(command="start", json=True), Path.cwd()) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "CONTROL_PORT_UNAVAILABLE" and lifecycle.supervisor.runtime is None
    lifecycle.reader.frontend.assert_not_called()


def test_restart_checks_port_only_after_verified_stop(lifecycle, monkeypatch):
    def available(_descriptor):
        assert "verified-stop" in lifecycle.supervisor.events
        return True

    monkeypatch.setattr(control, "frontend_port_available", available)
    assert control.run_lifecycle(args(command="restart"), Path.cwd()) == 0


def test_status_and_diagnose_never_bind_a_frontend_port(lifecycle, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Read-only control bound a socket"))
    monkeypatch.setattr(control, "frontend_port_available", forbidden)
    monkeypatch.setattr(
        control.inspect, "inspect_instance", Mock(return_value=control.inspect.InspectionReport("STOPPED", ()))
    )
    assert control.run_status(args(command="status"), Path.cwd()) == 0
    assert control.run_status(args(command="diagnose"), Path.cwd()) == 1
    forbidden.assert_not_called()


def test_runtime_payload_preserves_only_typed_native_diagnostics(lifecycle):
    inspection = control.runtime.RuntimeInspection("runtime-lock", "OWNER_MISMATCH", 5)
    result = control.runtime.RuntimeOutcome(
        "INSTANCE_RUNTIME_RECORD_UNVERIFIED", 1, component="Frontend", winerror=32, probe_pid=77, inspection=inspection
    )
    public = control._runtime_payload(result, lifecycle.descriptor, Path.cwd())
    assert (
        public["inspection"] == inspection.to_dict() and public["winerror"] == 32 and public["component"] == "Frontend"
    )
    assert "owned_probe_pid" not in public
    forged = replace(result, component=PRIVATE, winerror=-1, inspection={"private": PRIVATE})
    public = control._runtime_payload(forged, lifecycle.descriptor, Path.cwd())
    assert PRIVATE not in json.dumps(public) and public["winerror"] is None and "inspection" not in public
