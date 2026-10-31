"""Synthetic Runtime/process adapters only; never start the application stack."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote

import pytest
from scripts import dev, dev_instance_plan, dev_instance_storage, dev_private, dev_windows_acl
from scripts import dev_workspace_preview as preview
from scripts import dev_workspace_runtime as adapter

SECRET = "synthetic-runtime-secret-never-output"


class Child:
    def __init__(self, pid, events):
        self.pid, self.events, self.returncode = pid, events, None
        self._handle = pid + 10000

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append(("original-handle-terminate", self.pid))
        self.returncode = 0

    def kill(self):
        self.events.append(("original-handle-kill", self.pid))
        self.returncode = 1

    def wait(self, timeout):
        assert 0 < timeout <= 2
        return self.returncode


class FakeRuntime:
    def __init__(self, root, store, events):
        self.root, self.path = root, root / ".dev-runtime.json"
        self.stop_path, self.state = root / ".dev-runtime.stop", None
        self.store, self.events, self.processes = store, events, {}
        self.fail_register = False
        self.status_overrides = {}
        self.lock_available = True

    def acquire(self):
        self.events.append(("acquire",))
        return self.lock_available

    def release(self):
        self.events.append(("release",))

    def load(self):
        return copy.deepcopy(self.store.get(self.path))

    def begin(self, profile):
        assert profile == "workspace"
        self.events.append(("begin",))
        self.state = {
            "version": 1,
            "root": str(self.root),
            "instance": "f" * 32,
            "profile": profile,
            "services": {},
            "launcher_pid": 55,
            "launcher": {"pid": 55, "birth": "launch-time", "exe": "python"},
        }

    def check_stop(self):
        if self.stop_path in self.store:
            raise KeyboardInterrupt

    def register(self, name, pid, port):
        assert pid in self.processes and self.processes[pid]._handle
        self.events.append(("register", name, pid, port))
        if self.fail_register:
            raise OSError(SECRET)
        self.state["services"][name] = {"pid": pid, "birth": "birth-" + str(pid), "exe": "verified-exe", "members": []}
        self.store[self.path] = copy.deepcopy(self.state)

    def refresh(self):
        self.check_stop()
        self.events.append(("refresh",))

    def service_status(self, record):
        if not record.get("birth") or not record.get("exe"):
            return "UNKNOWN"
        return self.status_overrides.get(record["pid"], "RUNNING")

    def stop_services(self, say):
        self.events.append(("canonical-stop",))
        remaining = {}
        for name, record in (self.state or {}).get("services", {}).items():
            if self.service_status(record) in {"UNKNOWN", "UNOWNED"}:
                remaining[name] = record
            else:
                self.events.append(("verified-stop", record["pid"]))
        if remaining:
            self.state["services"] = remaining
            self.store[self.path] = copy.deepcopy(self.state)
            return False
        self.store.pop(self.path, None)
        self.store.pop(self.stop_path, None)
        self.state = None
        return True


@pytest.fixture
def instance(tmp_path, monkeypatch):
    anchor = tmp_path.resolve() / "private anchor"
    if os.name == "nt":
        dev_instance_storage._windows_create(anchor)
    else:
        anchor.mkdir(mode=0o700)
    descriptor = dev_instance_plan.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="mock", auth_mode="native"
    ).descriptor
    root = anchor / "instances" / descriptor.instance_id
    dev_instance_storage.initialize_private_directory(root, anchor=anchor)
    location = adapter.RuntimeLocation(descriptor, root, anchor)
    workspace = anchor / "frontend"
    dev_instance_storage.initialize_private_directory(workspace, anchor=anchor)
    node, guard = anchor / "node.exe", anchor / "guard.cjs"
    dev_private.create_private_file(node, b"synthetic executable; never execute")
    dev_private.create_private_file(guard, b"synthetic guard; never execute")
    argv = (
        str(node),
        "--require",
        str(guard),
        str(anchor / "next"),
        "dev",
        "--experimental-https",
        "--port",
        str(descriptor.ports["frontend"]),
        "--experimental-https-key",
        str(anchor / "provided-key"),
        "--experimental-https-cert",
        str(anchor / "provided-cert"),
        "--experimental-https-ca",
        str(anchor / "provided-ca"),
    )
    env = {
        "NODE_OPTIONS": "--require " + json.dumps(guard.as_posix()),
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "AUTH_SESSION_ENCRYPTION_KEY": SECRET,
        "DATABASE_URL": SECRET,
    }
    verified = preview.VerifiedPreviewLaunch(argv, workspace, env, ())
    specs = adapter.preview_launch(location, verified)
    events, store, launches, runtimes = [], {}, [], []

    def factory(selected):
        assert selected == root
        value = FakeRuntime(root, store, events)
        runtimes.append(value)
        return value

    def persist(path, value):
        store[path] = copy.deepcopy(value)

    def popen(command, **options):
        assert options["stdin"] == subprocess.DEVNULL and options["close_fds"] is True
        assert options["stderr"] == subprocess.STDOUT
        if os.name == "nt":
            assert options["creationflags"] == getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
        else:
            assert options["start_new_session"] is True
        assert "PYTHONPATH" not in options["env"]
        if adapter._BOOTSTRAP not in command:
            assert "DATABASE_URL" not in options["env"]
        child = Child(100 + len(launches), events)
        launches.append((child, command, options))
        return child

    forbidden = Mock(side_effect=AssertionError("Synthetic runtime attempted OS process control"))
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    if hasattr(os, "killpg"):
        monkeypatch.setattr(os, "killpg", forbidden)
    controller = adapter.WorkspaceRuntime(
        location,
        runtime_factory=factory,
        atomic_json=persist,
        process_info=lambda pid: {"pid": pid, "birth": "launch-time", "exe": "python"},
        matches=lambda saved, current: saved == current,
        popen=popen,
    )
    yield SimpleNamespace(
        location=location,
        root=root,
        anchor=anchor,
        specs=specs,
        controller=controller,
        store=store,
        events=events,
        launches=launches,
        runtimes=runtimes,
        factory=factory,
        persist=persist,
        node=node,
        forbidden=forbidden,
    )
    controller.release()
    forbidden.assert_not_called()


def start(instance, **changes):
    options = dict(preflight=lambda specs, timeout: True, probes={"Frontend": lambda spec, timeout: True}, timeout=2)
    options.update(changes)
    return instance.controller.start(instance.specs, **options)


def test_actual_adapter_spawns_registers_then_revalidates_before_and_after_probe(instance):
    outcome = start(instance)
    assert outcome.code == "INSTANCE_READY" and outcome.ready
    assert instance.events.index(
        ("register", "Frontend", 100, instance.location.descriptor.ports["frontend"])
    ) > instance.events.index(("begin",))
    assert sum(event == ("refresh",) for event in instance.events) >= 3
    assert instance.launches[0][2]["env"]["SBOM_DEV_RESOURCE_ID"] == instance.location.descriptor.instance_id
    assert "DATABASE_URL" not in instance.specs[0].environment
    assert SECRET not in repr(outcome) + json.dumps(outcome.to_dict())
    assert outcome.services[0].log_path == str(instance.root / ".dev-logs/frontend.log")
    assert instance.controller.stop().code == "INSTANCE_STOPPED"
    assert ("verified-stop", 100) in instance.events and not instance.store


def test_specs_are_immutable_and_transport_excludes_ambient_application_configuration(instance):
    assert dict(adapter.minimal_transport({"PATH": "public", "DATABASE_URL": SECRET, "NODE_OPTIONS": SECRET})) == {
        "PATH": "public"
    }
    with pytest.raises(FrozenInstanceError):
        instance.specs[0].port = 1
    with pytest.raises(TypeError):
        instance.specs[0].environment["DATABASE_URL"] = SECRET


def test_partial_start_readiness_failure_cleans_verified_processes_without_raw_exception(instance):
    def failed(spec, timeout):
        raise RuntimeError(SECRET)

    outcome = start(instance, probes={"Frontend": failed})
    assert outcome.code == "INSTANCE_READINESS_PROBE_FAILED" and not outcome.ready and not outcome.records_retained
    assert ("verified-stop", 100) in instance.events and SECRET not in json.dumps(outcome.to_dict())
    assert instance.controller.runtime is None
    assert outcome.component == "Frontend" and outcome.services[0].process_status == "STOPPED"


@pytest.mark.parametrize("name", ["SSLKEYLOGFILE", "sslkeylogfile", "PYTHONPATH"])
def test_secret_key_logging_and_preloads_refused_before_spawn(instance, name):
    spec = instance.specs[0]
    with pytest.raises(adapter.RuntimeAdapterError, match="^INSTANCE_COMPONENT_LAUNCH_INVALID$"):
        adapter.ComponentLaunch(spec.name, spec.argv, spec.cwd, {**spec.environment, name: SECRET}, spec.port)
    assert not instance.launches


def test_probe_preserves_only_declared_redacted_runtime_error(instance):
    def failure(_spec, _budget):
        raise adapter.RuntimeAdapterError("INSTANCE_FRONTEND_CONFIGURATION_MISMATCH")

    outcome = start(instance, probes={"Frontend": failure})
    assert outcome.code == "INSTANCE_FRONTEND_CONFIGURATION_MISMATCH"
    assert not outcome.ready and not outcome.records_retained
    assert str(adapter.RuntimeAdapterError(SECRET)) == "INSTANCE_RUNTIME_ADAPTER_INVALID"


@pytest.mark.parametrize("status", ["UNKNOWN", "UNOWNED"])
def test_pid_reuse_and_unknown_identity_after_probe_remain_protected(instance, status):
    def changed(spec, timeout):
        instance.runtimes[-1].status_overrides[100] = status
        return True

    outcome = start(instance, probes={"Frontend": changed})
    assert outcome.code == "INSTANCE_PROCESS_IDENTITY_UNVERIFIED" and outcome.records_retained
    assert ("verified-stop", 100) not in instance.events
    assert outcome.services[0].process_status == status
    assert instance.store[instance.root / ".dev-runtime.json"]["services"]["Frontend"]["pid"] == 100


def test_registration_failure_preserves_unknown_record_and_cleans_only_original_handle(instance):
    factory = instance.controller.factory

    def failing(root):
        runtime = factory(root)
        runtime.fail_register = True
        return runtime

    instance.controller.factory = failing
    outcome = start(instance)
    assert outcome.code == "INSTANCE_PROCESS_REGISTRATION_FAILED" and outcome.records_retained
    assert (("original-handle-terminate", 100) in instance.events) is (os.name == "nt")
    assert ("verified-stop", 100) not in instance.events
    assert outcome.services[0].process_status == "UNKNOWN"


def test_start_does_not_automatically_stop_an_existing_managed_instance(instance):
    assert start(instance).ready
    instance.controller.release()
    count = len(instance.launches)
    outcome = start(instance)
    assert outcome.code == "INSTANCE_EXISTING_RUNTIME_REQUIRES_STOP" and len(instance.launches) == count
    assert ("canonical-stop",) not in instance.events


def test_restart_requires_verified_cleanup_and_never_starts_over_uncertain_records(instance):
    assert start(instance).ready
    instance.runtimes[-1].status_overrides[100] = "UNKNOWN"
    result = instance.controller.restart(
        instance.specs, preflight=lambda *_: True, probes={"Frontend": lambda *_: True}, timeout=2
    )
    assert result.code == "INSTANCE_OWNERSHIP_UNCERTAIN_RECORDS_RETAINED" and len(instance.launches) == 1


def test_verified_restart_creates_new_owned_process_without_deleting_unrelated_files(instance):
    dev_private.create_private_file(instance.root / "preserve-application-data", b"preserve")
    assert start(instance).ready
    result = instance.controller.restart(
        instance.specs, preflight=lambda *_: True, probes={"Frontend": lambda *_: True}, timeout=2
    )
    assert result.ready and len(instance.launches) == 2
    assert (instance.root / "preserve-application-data").read_bytes() == b"preserve"


def test_wrong_logical_runtime_binding_is_retained_without_any_process_action(instance):
    runtime = instance.factory(instance.root)
    runtime.begin("workspace")
    runtime.state["workspace_context"] = {"instance_id": "another instance"}
    instance.persist(runtime.path, runtime.state)
    result = instance.controller.stop()
    assert result.code == "INSTANCE_RUNTIME_RECORD_UNVERIFIED" and result.records_retained
    assert ("canonical-stop",) not in instance.events and not instance.launches


def test_executable_drift_and_dotenv_sources_refuse_before_any_spawn(instance):
    instance.node.write_bytes(b"changed executable")
    outcome = start(instance)
    assert outcome.code == "INSTANCE_EXECUTABLE_CHANGED" and not instance.launches
    dev_private.create_private_file(instance.root / ".env", SECRET.encode())
    outcome = start(instance)
    assert outcome.code == "INSTANCE_RUNTIME_DOTENV_REFUSED" and not instance.launches


def test_probe_timeout_is_bounded_and_late_readonly_thread_is_released(instance):
    release = threading.Event()

    def delayed(spec, timeout):
        release.wait()
        return True

    try:
        result = start(instance, probes={"Frontend": delayed}, timeout=0.03)
        assert result.code == "INSTANCE_READINESS_TIMEOUT" and not result.records_retained
    finally:
        release.set()


def test_stop_after_source_and_configuration_loss_needs_only_protected_runtime_records(instance):
    assert start(instance).ready
    result = instance.controller.stop()
    assert result.exit_code == 0 and not instance.store


def test_remote_stop_requests_only_verified_launcher_instance_and_waits_for_its_lock(instance):
    assert start(instance).ready
    instance.controller.release()
    factory = instance.controller.factory
    now = [0.0]

    def busy(root):
        runtime = factory(root)
        runtime.lock_available = False
        return runtime

    instance.controller.factory = busy
    instance.controller.clock = lambda: now[0]

    def finish(seconds):
        now[0] += seconds
        runtime = instance.runtimes[-1]
        assert instance.store[runtime.stop_path] == {"instance": "f" * 32}
        runtime.lock_available = True

    instance.controller.sleep = finish
    result = instance.controller.stop(timeout=1)
    assert result.exit_code == 0 and ("verified-stop", 100) in instance.events


def test_remote_stop_never_requests_shutdown_for_reused_launcher_identity(instance):
    assert start(instance).ready
    instance.controller.release()
    factory = instance.controller.factory

    def busy(root):
        runtime = factory(root)
        runtime.lock_available = False
        return runtime

    instance.controller.factory = busy
    instance.controller.process_info = lambda pid: {"pid": pid, "birth": "reused", "exe": "python"}
    outcome = instance.controller.stop(timeout=1)
    assert outcome.code == "INSTANCE_LAUNCHER_OWNERSHIP_UNVERIFIED"
    assert instance.root / ".dev-runtime.stop" not in instance.store
    assert ("canonical-stop",) not in instance.events


def isolated_specs(instance, *, include_frontend=True):
    # Reuse the existing pure lifecycle fixture builder, not application fixtures
    # or conftest. It builds only frozen public/configuration contract objects.
    module_spec = importlib.util.spec_from_file_location(
        "runtime_pure_lifecycle_fixture", Path(__file__).with_name("test_dev_workspace_lifecycle.py")
    )
    fixture_module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(fixture_module)
    descriptor, snapshot = fixture_module.prepared(platform=sys.platform)
    location = adapter.RuntimeLocation(descriptor, instance.root, instance.anchor)
    source = instance.anchor / "selected checkout"
    dev_instance_storage.initialize_private_directory(source, anchor=instance.anchor)
    dev_private.create_private_file(source / ".env", SECRET.encode())
    environment = {
        key: value.replace(snapshot.state_root, str(instance.root)).replace(
            quote(snapshot.state_root, safe=""), quote(str(instance.root), safe="")
        ) for key, value in snapshot.environment.items()
    }
    snapshot = replace(snapshot, source_root=str(source), state_root=str(instance.root), environment=environment)
    lifecycle = adapter.dev_workspace_lifecycle.plan_lifecycle(descriptor, snapshot)
    argv = list(instance.specs[0].argv)
    argv[argv.index("--port") + 1] = str(descriptor.ports["frontend"])
    frontenv = {
        **lifecycle.component_environment("Frontend"),
        "NODE_OPTIONS": instance.specs[0].environment["NODE_OPTIONS"],
    }
    front = preview.VerifiedPreviewLaunch(tuple(argv), instance.specs[0].cwd, frontenv, ())
    instance.deferred_frontend = front
    specs = adapter.isolated_launches(
        location,
        lifecycle,
        python_executable=instance.node,
        frontend=front if include_frontend else None,
        transport={"PATH": "explicit transport", "AMBIENT_SECRET": SECRET},
    )
    instance.controller.location = location
    return source, specs


def test_full_lifecycle_uses_private_settings_cwd_exact_worker_names_and_background_barrier(instance):
    from scripts import dev

    source, specs = isolated_specs(instance)
    events = []

    def ready(spec, timeout):
        events.append(spec.name)
        if spec.name in {"Celery worker", "Celery reports worker"}:
            role = "reports" if spec.name == "Celery reports worker" else "default"
            expected = dev.worker_node(role, "f" * 32, "isolated")
            assert "--hostname=" + expected in spec.argv
        return True

    outcome = instance.controller.start(
        specs, preflight=lambda *_: True, probes={spec.name: ready for spec in specs}, timeout=5
    )
    assert outcome.ready and len(instance.launches) == 5
    assert events == [spec.name for spec in specs]
    first_probe_at = instance.events.index(("refresh",))
    assert sum(event[0] == "register" for event in instance.events[:first_probe_at]) == 3
    for _child, command, options in instance.launches[:-1]:
        assert {"-I", "-B", "-c"} <= set(command) and adapter._BOOTSTRAP in command
        assert str(source) in command and "runpy.run_module" in command[command.index("-c") + 1]
        assert "Settings(" not in command[command.index("-c") + 1]
        assert options["cwd"] == instance.root
        assert options["env"]["PYTHON_DOTENV_DISABLED"] == "1"
        assert options["env"]["APP_ENVIRONMENT"] == "development"
        assert options["env"]["SBOM_DEV_RESOURCE_ID"] == instance.location.descriptor.instance_id
        assert "AMBIENT_SECRET" not in options["env"]
        assert "DATABASE_URL" in options["env"]
    assert (source / ".env").read_text() == SECRET
    assert instance.controller.stop().exit_code == 0


def test_api_failure_after_verified_workers_cleans_all_and_never_starts_frontend(instance):
    _, specs = isolated_specs(instance)

    def ready(spec, timeout):
        if spec.name == "API":
            raise RuntimeError(SECRET)
        return True

    result = instance.controller.start(
        specs, preflight=lambda *_: True, probes={spec.name: ready for spec in specs}, timeout=5
    )
    assert result.code == "INSTANCE_READINESS_PROBE_FAILED" and result.component == "API"
    assert len(instance.launches) == 4 and not result.records_retained
    assert len([event for event in instance.events if event[0] == "verified-stop"]) == 4
    assert all(item.process_status == "STOPPED" for item in result.services)


def test_preview_requires_exact_port_and_trusted_guard_not_a_forged_ready_object(instance):
    verified = preview.VerifiedPreviewLaunch((str(instance.node), "-e", SECRET), instance.specs[0].cwd, {}, ())
    with pytest.raises(adapter.RuntimeAdapterError):
        adapter.preview_launch(instance.location, verified)
    wrong = list(instance.specs[0].argv)
    wrong[wrong.index("--port") + 1] = "1"
    verified = preview.VerifiedPreviewLaunch(tuple(wrong), instance.specs[0].cwd, instance.specs[0].environment, ())
    with pytest.raises(adapter.RuntimeAdapterError, match="^INSTANCE_FRONTEND_PORT_MISMATCH$"):
        adapter.preview_launch(instance.location, verified)
    unsafe = {
        **instance.specs[0].environment,
        "NODE_OPTIONS": "--require /unapproved " + instance.specs[0].environment["NODE_OPTIONS"],
    }
    verified = preview.VerifiedPreviewLaunch(instance.specs[0].argv, instance.specs[0].cwd, unsafe, ())
    with pytest.raises(adapter.RuntimeAdapterError, match="^NODE_OPTIONS_REVIEW_REQUIRED$"):
        adapter.preview_launch(instance.location, verified)


def test_preview_scope_cannot_start_backend_workers_or_beat(instance):
    _, specs = isolated_specs(instance)
    instance.controller.location = instance.location  # Restore the real mock-preview scope.
    result = instance.controller.start(
        specs, preflight=lambda *_: True, probes={spec.name: lambda *_: True for spec in specs}, timeout=2
    )
    assert result.code == "INSTANCE_START_CONTRACT_REQUIRED" and not instance.launches


def test_supervision_failure_reports_unverified_process_instead_of_successful_shutdown(instance):
    assert start(instance).ready
    instance.runtimes[-1].status_overrides[100] = "UNOWNED"
    result = instance.controller.supervise({"Frontend": lambda *_: True})
    assert result.code == "INSTANCE_PROCESS_IDENTITY_UNVERIFIED" and result.exit_code == 1
    assert result.records_retained and ("verified-stop", 100) not in instance.events


def test_malformed_protected_runtime_record_is_preserved_before_any_process_action(instance):
    path = instance.root / ".dev-runtime.json"
    dev_private.create_private_file(path, SECRET.encode())
    factory = instance.controller.factory

    def malformed(root):
        value = factory(root)
        value.load = Mock(side_effect=ValueError(SECRET))
        return value

    instance.controller.factory = malformed
    result = start(instance)
    assert result.code == "INSTANCE_RUNTIME_RECORD_UNVERIFIED" and result.records_retained
    assert path.read_text() == SECRET and not instance.launches and ("canonical-stop",) not in instance.events


def test_deferred_frontend_factory_runs_only_after_api_probe_and_all_four_owned_backends(instance):
    _, specs = isolated_specs(instance, include_frontend=False)
    api_ready = []

    def ready(spec, timeout):
        if spec.name == "API":
            api_ready.append(True)
        return True

    def frontend(backends, timeout):
        assert api_ready and len(instance.launches) == 4 and 0 < timeout <= 30
        assert [spec.name for spec in backends] == [spec.name for spec in specs]
        return instance.deferred_frontend

    result = instance.controller.start(
        specs,
        preflight=lambda *_: True,
        probes={name: ready for name in adapter._LOGS},
        frontend_factory=frontend,
        timeout=5,
    )
    assert result.ready and len(instance.launches) == 5
    assert instance.controller.stop().exit_code == 0


def test_failed_api_never_calls_frontend_factory_and_cleans_only_four_owned_processes(instance):
    _, specs = isolated_specs(instance, include_frontend=False)
    factory = Mock(side_effect=AssertionError("Frontend verification ran before API readiness"))

    def ready(spec, timeout):
        if spec.name == "API":
            raise RuntimeError(SECRET)
        return True

    result = instance.controller.start(
        specs,
        preflight=lambda *_: True,
        probes={name: ready for name in adapter._LOGS},
        frontend_factory=factory,
        timeout=5,
    )
    assert result.exit_code == 1 and result.component == "API" and not result.records_retained
    assert len(instance.launches) == 4 and len([event for event in instance.events if event[0] == "verified-stop"]) == 4
    factory.assert_not_called()


def test_deferred_factory_identity_race_prevents_frontend_spawn_and_preserves_uncertain_backend(instance):
    _, specs = isolated_specs(instance, include_frontend=False)

    def frontend(backends, timeout):
        instance.runtimes[-1].status_overrides[100] = "UNOWNED"
        return instance.deferred_frontend

    result = instance.controller.start(
        specs,
        preflight=lambda *_: True,
        probes={name: lambda *_: True for name in adapter._LOGS},
        frontend_factory=frontend,
        timeout=5,
    )
    assert result.code == "INSTANCE_PROCESS_IDENTITY_UNVERIFIED" and result.records_retained
    assert len(instance.launches) == 4 and ("verified-stop", 100) not in instance.events
    assert len([event for event in instance.events if event[0] == "verified-stop"]) == 3


def test_deferred_frontend_factory_timeout_is_bounded_without_lingering_test_thread(instance):
    _, specs = isolated_specs(instance, include_frontend=False)
    release, finished = threading.Event(), threading.Event()

    def frontend(backends, timeout):
        try:
            release.wait()
            return instance.deferred_frontend
        finally:
            finished.set()

    instance.controller.clock = lambda: 0.0
    try:
        result = instance.controller.start(
            specs,
            preflight=lambda *_: True,
            probes={name: lambda *_: True for name in adapter._LOGS},
            frontend_factory=frontend,
            timeout=0.2,
        )
        assert result.code == "INSTANCE_READINESS_TIMEOUT" and len(instance.launches) == 4
        assert not result.records_retained
    finally:
        release.set()
        assert finished.wait(timeout=1)


def test_canonical_factory_uses_explicit_private_writers_instead_of_default_token_owner(instance, monkeypatch):
    """Model an elevated token whose default new-file owner is Administrators.

    No ACL/token is changed. Only files created through the explicit-owner
    private writer are accepted by the injected ownership classifier.
    """
    explicit = set()
    original_create, original_private = dev_private.create_private_file, adapter.dev_instance_registry._private
    def create(path, raw):
        original_create(path, raw)
        info = Path(path).lstat()
        explicit.add((info.st_dev, info.st_ino))
    def private(path, **kwargs):
        info = original_private(path, **kwargs)
        if not kwargs.get("directory") and Path(path).is_relative_to(instance.root) and (info.st_dev, info.st_ino) not in explicit:
            raise dev_windows_acl.AclVerificationError("EqualSid", category="OWNER_MISMATCH")
        return info
    monkeypatch.setattr(dev_private, "create_private_file", create)
    monkeypatch.setattr(adapter.dev_instance_registry, "_private", private)
    monkeypatch.setattr(dev, "process_info", lambda pid: {"pid": pid, "birth": "fixture-launch", "exe": "fixture-python"})
    instance.controller.factory = dev.Runtime
    canonical = instance.controller._new()
    assert canonical._state_writer is instance.controller.atomic_json
    assert canonical.acquire()
    try:
        canonical.begin("workspace")
        canonical.state["workspace_context"] = instance.controller._binding()
        instance.controller._persist(canonical)
        canonical.refresh()
        for path in (canonical.lock_path, canonical.path):
            private(path)
        assert canonical.load()["workspace_context"] == instance.controller._binding()
        assert canonical.stop_services(lambda *args: None)
    finally:
        canonical.release()


def test_existing_unknown_owner_lock_is_preserved_before_factory_or_spawn(instance, monkeypatch):
    path = instance.root / ".dev-runtime.lock"
    dev_private.create_private_file(path, b"\0")
    before = (path.lstat().st_ino, path.read_bytes())
    original = adapter.dev_instance_registry._private
    def private(selected, **kwargs):
        if Path(selected) == path:
            raise dev_windows_acl.AclVerificationError("EqualSid", category="OWNER_MISMATCH")
        return original(selected, **kwargs)
    monkeypatch.setattr(adapter.dev_instance_registry, "_private", private)
    factory = Mock(side_effect=AssertionError("Unknown lock must not be repaired or adopted"))
    instance.controller.factory = factory
    result = start(instance)
    assert result.code == "INSTANCE_RUNTIME_RECORD_UNVERIFIED" and instance.launches == []
    assert result.to_dict()["inspection"] == {"stage": "runtime-lock", "category": "OWNER_MISMATCH", "winerror": None}
    assert before == (path.lstat().st_ino, path.read_bytes())
    assert SECRET not in json.dumps(result.to_dict())
    factory.assert_not_called()


def test_private_writer_refuses_existing_unknown_state_without_overwrite_or_staging(instance, monkeypatch):
    path = instance.root / ".dev-runtime.json"
    dev_private.create_private_file(path, b"existing fixture state")
    before = (path.lstat().st_ino, path.read_bytes())
    original = adapter.dev_instance_registry._private
    def private(selected, **kwargs):
        if Path(selected) == path:
            raise dev_windows_acl.AclVerificationError("EqualSid", category="OWNER_MISMATCH")
        return original(selected, **kwargs)
    monkeypatch.setattr(adapter.dev_instance_registry, "_private", private)
    create = Mock(side_effect=AssertionError("Unknown state was overwritten"))
    monkeypatch.setattr(dev_private, "create_private_file", create)
    with pytest.raises(adapter.RuntimeAdapterError) as caught:
        adapter.private_atomic_json(path, {"fixture": True}, root=instance.root)
    assert caught.value.inspection.category == "OWNER_MISMATCH"
    assert before == (path.lstat().st_ino, path.read_bytes())
    create.assert_not_called()


@pytest.mark.parametrize("change", [{}, {"APP_ENVIRONMENT": "production"}, {"PYTHON_DOTENV_DISABLED": "0"}, {"SBOM_DEV_RESOURCE_ID": "bad"}])
def test_instance_heartbeat_uses_private_writer_only_for_exact_development_namespace(instance, monkeypatch, change):
    directory = instance.root / ".dev-logs"
    dev_instance_storage.initialize_private_directory(directory, anchor=instance.anchor)
    env = {"SBOM_DEV_RESOURCE_ID": instance.location.descriptor.instance_id, "SBOM_DEV_INSTANCE": "fixture-instance",
           "APP_ENVIRONMENT": "development", "PYTHON_DOTENV_DISABLED": "1", "SBOM_DEV_STATE_DIR": str(directory), **change}
    legacy = Mock(side_effect=AssertionError("Instance heartbeat used default-owner writer"))
    monkeypatch.setattr(dev, "atomic_json", legacy)
    writer = Mock(wraps=adapter.private_atomic_json)
    monkeypatch.setattr(adapter, "private_atomic_json", writer)
    if change:
        with pytest.raises(dev.OwnershipError, match="Instance heartbeat context is unverified"):
            dev.write_service_heartbeat(env, "default")
        writer.assert_not_called()
    else:
        dev.write_service_heartbeat(env, "default")
        writer.assert_called_once()
        adapter.dev_instance_registry._private(directory / "default-health.json")
    legacy.assert_not_called()
