"""Identity-bound Windows warm shutdown and verified escalation regressions."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev

from tests.test_dev_windows_lifecycle import Kernel


@pytest.fixture
def kernel(monkeypatch):
    value = Kernel()
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(dev.ctypes, "WinDLL", lambda *args, **kwargs: value, raising=False)
    monkeypatch.setattr(dev.ctypes, "get_last_error", lambda: value.last_error, raising=False)
    monkeypatch.setattr(dev, "WINDOWS_SHUTDOWN_GRACE", 0.3, raising=False)
    return value


def managed_runtime(tmp_path, kernel, component="Celery worker", pid=100):
    runtime = dev.Runtime(tmp_path)
    record = kernel.add(pid)
    record["shutdown"] = {"instance": "shutdown-fixture", "component": component}
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "shutdown-fixture", "profile": "legacy",
        "services": {component: record},
    }
    kernel.entries = [(pid, 1)]
    dev.atomic_json(runtime.path, runtime.state)
    return runtime, record


def request_path(runtime, pid):
    return dev.windows_shutdown_path(runtime.root / ".dev-logs", runtime.state["instance"], pid)


def test_windows_nonforce_only_publishes_for_verified_individuals(kernel, tmp_path, monkeypatch):
    runtime, record = managed_runtime(tmp_path, kernel)
    child = kernel.add(101, birth=2000)
    reused = kernel.add(102, birth=3000)
    record["members"] = [record.copy(), child, reused]
    kernel.processes[102]["birth"] = 4000
    forbidden = Mock(side_effect=AssertionError("no console or PID command may implement warm shutdown"))
    monkeypatch.setattr(dev.subprocess, "run", forbidden)
    runtime._windows_terminate(record, force=False)
    root_request = json.loads(request_path(runtime, 100).read_text())
    child_request = json.loads(request_path(runtime, 101).read_text())
    assert root_request == {**{k: record[k] for k in ("pid", "birth", "exe")}, "instance": "shutdown-fixture"}
    assert child_request == {**child, "instance": "shutdown-fixture"}
    assert not request_path(runtime, 102).exists()
    assert all(not call.args[0] & 1 for call in kernel.OpenProcess.call_args_list)  # no PROCESS_TERMINATE
    kernel.TerminateProcess.assert_not_called()
    forbidden.assert_not_called()


def test_windows_nonforce_access_denied_does_not_publish_or_terminate(kernel, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    kernel.processes[100]["denied"] = True
    with pytest.raises(dev.OwnershipError, match="winerror=5"):
        runtime._windows_terminate(record, force=False)
    assert not request_path(runtime, 100).exists()
    kernel.TerminateProcess.assert_not_called()


@pytest.mark.parametrize("mismatch", ["instance", "component"])
def test_windows_nonforce_unregistered_protocol_never_targets_a_process(kernel, tmp_path, mismatch):
    runtime, record = managed_runtime(tmp_path, kernel)
    record["shutdown"][mismatch] = "not-owned"
    runtime._windows_terminate(record, force=False)
    assert not list(tmp_path.rglob("shutdown-*.json"))
    kernel.TerminateProcess.assert_not_called()


def test_windows_nonforce_without_hook_never_disguises_terminate_as_graceful(kernel, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    record.pop("shutdown")
    runtime._windows_terminate(record, force=False)
    assert not list(tmp_path.rglob("shutdown-*.json"))
    kernel.TerminateProcess.assert_not_called()


@pytest.mark.parametrize("change", [
    {"instance": "previous-instance"}, {"pid": 999}, {"birth": "reused"},
    {"exe": r"C:\Other\python.exe"}, {"birth": None}, {"exe": ""},
])
def test_windows_child_rejects_stale_or_foreign_shutdown_request(kernel, monkeypatch, tmp_path, change):
    saved = kernel.add()
    monkeypatch.setattr(dev.os, "getpid", lambda: 100)
    env = {"SBOM_DEV_INSTANCE": "shutdown-fixture", "SBOM_DEV_STATE_DIR": str(tmp_path)}
    path = dev.windows_shutdown_path(tmp_path, "shutdown-fixture", 100)
    dev.atomic_json(path, {**saved, "instance": "shutdown-fixture", **change})
    assert dev.windows_shutdown_requested(env) is False
    kernel.TerminateProcess.assert_not_called()


def test_windows_child_accepts_only_matching_live_identity(kernel, monkeypatch, tmp_path):
    saved = kernel.add()
    monkeypatch.setattr(dev.os, "getpid", lambda: 100)
    env = {"SBOM_DEV_INSTANCE": "shutdown-fixture", "SBOM_DEV_STATE_DIR": str(tmp_path)}
    dev.atomic_json(dev.windows_shutdown_path(tmp_path, "shutdown-fixture", 100), {**saved, "instance": "shutdown-fixture"})
    assert dev.windows_shutdown_requested(env) is True
    kernel.processes[100]["denied"] = True
    assert dev.windows_shutdown_requested(env) is False
    kernel.processes[100]["denied"] = False
    kernel.processes[100]["exited"] = True
    assert dev.windows_shutdown_requested(env) is False


@pytest.mark.parametrize("content", ["not-json", "[]", "null", "{}"])
def test_windows_missing_or_malformed_shutdown_request_is_not_authority(kernel, monkeypatch, tmp_path, content):
    kernel.add()
    monkeypatch.setattr(dev.os, "getpid", lambda: 100)
    env = {"SBOM_DEV_INSTANCE": "shutdown-fixture", "SBOM_DEV_STATE_DIR": str(tmp_path)}
    assert dev.windows_shutdown_requested(env) is False
    dev.windows_shutdown_path(tmp_path, "shutdown-fixture", 100).write_text(content)
    assert dev.windows_shutdown_requested(env) is False


@pytest.mark.parametrize("instance,pid", [("../escape", 100), ("", 100), ("ok", 0), ("ok", True), ("ok", 2**32)])
def test_windows_shutdown_filename_cannot_escape_owned_directory(tmp_path, instance, pid):
    with pytest.raises(dev.OwnershipError):
        dev.windows_shutdown_path(tmp_path, instance, pid)


def fake_clock(monkeypatch, on_sleep=lambda: None):
    clock = [0.0]
    monkeypatch.setattr(dev.time, "monotonic", lambda: clock[0])
    def sleep(seconds):
        clock[0] += seconds
        on_sleep()
    monkeypatch.setattr(dev.time, "sleep", sleep)
    return clock


def test_windows_warm_completion_exits_without_forced_termination(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    def finish():
        assert request_path(runtime, 100).exists()
        kernel.processes[100]["exited"] = True
    fake_clock(monkeypatch, finish)
    assert runtime.terminate(record, timeout=1)
    kernel.TerminateProcess.assert_not_called()


def test_windows_grace_deadline_warns_then_forces_only_revalidated_owned_process(kernel, monkeypatch, tmp_path, capsys):
    runtime, record = managed_runtime(tmp_path, kernel)
    kernel.add(999, birth=9999)
    clock = fake_clock(monkeypatch)
    assert runtime.terminate(record, timeout=0.3)
    assert clock[0] >= 0.3
    assert {pid for pid, handle in kernel.terminated} == {100}
    assert not kernel.processes[999]["exited"]
    output = capsys.readouterr().out.lower()
    assert "warn" in output and "forc" in output and ("task" in output or "work" in output)


def test_windows_pid_reuse_during_grace_is_protected(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    fake_clock(monkeypatch, lambda: kernel.processes[100].update(birth=2000))
    assert not runtime.terminate(record, timeout=0.3)
    assert not kernel.processes[100]["exited"]
    kernel.TerminateProcess.assert_not_called()


def test_windows_stop_requests_all_workers_before_waiting_for_either(kernel, monkeypatch, tmp_path):
    runtime, first = managed_runtime(tmp_path, kernel)
    second = kernel.add(101, birth=2000)
    second["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = second
    kernel.entries = [(100, 1), (101, 1)]
    paths = [request_path(runtime, pid) for pid in (100, 101)]
    def finish_both():
        assert all(path.exists() for path in paths)
        for pid in (100, 101):
            kernel.processes[pid]["exited"] = True
    clock = fake_clock(monkeypatch, finish_both)
    assert runtime.stop_services(lambda *args: None)
    assert runtime._shutdown_deadline is None
    assert clock[0] <= 0.3
    kernel.TerminateProcess.assert_not_called()


def test_windows_stop_shares_one_bounded_grace_window(kernel, monkeypatch, tmp_path):
    runtime, first = managed_runtime(tmp_path, kernel)
    second = kernel.add(101, birth=2000)
    second["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = second
    kernel.entries = [(100, 1), (101, 1)]
    clock = fake_clock(monkeypatch)
    assert runtime.stop_services(lambda *args: None)
    assert clock[0] <= 0.4
    assert {pid for pid, handle in kernel.terminated} == {100, 101}


NATIVE_PROGRAM = r'''
import json,os,sys,threading,time,types
from pathlib import Path
from celery import Celery
from scripts import dev
folder=Path(sys.argv[1]); mode=sys.argv[2]
app=Celery('owned-shutdown-fixture',broker='memory://',backend='cache+memory://')
app.conf.update(worker_hijack_root_logger=False,worker_enable_remote_control=False,task_serializer='json',accept_content=['json'])
stub=types.ModuleType('app.workers.celery_app');stub.celery_app=app
sys.modules['app.workers.celery_app']=stub
dev.local_celery_app()
if mode=='worker':
    from celery.signals import worker_ready,worker_shutdown
    from celery.worker import state
    @app.task(name='fixture.busy',acks_late=True)
    def busy():
        (folder/'started').touch()
        deadline=time.monotonic()+15
        while state.should_stop is None:
            if time.monotonic()>deadline: raise RuntimeError('warm request was not observed')
            time.sleep(.01)
        (folder/'warm-seen').touch()
        time.sleep(.3)
        (folder/'completed').write_text(str(time.time_ns()))
    def ready(**kwargs):
        app.send_task('fixture.busy')
    def closed(**kwargs):
        (folder/'closed').write_text(str(time.time_ns()))
    worker_ready.connect(ready,weak=False);worker_shutdown.connect(closed,weak=False)
    app.Worker(pool='solo',concurrency=1,without_gossip=True,without_mingle=True,without_heartbeat=True,loglevel='WARNING').start()
else:
    from celery.beat import Service
    class Scheduler:
        max_interval=.1
        def __init__(self,**kwargs): pass
        def tick(self):
            (folder/'started').touch();return .1
        def should_sync(self): return False
        def close(self):
            (folder/'closed').write_text('scheduler-persisted')
    Service(app,scheduler_cls=Scheduler,max_interval=.1).start()
'''


@pytest.mark.skipif(sys.platform != "win32", reason="actual Windows native cooperative process shutdown")
@pytest.mark.parametrize("mode,component", [("worker", "Celery worker"), ("beat", "Celery Beat")])
def test_native_windows_cooperative_task_completion_and_scheduler_close(tmp_path, monkeypatch, mode, component):
    runtime = dev.Runtime(tmp_path)
    assert runtime.acquire()
    runtime.begin("legacy")
    state_dir = tmp_path / ".dev-logs"
    state_dir.mkdir()
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, (str(Path(dev.__file__).resolve().parents[1]), os.environ.get("PYTHONPATH", "")))), PYTHON_DOTENV_DISABLED="1",
               SBOM_DEV_INSTANCE=runtime.state["instance"], SBOM_DEV_STATE_DIR=str(state_dir), SBOM_DEV_PROFILE="legacy")
    child = unrelated = None
    log = tmp_path / "fixture.log"
    record = None
    try:
        unrelated = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-c", "import time; time.sleep(40)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with log.open("wb") as output:
            child = subprocess.Popen([sys.executable, "-u", "-c", NATIVE_PROGRAM, str(tmp_path), mode], env=env,
                                     stdout=output, stderr=subprocess.STDOUT, **dev.platform_spawn_options())
        runtime.processes[child.pid] = child
        runtime.register(component, child.pid)
        record = runtime.state["services"][component]
        deadline = time.monotonic() + 15
        while not (tmp_path / "started").exists():
            assert child.poll() is None, log.read_text(errors="replace")
            assert time.monotonic() < deadline, log.read_text(errors="replace")
            runtime.refresh()
            time.sleep(.05)
        runtime.refresh()
        forced = []
        original = runtime._windows_terminate
        def terminate(saved, *, force):
            forced.append(force)
            return original(saved, force=force)
        monkeypatch.setattr(runtime, "_windows_terminate", terminate)
        assert runtime.terminate(record, timeout=8), log.read_text(errors="replace")
        assert child.wait(timeout=5) == 0, log.read_text(errors="replace")
        assert True not in forced
        assert unrelated.poll() is None
        assert (tmp_path / "closed").exists(), log.read_text(errors="replace")
        if mode == "worker":
            assert (tmp_path / "warm-seen").exists()
            assert int((tmp_path / "completed").read_text()) <= int((tmp_path / "closed").read_text())
        else:
            assert (tmp_path / "closed").read_text() == "scheduler-persisted"
    finally:
        if record is not None:
            runtime._windows_terminate(record, force=True)  # Only independently reverified test-owned processes.
        runtime.release()
        if child is not None:
            child.wait(timeout=10)
        if unrelated is not None:
            unrelated.terminate()  # Original Popen handle for this test's unrelated fixture.
            unrelated.wait(timeout=10)


def test_windows_request_persistence_failure_reports_and_cleans_verified_siblings(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    sibling = kernel.add(101, birth=2000)
    sibling["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = sibling
    kernel.entries = [(100, 1), (101, 1)]
    sibling_path = request_path(runtime, 101)
    original = dev.atomic_json
    def publish(path, value):
        if Path(path).name == "shutdown-shutdown-fixture-100.json":
            failure = PermissionError("synthetic protected request file")
            failure.winerror = 5
            raise failure
        return original(path, value)
    monkeypatch.setattr(dev, "atomic_json", publish)
    def finish_sibling():
        assert sibling_path.exists()
        kernel.processes[101]["exited"] = True
    fake_clock(monkeypatch, finish_sibling)
    messages = []
    assert runtime.stop_services(lambda *args: messages.append(args))
    assert kernel.processes[101]["exited"]
    assert {pid for pid, handle in kernel.terminated} == {100}
    assert not runtime.path.exists()
    assert "winerror=5" in str(messages)
    assert "cooperative request persistence failed" in str(messages)
    assert "tree_unverified" not in record


def test_windows_unsupported_component_reports_forced_fallback_without_fake_grace(kernel, monkeypatch, tmp_path, capsys):
    runtime, record = managed_runtime(tmp_path, kernel, component="API")
    clock = fake_clock(monkeypatch)
    assert runtime.terminate(record)
    assert clock[0] == 0
    assert {pid for pid, handle in kernel.terminated} == {100}
    assert not list(tmp_path.rglob("shutdown-*.json"))
    text = capsys.readouterr().out.lower()
    assert "no cooperative shutdown hook" in text and "forcing only verified handles" in text



def test_windows_failed_batch_resets_grace_deadline_before_standalone_retry(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    kernel.processes[100]["denied"] = True
    original = dev.atomic_json
    def persist(path, value):
        if Path(path) == runtime.path:
            raise PermissionError("synthetic runtime persistence failure")
        return original(path, value)
    monkeypatch.setattr(dev, "atomic_json", persist)
    finish = [False]
    def complete_on_retry():
        if finish[0]:
            kernel.processes[101]["exited"] = True
    clock = fake_clock(monkeypatch, complete_on_retry)
    with pytest.raises(PermissionError, match="runtime persistence failure"):
        runtime.stop_services(lambda *args: None)
    assert runtime._shutdown_deadline is None
    before_retry = clock[0]
    # Keep the first record's genuine uncertainty. A fresh, independently
    # verified standalone service on the same Runtime gets a fresh grace bound.
    fresh = kernel.add(101, birth=2000)
    fresh["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = fresh
    kernel.entries = [(100, 1), (101, 1)]
    finish[0] = True
    assert runtime.terminate(fresh)
    assert record["tree_unverified"] is True
    assert clock[0] > before_retry
    kernel.TerminateProcess.assert_not_called()


def test_windows_batch_snapshots_every_worker_before_any_request_and_never_resnapshots_drain(kernel, monkeypatch, tmp_path):
    runtime, first = managed_runtime(tmp_path, kernel)
    second = kernel.add(101, birth=2000)
    second["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = second
    kernel.entries = [(100, 1), (101, 1)]
    events = []
    snapshot = runtime._snapshot_members
    def capture(record):
        events.append(("snapshot", record["pid"]))
        return snapshot(record)
    monkeypatch.setattr(runtime, "_snapshot_members", capture)
    terminate = runtime._windows_terminate
    def request(record, *, force):
        if not force:
            assert events[:2] == [("snapshot", 100), ("snapshot", 101)]
            events.append(("request", record["pid"]))
        return terminate(record, force=force)
    monkeypatch.setattr(runtime, "_windows_terminate", request)
    fake_clock(monkeypatch, lambda: [kernel.processes[pid].update(exited=True) for pid in (100, 101)])
    assert runtime.stop_services(lambda *args: None)
    assert [event for event in events if event[0] == "snapshot"] == [("snapshot", 100), ("snapshot", 101)]
    assert runtime._shutdown_prepared == set()
    kernel.TerminateProcess.assert_not_called()


def test_windows_closing_identity_query_uncertainty_can_resolve_to_confirmed_absence(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    terminate = runtime._windows_terminate
    requested = [False]
    def request(saved, *, force):
        result = terminate(saved, force=force)
        if not force and not requested[0]:
            requested[0] = True
            kernel.processes[100]["denied"] = True
        return result
    monkeypatch.setattr(runtime, "_windows_terminate", request)
    def finish():
        # A completed pre-shutdown snapshot remains proof of the known tree.
        # A closing-process access denial is still UNKNOWN until actual absence.
        assert "tree_unverified" not in record
        kernel.processes.pop(100)
    fake_clock(monkeypatch, finish)
    assert runtime.stop_services(lambda *args: None)
    assert not runtime.path.exists()
    assert "tree_unverified" not in record
    assert runtime._shutdown_prepared == set()
    kernel.TerminateProcess.assert_not_called()


def test_windows_failed_pre_shutdown_snapshot_remains_sticky_after_known_processes_exit(kernel, monkeypatch, tmp_path):
    runtime, first = managed_runtime(tmp_path, kernel)
    second = kernel.add(101, birth=2000)
    second["shutdown"] = {"instance": "shutdown-fixture", "component": "Celery reports worker"}
    runtime.state["services"]["Celery reports worker"] = second
    kernel.entries = [(100, 1), (101, 1)]
    snapshot = runtime._snapshot_members
    captures = []
    def capture(record):
        captures.append(record["pid"])
        if record["pid"] == 100:
            raise dev.OwnershipError("Process32NextW failed (winerror=5; status=UNKNOWN)")
        return snapshot(record)
    monkeypatch.setattr(runtime, "_snapshot_members", capture)
    fake_clock(monkeypatch, lambda: [kernel.processes[pid].update(exited=True) for pid in (100, 101)])
    assert not runtime.stop_services(lambda *args: None)
    saved = runtime.load()["services"]
    assert list(saved) == ["Celery worker"]
    assert saved["Celery worker"]["tree_unverified"] is True
    assert "Process32NextW" in saved["Celery worker"]["inspection_error"]
    assert captures == [100, 101]
    assert runtime._shutdown_prepared == set()
    assert not runtime.stop_services(lambda *args: None)
    assert runtime.load()["services"]["Celery worker"]["tree_unverified"] is True
    kernel.TerminateProcess.assert_not_called()


def test_windows_prior_uncertain_tree_is_not_cleared_by_a_new_batch(kernel, monkeypatch, tmp_path):
    runtime, record = managed_runtime(tmp_path, kernel)
    record["tree_unverified"] = True
    record["inspection_error"] = "Previous snapshot could not verify all descendants"
    kernel.processes[100]["exited"] = True
    fake_clock(monkeypatch)
    assert not runtime.stop_services(lambda *args: None)
    retained = runtime.load()["services"]["Celery worker"]
    assert retained["tree_unverified"] is True
    assert "Previous snapshot" in retained["inspection_error"]
    assert runtime._shutdown_prepared == set()
    kernel.TerminateProcess.assert_not_called()
