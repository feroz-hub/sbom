"""Windows API boundary regressions; no process_info or tree happy-path stubs.

The WinDLL boundary is deterministic on every CI host. Native disposable-child
coverage at the end also exercises the actual Windows APIs when available.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev


class Kernel:
    """Small stateful kernel32 double, including last-error and handle lifetime."""

    def __init__(self):
        self.last_error = 0
        self.processes = {}
        self.handles = {}
        self.closed = []
        self.terminated = []
        self.next_handle = 40
        self.failures = {}
        self.wait_error = None
        self.wait_results = []
        self.entries = []
        self.entry_index = 0
        self.snapshot_entries = None
        self.snapshot_count = 0
        for name in (
            "OpenProcess", "CloseHandle", "WaitForSingleObject", "GetProcessTimes",
            "QueryFullProcessImageNameW", "TerminateProcess", "CreateToolhelp32Snapshot",
            "Process32FirstW", "Process32NextW",
        ):
            setattr(self, name, Mock(side_effect=getattr(self, "_" + name)))

    def add(self, pid=100, birth=1000, exe=r"C:\Python\python.exe", *, exited=False):
        self.processes[pid] = {"birth": birth, "exe": exe, "exited": exited}
        return {"pid": pid, "birth": str(birth), "exe": exe}

    def fail(self, operation, code, *, exit_process=False):
        self.failures[operation] = (code, exit_process)

    def _failure(self, operation, handle=None):
        if operation not in self.failures:
            return False
        code, exit_process = self.failures[operation]
        self.last_error = code
        if exit_process:
            self.processes[self.handles[handle]]["exited"] = True
        return True

    def _OpenProcess(self, access, inherit, pid):
        if self._failure("OpenProcess"):
            return 0
        if pid not in self.processes:
            self.last_error = 87
            return 0
        if self.processes[pid].get("denied"):
            self.last_error = 5
            return 0
        self.next_handle += 1
        self.handles[self.next_handle] = pid
        return self.next_handle

    def _CloseHandle(self, handle):
        self.closed.append(handle)
        return 1

    def _WaitForSingleObject(self, handle, timeout):
        assert timeout == 0
        if self.wait_results:
            result, code = self.wait_results.pop(0)
            if code is not None:
                self.last_error = code
            return result
        if self.wait_error is not None:
            self.last_error = self.wait_error
            return 0xFFFFFFFF
        return 0 if self.processes[self.handles[handle]]["exited"] else 258

    def _GetProcessTimes(self, handle, created, exited, kernel_time, user_time):
        if self._failure("GetProcessTimes", handle):
            return 0
        process = self.processes[self.handles[handle]]
        created._obj.dwHighDateTime = process["birth"] >> 32
        created._obj.dwLowDateTime = process["birth"] & 0xFFFFFFFF
        exited._obj.dwHighDateTime = 0
        exited._obj.dwLowDateTime = 1 if process["exited"] else 0
        return 1

    def _QueryFullProcessImageNameW(self, handle, flags, buffer, size):
        if self._failure("QueryFullProcessImageNameW", handle):
            return 0
        buffer.value = self.processes[self.handles[handle]]["exe"]
        return 1

    def _TerminateProcess(self, handle, code):
        if self._failure("TerminateProcess", handle):
            return 0
        pid = self.handles[handle]
        self.terminated.append((pid, handle))
        self.processes[pid]["exited"] = True
        return 1

    def _CreateToolhelp32Snapshot(self, flags, pid):
        if self._failure("CreateToolhelp32Snapshot"):
            return ctypes.c_void_p(-1).value
        if self.snapshot_entries is not None:
            self.entries = self.snapshot_entries[min(self.snapshot_count, len(self.snapshot_entries) - 1)]
        self.snapshot_count += 1
        return 900

    def _entry(self, pointer):
        if self.entry_index >= len(self.entries):
            self.last_error = 18
            return 0
        pointer._obj.pid, pointer._obj.parent = self.entries[self.entry_index]
        return 1

    def _Process32FirstW(self, handle, pointer):
        if self._failure("Process32FirstW"):
            return 0
        self.entry_index = 0
        return self._entry(pointer)

    def _Process32NextW(self, handle, pointer):
        if self._failure("Process32NextW"):
            return 0
        self.entry_index += 1
        return self._entry(pointer)


@pytest.fixture
def kernel(monkeypatch):
    value = Kernel()
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(dev.ctypes, "WinDLL", lambda *args, **kwargs: value, raising=False)
    monkeypatch.setattr(dev.ctypes, "get_last_error", lambda: value.last_error, raising=False)
    # These fake workers have no cooperative loop; the dedicated shutdown
    # tests separately exercise warm waiting and the real native Celery loop.
    monkeypatch.setattr(dev, "WINDOWS_SHUTDOWN_GRACE", 0, raising=False)
    return value


def test_windows_live_identity_uses_creation_filetime_and_closes_handle(kernel):
    recorded = kernel.add(birth=(10 << 32) | 123)
    assert dev.process_info(100) == recorded
    assert kernel.closed == [41]
    assert kernel.OpenProcess.call_args.args[0] & 0x100000  # SYNCHRONIZE


def test_windows_exit_before_open_is_absent(kernel):
    assert dev.process_info(100) is None
    kernel.CloseHandle.assert_not_called()


def test_windows_open_access_denied_remains_unknown(kernel):
    kernel.add()
    kernel.fail("OpenProcess", 5)
    with pytest.raises(dev.OwnershipError) as error:
        dev.process_info(100)
    assert "OpenProcess" in str(error.value) and "winerror=5" in str(error.value)
    kernel.TerminateProcess.assert_not_called()


def test_windows_already_exited_handle_skips_image_lookup(kernel):
    kernel.add(exited=True)
    kernel.fail("QueryFullProcessImageNameW", 31)
    assert dev.process_info(100) is None
    kernel.QueryFullProcessImageNameW.assert_not_called()
    assert kernel.closed == [41]


@pytest.mark.parametrize("operation", ["GetProcessTimes", "QueryFullProcessImageNameW"])
def test_windows_exit_during_identity_lookup_is_confirmed_by_same_handle(kernel, operation):
    kernel.add()
    kernel.fail(operation, 31, exit_process=True)
    assert dev.process_info(100) is None
    assert kernel.closed == [41]
    assert {call.args[0] for call in kernel.WaitForSingleObject.call_args_list} == {41}
    assert kernel.WaitForSingleObject.call_count >= 2


@pytest.mark.parametrize("operation", ["GetProcessTimes", "QueryFullProcessImageNameW"])
@pytest.mark.parametrize("code", [5, 31])
def test_windows_lookup_failure_for_live_process_is_never_absence(kernel, operation, code):
    kernel.add()
    kernel.fail(operation, code)
    with pytest.raises(dev.OwnershipError) as error:
        dev.process_info(100)
    assert operation in str(error.value) and f"winerror={code}" in str(error.value)
    assert "UNKNOWN" in str(error.value)
    assert kernel.closed == [41]
    kernel.TerminateProcess.assert_not_called()


def test_windows_wait_failure_preserves_unknown_ownership(kernel):
    kernel.add()
    kernel.wait_error = 6
    with pytest.raises(dev.OwnershipError) as error:
        dev.process_info(100)
    assert "WaitForSingleObject" in str(error.value) and "winerror=6" in str(error.value)
    assert kernel.closed == [41]


@pytest.mark.parametrize("operation", ["CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW"])
def test_windows_enumeration_failure_is_not_partial_success(kernel, operation):
    kernel.add()
    kernel.entries = [(100, 1), (101, 100)]
    kernel.fail(operation, 5)
    with pytest.raises(dev.OwnershipError) as error:
        dev.windows_children(100)
    assert operation in str(error.value) and "winerror=5" in str(error.value)
    if operation != "CreateToolhelp32Snapshot":
        assert 900 in kernel.closed


def test_windows_normal_enumeration_end_and_disappearing_child(kernel):
    parent = kernel.add()
    kernel.entries = [(100, 1), (101, 100)]  # Child exited between snapshot and OpenProcess.
    assert dev.windows_children(100) == [parent]
    assert 900 in kernel.closed


def test_windows_empty_process_snapshot_has_normal_end(kernel):
    kernel.add()
    kernel.entries = []
    result = dev.windows_children(100)
    assert {record["pid"] for record in result} <= {100}
    assert 900 in kernel.closed


@pytest.mark.parametrize("changed", [{"birth": 2000}, {"exe": r"C:\Other\python.exe"}])
def test_windows_termination_revalidates_identity_on_termination_handle(kernel, tmp_path, changed):
    saved = kernel.add()
    kernel.processes[100].update(changed)
    dev.Runtime(tmp_path)._windows_terminate(saved, force=True)
    kernel.TerminateProcess.assert_not_called()
    assert kernel.closed


def test_windows_termination_only_acts_on_verified_individual_handles(kernel, monkeypatch, tmp_path):
    parent = kernel.add()
    child = kernel.add(101, birth=2000)
    reused = kernel.add(102, birth=3000)
    kernel.processes[102]["birth"] = 4000
    parent["members"] = [parent.copy(), child, reused]
    runner = Mock(side_effect=AssertionError("PID-based taskkill must not be used"))
    monkeypatch.setattr(dev.subprocess, "run", runner)
    dev.Runtime(tmp_path)._windows_terminate(parent, force=True)
    assert {pid for pid, handle in kernel.terminated} == {100, 101}
    assert len(kernel.terminated) == 2
    for pid, handle in kernel.terminated:
        assert kernel.handles[handle] == pid
        assert handle in kernel.closed
    runner.assert_not_called()


def test_windows_denied_termination_preserves_record(kernel, tmp_path):
    saved = kernel.add()
    kernel.fail("OpenProcess", 5)
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {"API": saved},
    }
    dev.atomic_json(runtime.path, runtime.state)
    assert not runtime.stop_services(lambda *args: None)
    assert runtime.load()["services"]["API"] == saved
    kernel.TerminateProcess.assert_not_called()


def test_cleanup_continues_after_component_inspection_error(monkeypatch, tmp_path):
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test",
        "services": {"Celery worker": {"pid": 100}, "Celery Beat": {"pid": 101}},
    }
    calls = []
    def terminate(record):
        calls.append(record["pid"])
        if record["pid"] == 101:
            raise dev.OwnershipError("Process32NextW winerror=5 status=UNKNOWN")
        return True
    monkeypatch.setattr(runtime, "terminate", terminate)
    output = []
    assert not runtime.stop_services(lambda *args: output.append(args))
    assert calls == [101, 100]
    assert list(runtime.load()["services"]) == ["Celery Beat"]
    assert "Celery Beat" in str(output)


@pytest.mark.skipif(sys.platform != "win32", reason="actual Windows process handles")
def test_native_windows_exited_handle_is_absent_before_parent_reaps():
    child = subprocess.Popen([sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Wait directly on the kernel handle, retaining Popen's original handle.
        from ctypes import wintypes
        native = ctypes.WinDLL("kernel32", use_last_error=True)
        native.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        native.WaitForSingleObject.restype = wintypes.DWORD
        assert native.WaitForSingleObject(int(child._handle), 10000) == 0
        assert child.returncode is None
        assert dev.process_info(child.pid) is None
    finally:
        child.wait(timeout=10)


@pytest.mark.parametrize("cleanup_uncertain", [False, True])
def test_windows_partial_startup_failure_cleans_verified_worker(kernel, monkeypatch, tmp_path, cleanup_uncertain):
    kernel.add(os.getpid(), birth=100)
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "BEAT_LOCK", tmp_path / ".dev-beat.pid")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_LEGACY_CONFIG", "managed")
    args = dev.parse_args(["start", "--profile", "legacy", "--legacy-config", "managed"])
    monkeypatch.setattr(dev, "parse_args", lambda: args)
    monkeypatch.setattr(dev, "validate_repository_layout", lambda: None)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda: None)
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: None)
    monkeypatch.setattr(dev.Runtime, "acquire", lambda self: True)
    monkeypatch.setattr(dev.signal, "signal", lambda *args: None)

    def start(args):
        kernel.add(100)
        dev.ACTIVE_RUNTIME.processes[100] = SimpleNamespace(poll=lambda: None)
        dev.ACTIVE_RUNTIME.register("Celery worker", 100)
        if cleanup_uncertain:
            kernel.fail("Process32FirstW", 5)
        raise dev.SetupError("synthetic Beat startup failure")

    monkeypatch.setattr(dev, "start_application", start)
    with pytest.raises(dev.SetupError, match="synthetic Beat startup failure"):
        dev.main()
    assert {pid for pid, handle in kernel.terminated} == {100}
    assert (tmp_path / ".dev-runtime.json").exists() is cleanup_uncertain
    assert dev.ACTIVE_RUNTIME is None


def test_windows_failed_refresh_preserves_previous_descendant_proofs(kernel, tmp_path):
    parent = kernel.add()
    child = kernel.add(101, birth=2000)
    parent["members"] = [parent.copy(), child]
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {"Celery Beat": parent},
    }
    dev.atomic_json(runtime.path, runtime.state)
    kernel.fail("Process32FirstW", 5)
    with pytest.raises((dev.OwnershipError, dev.SetupError)):
        runtime.refresh()
    assert runtime.load()["services"]["Celery Beat"]["members"][-1] == child
    kernel.TerminateProcess.assert_not_called()


def readiness_runtime(tmp_path, parent, child):
    runtime = dev.Runtime(tmp_path)
    parent["members"] = [parent.copy(), child]
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {"Celery worker": parent},
    }
    return runtime


def test_windows_redirected_worker_pid_can_attest_readiness_only_when_verified(kernel, tmp_path):
    parent = kernel.add()
    child = kernel.add(101, birth=2000)
    kernel.entries = [(100, 1), (101, 100)]
    runtime = readiness_runtime(tmp_path, parent, child)
    assert dev.service_pid_matches(runtime, parent, 101)
    assert dev.service_pid_matches(runtime, parent, 100)


@pytest.mark.parametrize("change", [
    {"birth": 3000}, {"exe": r"C:\Other\python.exe"}, {"exited": True},
])
def test_windows_redirected_worker_pid_cannot_attest_after_identity_change(kernel, tmp_path, change):
    parent = kernel.add()
    child = kernel.add(101, birth=2000)
    runtime = readiness_runtime(tmp_path, parent, child)
    kernel.processes[101].update(change)
    assert not dev.service_pid_matches(runtime, parent, 101)


def test_windows_unrecorded_or_uninspectable_worker_pid_cannot_attest_readiness(kernel, tmp_path):
    parent = kernel.add()
    child = kernel.add(101, birth=2000)
    kernel.add(102, birth=3000)
    runtime = readiness_runtime(tmp_path, parent, child)
    assert not dev.service_pid_matches(runtime, parent, 102)
    kernel.fail("OpenProcess", 5)
    assert not dev.service_pid_matches(runtime, parent, 101)


@pytest.mark.parametrize("operation", ["GetProcessTimes", "QueryFullProcessImageNameW"])
def test_windows_lookup_failure_and_failed_exit_probe_remain_unknown(kernel, operation):
    kernel.add()
    kernel.fail(operation, 31)
    kernel.wait_results = [(258, None), (0xFFFFFFFF, 6)]
    with pytest.raises(dev.OwnershipError) as error:
        dev.process_info(100)
    assert operation in str(error.value) and "winerror=31" in str(error.value)
    assert "UNKNOWN" in str(error.value)
    assert kernel.closed == [41]
    kernel.TerminateProcess.assert_not_called()


def test_windows_process_tree_rejects_stale_parent_pid_edge(kernel):
    parent = kernel.add(birth=2000)
    kernel.add(101, birth=1000)
    kernel.entries = [(100, 1), (101, 100)]
    assert dev.windows_children(100) == [parent]


def test_windows_process_tree_rejects_changed_parent_across_pinned_snapshots(kernel):
    parent = kernel.add()
    kernel.add(101, birth=2000)
    kernel.snapshot_entries = [
        [(100, 1), (101, 100)],
        [(100, 1), (101, 1)],
    ]
    assert dev.windows_children(100) == [parent]
    assert kernel.snapshot_count == 2
    assert {41, 42, 900} <= set(kernel.closed)


@pytest.mark.parametrize("uncertain", ["denied", "reused"])
def test_windows_unknown_member_does_not_block_verified_sibling_cleanup(kernel, tmp_path, uncertain):
    parent = kernel.add(exited=True)
    child = kernel.add(101, birth=2000)
    protected = kernel.add(102, birth=3000)
    parent["members"] = [parent.copy(), child, protected]
    if uncertain == "denied":
        kernel.processes[102]["denied"] = True
    else:
        kernel.processes[102]["birth"] = 4000
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {"Celery worker": parent},
    }
    assert not runtime.stop_services(lambda *args: None)
    assert {pid for pid, handle in kernel.terminated} == {101}
    assert not kernel.processes[102]["exited"]
    assert runtime.load()["services"]["Celery worker"]["members"][-1] == protected


def test_windows_uncertain_tree_record_survives_repeated_stop(kernel, tmp_path):
    parent = kernel.add()
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {"Celery Beat": parent},
    }
    kernel.fail("Process32FirstW", 5)
    assert not runtime.stop_services(lambda *args: None)
    assert kernel.processes[100]["exited"]
    assert not runtime.stop_services(lambda *args: None)
    assert "Celery Beat" in runtime.load()["services"]


def test_windows_registration_cleanup_failure_preserves_original_inspection_diagnosis(kernel, monkeypatch, tmp_path):
    runtime = dev.Runtime(tmp_path)
    runtime.state = {
        "version": 1, "root": str(runtime.root), "instance": "test", "services": {},
    }
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "ACTIVE_PROFILE", "legacy")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", runtime)
    monkeypatch.setattr(dev.GreenfieldStack, "node_binary", lambda: tmp_path / "node.exe")
    child = SimpleNamespace(pid=100, poll=lambda: None, returncode=None)
    monkeypatch.setattr(dev.subprocess, "Popen", lambda *args, **kwargs: child)
    monkeypatch.setattr(runtime, "register", Mock(side_effect=dev.OwnershipError(
        "QueryFullProcessImageNameW failed winerror=31 status=UNKNOWN"
    )))
    monkeypatch.setattr(dev, "stop_processes", Mock(side_effect=PermissionError("synthetic cleanup denied")))
    with pytest.raises(dev.OwnershipError) as error:
        dev.start_process("Celery Beat", ["fixture-command"], {"PATH": ""}, cwd=tmp_path)
    assert "QueryFullProcessImageNameW" in str(error.value) and "winerror=31" in str(error.value)
    assert "cleanup" in str(error.value).lower()
    assert "Celery Beat" in runtime.load()["services"]


@pytest.mark.parametrize("code", [5, 32, 33])
def test_windows_atomic_json_retries_transient_sharing_errors(kernel, monkeypatch, tmp_path, code):
    target = tmp_path / "beat-health.json"
    dev.atomic_json(target, {"phase": "old"})
    replace = dev.os.replace
    attempts, delays = [], []
    error = PermissionError("synthetic Windows sharing conflict")
    error.winerror = code

    def intermittent(source, destination):
        attempts.append((source, destination))
        if len(attempts) <= 3:
            assert json.loads(target.read_text()) == {"phase": "old"}
            raise error
        replace(source, destination)

    monkeypatch.setattr(dev.os, "replace", intermittent)
    monkeypatch.setattr(dev.time, "sleep", delays.append)
    value = {"phase": "ready", "pid": 100, "data": [1, 2, 3]}
    dev.atomic_json(target, value)
    assert json.loads(target.read_text()) == value
    assert len(attempts) == 4 and len(delays) == 3
    assert 0 < sum(delays) <= 0.85
    assert not list(tmp_path.glob("beat-health.json.*.tmp"))


def test_windows_atomic_json_permanent_denial_is_bounded_and_preserves_target(kernel, monkeypatch, tmp_path):
    target = tmp_path / "beat-health.json"
    dev.atomic_json(target, {"phase": "old"})
    attempts, delays = [], []
    error = PermissionError("synthetic permanent Windows denial")
    error.winerror = 5

    def denied(source, destination):
        attempts.append((source, destination))
        raise error

    monkeypatch.setattr(dev.os, "replace", denied)
    monkeypatch.setattr(dev.time, "sleep", delays.append)
    with pytest.raises(PermissionError) as raised:
        dev.atomic_json(target, {"phase": "ready"})
    assert raised.value is error
    assert 1 < len(attempts) <= 11
    assert len(delays) == len(attempts) - 1 and sum(delays) <= 0.85
    assert json.loads(target.read_text()) == {"phase": "old"}
    assert not list(tmp_path.glob("beat-health.json.*.tmp"))


@pytest.mark.parametrize("platform,code", [("win32", 2), ("linux", 5), ("darwin", 32)])
def test_atomic_json_other_errors_and_unix_are_not_retried(kernel, monkeypatch, tmp_path, platform, code):
    monkeypatch.setattr(dev.sys, "platform", platform)
    target = tmp_path / "beat-health.json"
    dev.atomic_json(target, {"phase": "old"})
    error = PermissionError("synthetic non-retryable failure")
    error.winerror = code
    replace = Mock(side_effect=error)
    sleep = Mock(side_effect=AssertionError("unexpected retry"))
    monkeypatch.setattr(dev.os, "replace", replace)
    monkeypatch.setattr(dev.time, "sleep", sleep)
    with pytest.raises(PermissionError) as raised:
        dev.atomic_json(target, {"phase": "ready"})
    assert raised.value is error
    replace.assert_called_once()
    sleep.assert_not_called()
    assert json.loads(target.read_text()) == {"phase": "old"}
    assert not list(tmp_path.glob("beat-health.json.*.tmp"))


@pytest.mark.skipif(sys.platform != "win32", reason="actual Windows file-sharing semantics")
def test_native_windows_atomic_json_waits_for_concurrent_reader(monkeypatch, tmp_path):
    from ctypes import wintypes

    target = tmp_path / "beat-health.json"
    dev.atomic_json(target, {"phase": "old"})
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    native.CreateFileW.restype = wintypes.HANDLE
    native.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    native.CloseHandle.argtypes = [wintypes.HANDLE]
    # A real reader sharing reads/writes, but not deletion/rename, like the
    # launcher's brief read_text while Beat replaces its heartbeat.
    handle = native.CreateFileW(str(target), 0x80000000, 0x1 | 0x2, None, 3, 0x80, None)
    assert handle != ctypes.c_void_p(-1).value
    first_conflict = threading.Event()
    released = threading.Event()
    replace = dev.os.replace
    conflicts = []

    def observed_replace(source, destination):
        try:
            return replace(source, destination)
        except PermissionError as error:
            conflicts.append(error.winerror)
            first_conflict.set()
            raise

    def reader():
        first_conflict.wait(timeout=10)
        native.CloseHandle(handle)
        released.set()

    thread = threading.Thread(target=reader)
    thread.start()
    monkeypatch.setattr(dev.os, "replace", observed_replace)
    try:
        value = {"phase": "ready", "data": list(range(100))}
        dev.atomic_json(target, value)
        assert released.wait(timeout=10)
        assert conflicts and set(conflicts) <= {5, 32, 33}
        assert json.loads(target.read_text()) == value
        assert not list(tmp_path.glob("beat-health.json.*.tmp"))
    finally:
        first_conflict.set()
        thread.join(timeout=10)
        assert not thread.is_alive()



def test_windows_main_cleanup_persistence_error_keeps_startup_diagnosis(kernel, monkeypatch, tmp_path, capsys):
    kernel.add(os.getpid(), birth=100)
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "BEAT_LOCK", tmp_path / ".dev-beat.pid")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    args = dev.parse_args(["start", "--profile", "legacy", "--legacy-config", "managed"])
    monkeypatch.setattr(dev, "parse_args", lambda: args)
    monkeypatch.setattr(dev, "validate_repository_layout", lambda: None)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda: None)
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: None)
    monkeypatch.setattr(dev.Runtime, "acquire", lambda self: True)
    monkeypatch.setattr(dev.signal, "signal", lambda *args: None)
    def stop(runtime, say):
        if runtime.state:
            failure = PermissionError("synthetic runtime sharing denial")
            failure.winerror = 5
            raise failure
        return True
    monkeypatch.setattr(dev.Runtime, "stop_services", stop)
    monkeypatch.setattr(dev, "start_application", Mock(side_effect=dev.SetupError("original startup diagnosis")))
    with pytest.raises(dev.SetupError, match="original startup diagnosis"):
        dev.main()
    assert "Cleanup failed (PermissionError, winerror=5)" in capsys.readouterr().out
    assert dev.ACTIVE_RUNTIME is None
    assert (tmp_path / ".dev-runtime.json").exists()
