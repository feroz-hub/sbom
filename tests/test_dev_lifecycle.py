"""Lifecycle safety tests: all process inspection and termination are mocked."""
from __future__ import annotations

import errno
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from scripts import dev
from scripts import dev as lifecycle

process_info_adapter = lifecycle.process_info
# These cases exercise POSIX process-group and macOS libproc branches whose
# primitives (os.killpg, os.getsid, signal.SIGKILL) do not exist on Windows;
# CI runs them on Linux and macOS.
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX/macOS process primitives")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    for name in dev.REQUIRED_FILES:  # A complete checkout, so layout validation passes.
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).touch()
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "BEAT_LOCK", tmp_path / ".dev-beat.pid")
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)
    monkeypatch.setattr(dev, "read_config", lambda: {})
    monkeypatch.setattr(dev, "reachable", lambda *args: False)
    monkeypatch.setattr(dev, "service_available", lambda *args: False)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: False)
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: None)
    monkeypatch.setattr(dev, "validate_repository_layout", lambda *args, **kwargs: None, raising=False)
    monkeypatch.setattr(dev, "validate_prerequisites", lambda *args, **kwargs: None, raising=False)
    monkeypatch.setattr(dev, "resolve_profile", lambda requested="auto": "legacy" if requested == "auto" else requested, raising=False)
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: None)
    monkeypatch.setattr(lifecycle, "group_members", lambda pid: [])
    monkeypatch.setattr(dev, "process_info", lambda pid: None)
    # raising=False: os.killpg does not exist on Windows, where this tripwire is simply added.
    monkeypatch.setattr(lifecycle.os, "killpg", lambda *args: pytest.fail("Unmocked signal"), raising=False)
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda *args, **kwargs: pytest.fail("Unmocked process command"))


def identity(pid=100, birth="boot:100", **extra):
    return {"pid": pid, "birth": birth, "exe": "/venv/python", "pgid": pid, "sid": pid, "uid": 1000, **extra}


def state(runtime, services=None):
    value = {"version": 1, "root": str(runtime.root), "profile": "legacy", "instance": "test-instance", "launcher_pid": 99,
             "launcher": identity(99), "services": services or {}}
    lifecycle.atomic_json(runtime.path, value)
    return value


@pytest.mark.parametrize("command", ["start", "stop", "restart", "status", "diagnose", "doctor", "logs"])
def test_parse_commands(command):
    assert dev.parse_args([command, "--verbose"]).command == command
    assert dev.parse_args(["--verbose", command]).verbose


def test_default_and_check():
    assert dev.parse_args([]).command == "start"
    assert dev.parse_args(["--check"]).check


def test_already_stopped_is_idempotent(capsys):
    dev.stop_application()
    dev.stop_application()
    assert "already stopped" in capsys.readouterr().out


def test_stale_registry_and_beat_lock_are_cleaned(tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime, {"API": identity()})
    dev.BEAT_LOCK.write_text("99")
    dev.stop_application()
    assert not runtime.path.exists()
    assert not dev.BEAT_LOCK.exists()


def test_reused_pid_is_never_killed(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime, {"API": identity()})
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: identity(birth="new-process"))
    with pytest.raises(dev.SetupError, match="safely stopped"):
        dev.stop_application()
    assert runtime.path.exists()


def test_unknown_identity_is_retained(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime, {"API": identity()})
    monkeypatch.setattr(lifecycle, "process_info", MagicMock(side_effect=lifecycle.OwnershipError("denied")))
    assert not runtime.stop_services(lambda *args: None)
    assert runtime.path.exists()


@posix_only
def test_owned_group_gracefully_stopped(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    record = identity()
    current = {100: record}
    monkeypatch.setattr(lifecycle, "process_info", current.get)
    signals = []
    def terminate(pid, sig):
        signals.append((pid, sig))
        current.clear()
    monkeypatch.setattr(lifecycle.os, "killpg", terminate)
    assert runtime.terminate(record)
    assert signals == [(100, lifecycle.signal.SIGTERM)]


@posix_only
def test_shutdown_reaps_exited_child_before_inspection(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    record = identity()
    state(runtime, {"API": record})
    status = {"alive": True, "reaped": False}
    def inspect(pid):
        if status["alive"]:
            return record
        if not status["reaped"]:
            raise lifecycle.OwnershipError("Exited child not reaped")
        return None
    def poll():
        if not status["alive"]:
            status["reaped"] = True
            return 0
        return None
    runtime.processes[100] = SimpleNamespace(poll=poll)
    monkeypatch.setattr(lifecycle, "process_info", inspect)
    monkeypatch.setattr(lifecycle.os, "killpg", lambda *args: status.update(alive=False))
    assert runtime.stop_services(lambda *args: None)
    assert status["reaped"]
    assert not runtime.path.exists()


def test_refresh_reaps_exited_child_before_macos_inspection(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    runtime.state = state(runtime, {"API": identity()})
    reaped = []
    runtime.processes[100] = SimpleNamespace(poll=lambda: reaped.append(True) or 1)

    def inspect(pid):
        if not reaped:
            raise lifecycle.OwnershipError("Cannot inspect PID 100.")
        return None

    monkeypatch.setattr(lifecycle, "process_info", inspect)
    runtime.refresh()
    assert reaped == [True]
    assert runtime.state["services"]["API"]["pid"] == 100


@posix_only
def test_owned_surviving_member_allows_orphan_group_cleanup(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    child = identity(101, pgid=100, sid=100)
    record = {**identity(), "members": [child]}
    members = [child]
    monkeypatch.setattr(lifecycle, "group_members", lambda pid: members)
    assert runtime.service_status(record) == "PARTIAL"
    monkeypatch.setattr(lifecycle.os, "killpg", lambda *args: members.clear())
    assert runtime.terminate(record)


@posix_only
def test_unknown_surviving_group_is_not_killed(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    monkeypatch.setattr(lifecycle, "group_members", lambda pid: [identity(101, pgid=100)])
    assert not runtime.terminate(identity())


@posix_only
def test_force_kill_rechecks_identity(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    record = identity()
    current = {100: record}
    signals = []
    monkeypatch.setattr(lifecycle, "process_info", current.get)
    def signal(pid, sig):
        signals.append(sig)
        # Simulate reuse after graceful termination; escalation must not kill it.
        current[100] = identity(birth="different")
    monkeypatch.setattr(lifecycle.os, "killpg", signal)
    assert not runtime.terminate(record, timeout=0)
    assert signals == [lifecycle.signal.SIGTERM]


@posix_only
def test_owned_stubborn_group_escalates(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    record = identity()
    current = {100: record}
    signals = []
    monkeypatch.setattr(lifecycle, "process_info", current.get)
    def signal(pid, sig):
        signals.append(sig)
        if sig == lifecycle.signal.SIGKILL:
            current.clear()
    monkeypatch.setattr(lifecycle.os, "killpg", signal)
    assert runtime.terminate(record, timeout=0)
    assert signals == [lifecycle.signal.SIGTERM, lifecycle.signal.SIGKILL]


def test_registry_roundtrip_atomic_private_and_no_environment(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: identity(pid))
    monkeypatch.setenv("SENSITIVE_API_KEY", "never-persist")
    replace = lifecycle.os.replace
    calls = []
    def observe(src, dst):
        calls.append((src, dst))
        assert json.loads(open(src).read())["root"] == str(tmp_path)
        replace(src, dst)
    monkeypatch.setattr(lifecycle.os, "replace", observe)
    runtime.begin()
    runtime.register("API", 100, 18000)
    saved = runtime.load()
    assert saved["services"]["API"]["port"] == 18000
    assert "never-persist" not in runtime.path.read_text()
    assert len(calls) == 2
    assert not list(tmp_path.glob("*.tmp"))
    if os.name != "nt":
        assert runtime.path.stat().st_mode & 0o077 == 0


def test_failed_atomic_write_preserves_previous_state(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    original = state(runtime)
    monkeypatch.setattr(lifecycle.os, "replace", MagicMock(side_effect=OSError("disk")))
    with pytest.raises(OSError):
        lifecycle.atomic_json(runtime.path, {"partial": True})
    assert runtime.load() == original
    assert not list(tmp_path.glob("*.tmp"))


def test_wrong_repository_state_is_refused(tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime)
    content = json.loads(runtime.path.read_text())
    content["root"] = "/other/repository"
    lifecycle.atomic_json(runtime.path, content)
    with pytest.raises(lifecycle.OwnershipError):
        runtime.load()


def test_concurrent_start_lock_and_crash_release(tmp_path):
    first, second = lifecycle.Runtime(tmp_path), lifecycle.Runtime(tmp_path)
    assert first.acquire()
    assert not second.acquire()
    first.release()
    assert second.acquire()
    second.release()
    assert first.lock_path.exists()  # Inode remains; the OS lock is released.


@pytest.mark.parametrize("failure", [KeyboardInterrupt, dev.SetupError("startup failure")])
@posix_only
def test_cleanup_on_interrupt_or_startup_failure(monkeypatch, tmp_path, failure):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start"])
    current = {os.getpid(): identity(os.getpid())}
    monkeypatch.setattr(lifecycle, "process_info", current.get)
    killed = []
    def terminate(pid, sig):
        killed.append(pid)
        current.pop(pid, None)
    monkeypatch.setattr(lifecycle.os, "killpg", terminate)
    def start(args):
        assert dev.ACTIVE_RUNTIME.path.exists()
        current[100] = identity()
        dev.ACTIVE_RUNTIME.register("API", 100, 18000)
        dev.BEAT_LOCK.write_text(str(os.getpid()))
        raise failure
    monkeypatch.setattr(dev, "start_application", start)
    if isinstance(failure, dev.SetupError):
        with pytest.raises(dev.SetupError, match="startup failure"):
            dev.main()
    else:
        dev.main()
    assert not (tmp_path / ".dev-runtime.json").exists()
    assert not dev.BEAT_LOCK.exists()
    assert dev.ACTIVE_RUNTIME is None
    assert killed == [100]


def test_restart_stops_before_start(monkeypatch):
    calls = []
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "restart"])
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: identity(pid))
    monkeypatch.setattr(dev, "stop_application", lambda: calls.append("stop"))
    monkeypatch.setattr(dev, "start_application", lambda args: calls.append("start"))
    dev.main()
    assert calls == ["stop", "start"]


def test_status_partial_service_failure(monkeypatch, tmp_path, capsys):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime, {"API": identity(), "Frontend": identity(200)})
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: identity() if pid == 100 else None)
    dev.application_status()
    output = capsys.readouterr().out
    assert "API" in output and "RUNNING" in output
    assert "Frontend" in output and "STOPPED" in output


def test_stale_beat_lock_recovery(monkeypatch):
    dev.BEAT_LOCK.write_text("99999")
    dev.clean_beat_lock()
    assert not dev.BEAT_LOCK.exists()
    dev.acquire_beat_lock()
    assert dev.BEAT_LOCK.read_text() == str(os.getpid())


@pytest.mark.parametrize("port", [18000, 13000])
def test_unrelated_port_never_stopped(monkeypatch, port):
    monkeypatch.setattr(dev, "reachable", lambda host, candidate: candidate == port)
    monkeypatch.setattr(dev, "port_diagnostic", lambda port: "PID: 123; ownership: unrelated/unknown")
    with pytest.raises(dev.SetupError, match="Nothing was killed"):
        dev.check_application_ports(18000, 13000)
    dev.stop_application()  # Warns but never signals arbitrary port owners.


def test_owned_port_identified(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    state(runtime, {"API": {**identity(), "port": 18000}})
    monkeypatch.setattr(lifecycle, "process_info", lambda pid: identity())
    monkeypatch.setattr(dev, "reachable", lambda host, port: port == 18000)
    with pytest.raises(dev.SetupError, match="existing SBOM dev instance"):
        dev.check_application_ports(18000, 13000)


def test_second_start_does_not_start_processes(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    assert runtime.acquire()
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start"])
    monkeypatch.setattr(dev, "start_application", lambda *args: pytest.fail("duplicate startup"))
    try:
        with pytest.raises(dev.SetupError, match="Existing instance is not ready"):
            dev.main()
    finally:
        runtime.release()


def test_cooperative_stop_is_scoped_to_instance(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    runtime.state = state(runtime)
    lifecycle.atomic_json(runtime.stop_path, {"instance": "other-instance"})
    runtime.check_stop()
    lifecycle.atomic_json(runtime.stop_path, {"instance": "test-instance"})
    with pytest.raises(KeyboardInterrupt):
        runtime.check_stop()


def test_check_overrides_lifecycle_without_mutation(monkeypatch):
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "restart", "--check"])
    monkeypatch.setattr(dev, "stop_application", lambda: pytest.fail("stop during check"))
    checked = []
    monkeypatch.setattr(dev, "start_application", lambda args: pytest.fail("startup during check"))
    monkeypatch.setattr(dev, "diagnose", lambda args: checked.append(args.check), raising=False)
    dev.main()
    assert checked == [True]


@pytest.mark.parametrize("value", ["true", "false"])
def test_ai_fixes_explicit_value_preserved(value):
    assert dev.resolve_config({"AI_FIXES_ENABLED": value}, 55439, 56379, 1025)["AI_FIXES_ENABLED"] == value


def test_windows_termination_validates_each_tree(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    record = identity()
    child = identity(101)
    record["members"] = [child, identity(102)]
    kernel = SimpleNamespace(
        OpenProcess=MagicMock(side_effect=lambda access, inherit, pid: pid),
        CloseHandle=MagicMock(), TerminateProcess=MagicMock(return_value=True),
        WaitForSingleObject=MagicMock(return_value=258),
    )
    current = {100: record, 101: child, 102: identity(102, birth="reused")}
    monkeypatch.setattr(lifecycle, "_windows_kernel", lambda: kernel, raising=False)
    monkeypatch.setattr(lifecycle, "_windows_process_info", lambda kernel, handle, pid: current.get(pid), raising=False)
    runtime._windows_terminate(record, force=True)
    assert {call.args[0] for call in kernel.TerminateProcess.call_args_list} == {100, 101}
    assert kernel.TerminateProcess.call_count == 2


@posix_only
def test_macos_birth_identity_uses_microseconds(monkeypatch):
    # Exercise the native adapter (without invoking a real OS process API).
    original = process_info_adapter
    library = SimpleNamespace()
    def info(pid, flavor, arg, pointer, size):
        value = pointer._obj
        value.sec, value.usec = 1700000000, 123456
        value.pid, value.ppid, value.pgid, value.uid = pid, 99, pid, 1000
        value.status = 2
        return size
    def path(pid, buffer, size):
        buffer.value = b'/venv/python'
        return len(buffer.value)
    library.proc_pidinfo, library.proc_pidpath = info, path
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    monkeypatch.setattr(lifecycle.ctypes, 'CDLL', lambda *args, **kwargs: library)
    monkeypatch.setattr(lifecycle.os, 'getsid', lambda pid: pid)
    assert original(100)['birth'] == '1700000000:123456'


def test_windows_birth_identity_uses_filetime(monkeypatch):
    kernel = SimpleNamespace(OpenProcess=MagicMock(return_value=7), CloseHandle=MagicMock(),
                             GetProcessTimes=MagicMock(), QueryFullProcessImageNameW=MagicMock(),
                             WaitForSingleObject=MagicMock(return_value=258), TerminateProcess=MagicMock())
    def times(handle, created, exited, kernel_time, user_time):
        created._obj.dwHighDateTime = 10
        created._obj.dwLowDateTime = 123
        return True
    def name(handle, flags, buffer, size):
        buffer.value = 'C:\\venv\\python.exe'
        return True
    kernel.GetProcessTimes.side_effect = times
    kernel.QueryFullProcessImageNameW.side_effect = name
    monkeypatch.setattr(lifecycle.sys, 'platform', 'win32')
    monkeypatch.setattr(lifecycle.ctypes, 'WinDLL', lambda *args, **kwargs: kernel, raising=False)
    info = process_info_adapter(100)
    assert info['birth'] == str((10 << 32) | 123)
    assert info['exe'] == 'C:\\venv\\python.exe'
    kernel.CloseHandle.assert_called_once_with(7)


def test_npm_env_to_node_exec_retains_ownership(tmp_path):
    recorded = identity(exe='/usr/bin/env', cwd=str(tmp_path / 'frontend'))
    current = {**recorded, 'exe': '/opt/node/bin/node', 'ppid': 1}
    assert lifecycle.matches(recorded, current)


def test_macos_npm_exec_without_cwd_can_be_stopped(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    recorded = identity(exe='/usr/bin/env')
    current = {100: {**recorded, 'exe': '/opt/node/bin/node', 'ppid': 1}}
    monkeypatch.setattr(lifecycle, 'process_info', current.get)
    runtime = lifecycle.Runtime(tmp_path)
    assert runtime.service_status(recorded) == 'RUNNING'
    signals = []
    def terminate(pid, sig):
        signals.append((pid, sig))
        current.clear()
    monkeypatch.setattr(lifecycle.os, 'killpg', terminate)
    assert runtime.terminate(recorded)
    assert signals == [(100, lifecycle.signal.SIGTERM)]


@pytest.mark.parametrize('platform', ['darwin', 'linux'])
@pytest.mark.parametrize('changed', [
    {'pid': 200}, {'birth': 'reused-pid'}, {'uid': 2000}, {'pgid': 200},
    {'sid': 200}, {'cwd': '/another/repository'}, {'exe': '/usr/bin/python3'},
])
def test_npm_exec_without_cwd_rejects_unrelated_identity(monkeypatch, platform, changed):
    monkeypatch.setattr(lifecycle.sys, 'platform', platform)
    recorded = identity(exe='/usr/bin/env')
    current = {**recorded, 'exe': '/opt/node/bin/node', **changed}
    assert not lifecycle.matches(recorded, current)


def test_linux_npm_exec_still_requires_cwd(monkeypatch):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'linux')
    recorded = identity(exe='/usr/bin/env')
    assert not lifecycle.matches(recorded, {**recorded, 'exe': '/opt/node/bin/node'})


@pytest.mark.parametrize('changed', [
    {'birth': 'reused-pid'}, {'uid': 2000}, {'pgid': 200}, {'sid': 200},
    {'cwd': '/another/repository'}, {'exe': '/usr/bin/python3'},
])
def test_npm_exec_exception_does_not_accept_unrelated_process(tmp_path, changed):
    recorded = identity(exe='/usr/bin/env', cwd=str(tmp_path / 'frontend'))
    current = {**recorded, 'exe': '/opt/node/bin/node', **changed}
    assert not lifecycle.matches(recorded, current)


@pytest.fixture
def macos_missing_executable(monkeypatch):
    def bsd_info(pid, flavor, arg, pointer, size):
        info = pointer._obj
        info.sec, info.usec = 1700000000, 123456
        info.pid, info.ppid, info.pgid, info.uid = pid, 99, pid, 1000
        info.status = 2
        return size

    def missing_path(pid, buffer, size):
        lifecycle.ctypes.set_errno(errno.ENOENT)
        return 0

    library = SimpleNamespace(proc_pidinfo=bsd_info, proc_pidpath=missing_path)
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    monkeypatch.setattr(lifecycle.ctypes, 'CDLL', lambda *args, **kwargs: library)
    monkeypatch.setattr(lifecycle.os, 'getsid', lambda pid: pid)
    return library


@posix_only
def test_macos_missing_executable_retains_kernel_birth_identity(macos_missing_executable):
    current = process_info_adapter(100)
    assert current == {**identity(birth='1700000000:123456', exe='', ppid=99), 'exe_unavailable': 'ENOENT'}
    assert lifecycle.matches(identity(birth=current['birth']), current)


@pytest.mark.parametrize('error', [0, errno.EPERM, errno.EACCES, errno.EIO, errno.ESRCH])
@posix_only
def test_macos_executable_inspection_errors_remain_fail_closed(macos_missing_executable, error):
    def failed_path(pid, buffer, size):
        lifecycle.ctypes.set_errno(error)
        return 0

    macos_missing_executable.proc_pidpath = failed_path
    with pytest.raises(lifecycle.OwnershipError, match='Cannot inspect executable'):
        process_info_adapter(100)


@pytest.mark.parametrize('changed', [
    {'pid': 200}, {'birth': 'reused-pid'}, {'uid': 2000}, {'pgid': 200},
    {'sid': 200}, {'cwd': '/another/repository'}, {'exe': '/another/program'},
    {'exe_unavailable': 'EACCES'}, {'exe_unavailable': None},
])
def test_macos_missing_executable_never_accepts_changed_identity(monkeypatch, changed):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    current = {**identity(exe='', cwd='/repository'), 'exe_unavailable': 'ENOENT', **changed}
    assert not lifecycle.matches(identity(cwd='/repository'), current)


@pytest.mark.parametrize('missing', ['uid', 'pgid', 'sid', 'birth', 'exe'])
def test_macos_missing_executable_requires_complete_saved_identity(monkeypatch, missing):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    recorded = identity()
    del recorded[missing]
    current = {**identity(exe=''), 'exe_unavailable': 'ENOENT'}
    assert not lifecycle.matches(recorded, current)


@pytest.mark.parametrize('missing', ['pid', 'uid', 'pgid', 'sid', 'birth', 'exe'])
def test_macos_missing_executable_requires_complete_current_identity(monkeypatch, missing):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    current = {**identity(exe=''), 'exe_unavailable': 'ENOENT'}
    del current[missing]
    assert not lifecycle.matches(identity(), current)


@pytest.mark.parametrize('platform', ['linux', 'win32'])
def test_missing_executable_exception_is_macos_only(monkeypatch, platform):
    monkeypatch.setattr(lifecycle.sys, 'platform', platform)
    assert not lifecycle.matches(identity(), {**identity(exe=''), 'exe_unavailable': 'ENOENT'})


def test_missing_executable_cannot_establish_new_service_ownership(monkeypatch, tmp_path):
    runtime = lifecycle.Runtime(tmp_path)
    runtime.state = state(runtime)
    monkeypatch.setattr(lifecycle, 'process_info', lambda pid: {**identity(pid, exe=''), 'exe_unavailable': 'ENOENT'})
    with pytest.raises(lifecycle.OwnershipError, match='Cannot establish executable identity'):
        runtime.register('Frontend', 100)
    assert runtime.load()['services'] == {}


def test_macos_missing_executable_preserves_member_proof_during_refresh(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    child = identity(101, pgid=100, sid=100)
    recorded = {**identity(), 'members': [child]}
    current = {pid: {**info, 'exe': '', 'exe_unavailable': 'ENOENT'} for pid, info in [(100, identity()), (101, child)]}
    monkeypatch.setattr(lifecycle, 'process_info', current.get)
    monkeypatch.setattr(lifecycle, 'group_members', lambda pgid: list(current.values()))
    runtime = lifecycle.Runtime(tmp_path)
    runtime.state = state(runtime, {'Frontend': recorded})
    runtime.refresh()
    assert runtime.service_status(recorded) == 'RUNNING'
    assert {info['pid']: info['exe'] for info in recorded['members']} == {100: '/venv/python', 101: '/venv/python'}


@posix_only
def test_macos_missing_executable_stops_recorded_surviving_child(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.sys, 'platform', 'darwin')
    child = identity(101, pgid=100, sid=100)
    recorded = {**identity(), 'members': [child]}
    current = {pid: {**info, 'exe': '', 'exe_unavailable': 'ENOENT'} for pid, info in [(100, identity()), (101, child)]}
    monkeypatch.setattr(lifecycle, 'process_info', current.get)
    monkeypatch.setattr(lifecycle, 'group_members', lambda pgid: list(current.values()))
    signals = []

    def terminate(pgid, sig):
        signals.append((pgid, sig))
        if sig == lifecycle.signal.SIGTERM:
            del current[100]
        else:
            current.clear()

    monkeypatch.setattr(lifecycle.os, 'killpg', terminate)
    assert lifecycle.Runtime(tmp_path).terminate(recorded, timeout=0)
    assert signals == [(100, lifecycle.signal.SIGTERM), (100, lifecycle.signal.SIGKILL)]
