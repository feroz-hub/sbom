"""Private, standard-library process ownership for the local development launcher.

Never infer ownership from a port or process name. A record originates from a
Popen child and is matched against OS birth identity before every signal.
"""
from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class OwnershipError(RuntimeError):
    pass


def process_info(pid: int) -> dict | None:
    """None means absent; access/inspection failure raises (never means safe to kill)."""
    if not isinstance(pid, int) or pid <= 0:
        raise OwnershipError("Invalid process identifier in runtime state.")
    try:
        if sys.platform.startswith("linux"):
            base = Path(f"/proc/{pid}")
            stat = (base / "stat").read_text().rsplit(")", 1)[1].split()
            if stat[0] == "Z":
                return None
            return {
                "pid": pid, "birth": Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + stat[19],
                "exe": os.readlink(base / "exe"), "cwd": os.readlink(base / "cwd"),
                "ppid": int(stat[1]), "pgid": int(stat[2]), "sid": int(stat[3]),
                "uid": base.stat().st_uid,
            }
        if sys.platform == "win32":
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            handle = kernel.OpenProcess(0x1000, False, pid)
            if not handle:
                if ctypes.get_last_error() == 87:
                    return None
                raise OwnershipError(f"Cannot inspect PID {pid}.")
            try:
                times = [wintypes.FILETIME() for _ in range(4)]
                size = wintypes.DWORD(32768)
                path = ctypes.create_unicode_buffer(size.value)
                if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)) or not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
                    raise OwnershipError(f"Cannot inspect PID {pid}.")
                # A terminated process handle may remain open in its parent.
                if times[1].dwHighDateTime or times[1].dwLowDateTime:
                    return None
                return {"pid": pid, "birth": str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime), "exe": path.value}
            finally:
                kernel.CloseHandle(handle)
        if sys.platform == "darwin":
            # libproc gives microsecond birth time; ps lstart alone has only
            # second resolution and is not sufficient to rule out PID reuse.
            class BsdInfo(ctypes.Structure):
                _fields_ = [(name, ctypes.c_uint32) for name in (
                    "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "rfu"
                )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [(name, ctypes.c_uint32) for name in (
                    "nfiles", "pgid", "jobc", "tdev", "tpgid", "nice"
                )] + [("sec", ctypes.c_uint64), ("usec", ctypes.c_uint64)]
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            info = BsdInfo()
            if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return None
                raise OwnershipError(f"Cannot inspect PID {pid}.")
            if info.status == 5:  # SZOMB
                return None
            path = ctypes.create_string_buffer(4096)
            if lib.proc_pidpath(pid, path, len(path)) <= 0:
                raise OwnershipError(f"Cannot inspect executable for PID {pid}.")
            return {"pid": pid, "birth": f"{info.sec}:{info.usec}", "exe": os.fsdecode(path.value),
                    "pgid": info.pgid, "ppid": info.ppid, "uid": info.uid, "sid": os.getsid(pid)}
        raise OwnershipError("Process ownership inspection is unsupported on this OS.")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (PermissionError, OSError) as exc:
        raise OwnershipError(f"Cannot safely inspect PID {pid} ({type(exc).__name__}).") from None


def matches(record: dict, current: dict | None) -> bool:
    # npm's shebang launches /usr/bin/env, which execs node without changing
    # the PID or OS birth identity. Popen can return before that exec finishes.
    # Permit this narrow transition only with the same Unix ownership context.
    npm_exec = bool(
        current and Path(record.get("exe", "")).name == "env"
        and Path(current.get("exe", "")).name in {"node", "nodejs"}
        and all(key in record and record[key] == current.get(key) for key in ("uid", "pgid", "sid", "cwd"))
    )
    return bool(current and all(record.get(key) == current.get(key) for key in ("pid", "birth"))
                and record.get("birth") and record.get("exe")
                and (record["exe"] == current.get("exe") or npm_exec)
                and all(record.get(key) == current.get(key) for key in ("uid", "pgid", "sid", "cwd") if key in record))


def group_members(pgid: int) -> list[dict]:
    if sys.platform == "win32":
        return []  # taskkill /T walks the verified parent's tree on Windows.
    if sys.platform.startswith("linux"):
        pids = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    else:
        result = subprocess.run(["ps", "-axo", "pid=,pgid="], capture_output=True, text=True, check=False)
        if result.returncode:
            raise OwnershipError("Cannot inspect process groups.")
        pids = [int(parts[0]) for line in result.stdout.splitlines() if len(parts := line.split()) == 2 and parts[1] == str(pgid)]
    members = []
    for pid in pids:
        try:
            info = process_info(pid)
        except OwnershipError:
            continue
        if info and info.get("pgid") == pgid:
            members.append(info)
    return members


def windows_children(pid: int) -> list[dict]:
    """Snapshot descendant birth identities with the native Toolhelp API."""
    from ctypes import wintypes
    class Entry(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                    ("exe", wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OwnershipError("Cannot inspect Windows process tree.")
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        parents = {}
        more = kernel.Process32FirstW(handle, ctypes.byref(entry))
        while more:
            parents[entry.pid] = entry.parent
            more = kernel.Process32NextW(handle, ctypes.byref(entry))
        owned = {pid}
        while additions := {child for child, parent in parents.items() if parent in owned} - owned:
            owned.update(additions)
        return [info for child in owned if (info := process_info(child))]
    finally:
        kernel.CloseHandle(handle)


def atomic_json(path: Path, value: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class Runtime:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.path = self.root / ".dev-runtime.json"
        self.lock_path = self.root / ".dev-runtime.lock"
        self.stop_path = self.root / ".dev-runtime.stop"
        self.lock = None
        self.state = None

    def acquire(self) -> bool:
        # Keep this inode permanently. Unlinking a lock allows two independent
        # lock holders; OS locks automatically release on exit, including crashes.
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.lock = os.fdopen(fd, "r+b")
        try:
            if sys.platform == "win32":
                import msvcrt
                if self.lock.seek(0, 2) == 0:
                    self.lock.write(b"\0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.lock = None
            return False
        return True

    def release(self) -> None:
        if self.lock:
            self.lock.close()
            self.lock = None

    def load(self) -> dict | None:
        try:
            state = json.loads(self.path.read_text())
            if (not isinstance(state, dict) or state.get("version") != 1 or state.get("root") != str(self.root)
                    or not isinstance(state.get("services"), dict) or not isinstance(state.get("instance"), str)):
                raise ValueError()
            if any(not isinstance(record, dict) or not isinstance(record.get("pid"), int)
                   for record in state["services"].values()):
                raise ValueError()
            return state
        except FileNotFoundError:
            return None
        except (ValueError, TypeError):
            # No guesses from corrupted state: ports still protect startup.
            raise OwnershipError("Runtime state is malformed or belongs to another repository; no process was stopped.") from None

    def begin(self) -> None:
        launcher = process_info(os.getpid())
        if not launcher:
            raise OwnershipError("Could not establish launcher identity.")
        self.stop_path.unlink(missing_ok=True)
        self.state = {"version": 1, "root": str(self.root), "instance": uuid.uuid4().hex,
                      "launcher_pid": os.getpid(), "launcher": launcher,
                      "started_at": datetime.now(timezone.utc).isoformat(), "services": {}}
        atomic_json(self.path, self.state)

    def check_stop(self) -> None:
        if self.state and self.stop_path.exists():
            try:
                requested = json.loads(self.stop_path.read_text())
            except (OSError, ValueError):
                return
            if requested.get("instance") == self.state["instance"]:
                raise KeyboardInterrupt

    def register(self, name: str, pid: int, port: int | None = None) -> None:
        info = process_info(pid)
        if not info:
            raise OwnershipError(f"{name} exited before ownership could be recorded.")
        if sys.platform != "win32" and (info.get("pgid") != pid or info.get("sid") != pid):
            raise OwnershipError(f"{name} did not start in an isolated process group.")
        self.state["services"][name] = {**info, "port": port, "members": [info]}
        atomic_json(self.path, self.state)

    def refresh(self) -> None:
        self.check_stop()
        for record in self.state["services"].values():
            if matches(record, process_info(record["pid"])):
                record["members"] = windows_children(record["pid"]) if sys.platform == "win32" else group_members(record["pid"])
        atomic_json(self.path, self.state)

    def service_status(self, record: dict) -> str:
        try:
            current = process_info(record["pid"])
            if matches(record, current):
                return "RUNNING"
            if current:
                return "UNOWNED"
            if sys.platform == "win32":
                if any(matches(saved, process_info(saved["pid"])) for saved in record.get("members", [])):
                    return "PARTIAL"
            else:
                members = group_members(record["pid"])
                if any(matches(saved, member) for saved in record.get("members", []) for member in members):
                    return "PARTIAL"
                if members:
                    return "UNOWNED"
            return "STOPPED"
        except (OwnershipError, KeyError, TypeError):
            return "UNKNOWN"

    def terminate(self, record: dict, timeout: float = 5) -> bool:
        status = self.service_status(record)
        if status == "STOPPED":
            return True
        if status not in {"RUNNING", "PARTIAL"}:
            return False
        pid = record["pid"]
        if status == "RUNNING":
            # Capture descendants before TERM: the leader may exit first while
            # a child ignores TERM. Its birth identity must survive escalation.
            record["members"] = windows_children(pid) if sys.platform == "win32" else group_members(pid)
            if not matches(record, process_info(pid)):
                return False
        if sys.platform == "win32":
            # Revalidate birth identity immediately before each tree operation.
            self._windows_terminate(record, force=False)
        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.service_status(record) == "STOPPED":
                return True
            time.sleep(0.1)
        # A terminated group leader may leave children behind. Only a recorded
        # surviving member can establish ownership in that case.
        if self.service_status(record) not in {"RUNNING", "PARTIAL"}:
            return self.service_status(record) == "STOPPED"
        if sys.platform == "win32":
            self._windows_terminate(record, force=True)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                return True
        for _ in range(30):
            if self.service_status(record) == "STOPPED":
                return True
            time.sleep(0.1)
        return False

    def _windows_terminate(self, record: dict, *, force: bool) -> None:
        # Children are retained separately so a dead npm/cmd parent does not
        # prevent cleanup of a recorded surviving node process.
        for saved in [record, *record.get("members", [])]:
            if matches(saved, process_info(saved["pid"])):
                subprocess.run(["taskkill", "/PID", str(saved["pid"]), "/T", *(["/F"] if force else [])],
                               capture_output=True, check=False)

    def stop_services(self, say) -> bool:
        state = self.state or self.load()
        if not state:
            return True
        remaining = {}
        for name, record in reversed(list(state["services"].items())):
            if self.terminate(record):
                say("OK", name, "stopped")
            else:
                remaining[name] = record
                say("WARN", name, f"PID {record['pid']}: ownership unverified or process still running; not removed")
        state["services"] = remaining
        if remaining:
            atomic_json(self.path, state)
            return False
        self.path.unlink(missing_ok=True)
        self.stop_path.unlink(missing_ok=True)
        self.state = None
        return True
