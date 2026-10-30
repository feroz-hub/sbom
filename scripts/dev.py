"""Safely manage the complete local Native IAM development stack."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import getpass
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from urllib.request import urlopen

MIN_PYTHON = (3, 11)
MIN_NODE = (20, 9, 0)
REQUIRED_FILES = ("requirements.txt", "alembic.ini", "frontend/package.json", "frontend/package-lock.json")
GREENFIELD_UUID_BASELINE = "100_greenfield_uuid_final"
PUBLIC_IDENTITY_TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")

UTC = timezone.utc  # noqa: UP017 - keep old-Python prerequisite diagnostics importable


# Process identity and lifecycle are canonical here; never infer ownership from ports.
class OwnershipError(RuntimeError):
    pass


def _windows_kernel():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "OpenProcess": (wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
        "CloseHandle": (wintypes.BOOL, [wintypes.HANDLE]),
        "WaitForSingleObject": (wintypes.DWORD, [wintypes.HANDLE, wintypes.DWORD]),
        "GetProcessTimes": (wintypes.BOOL, [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4),
        "QueryFullProcessImageNameW": (
            wintypes.BOOL, [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        ),
        "TerminateProcess": (wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(kernel, name)
        function.restype, function.argtypes = result, arguments
    return kernel


def _windows_error(pid, operation, code):
    return OwnershipError(f"PID {pid}: {operation} failed (winerror={code}; status=UNKNOWN; ownership unverified).")


def _windows_exited(kernel, handle, pid):
    result = kernel.WaitForSingleObject(handle, 0)
    if result == 0:
        return True
    if result == 258:  # WAIT_TIMEOUT: the process object is not signaled.
        return False
    raise _windows_error(pid, "WaitForSingleObject", ctypes.get_last_error())


def _windows_query_failed(kernel, handle, pid, operation, code):
    error = _windows_error(pid, operation, code)
    try:
        if _windows_exited(kernel, handle, pid):
            return None
    except OwnershipError as wait_error:
        raise OwnershipError(f"{error} {wait_error}") from None
    raise error


def _windows_process_info(kernel, handle, pid):
    """Read identity and liveness on one pinned process object, never a new PID."""
    from ctypes import wintypes

    if _windows_exited(kernel, handle, pid):
        return None
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
        return _windows_query_failed(kernel, handle, pid, "GetProcessTimes", ctypes.get_last_error())
    size = wintypes.DWORD(32768)
    path = ctypes.create_unicode_buffer(size.value)
    if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
        return _windows_query_failed(kernel, handle, pid, "QueryFullProcessImageNameW", ctypes.get_last_error())
    if _windows_exited(kernel, handle, pid):
        return None
    return {"pid": pid, "birth": str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime), "exe": path.value}


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
                "pid": pid,
                "birth": Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + stat[19],
                "exe": os.readlink(base / "exe"),
                "cwd": os.readlink(base / "cwd"),
                "ppid": int(stat[1]),
                "pgid": int(stat[2]),
                "sid": int(stat[3]),
                "uid": base.stat().st_uid,
            }
        if sys.platform == "win32":
            if pid > 0xFFFFFFFF:
                raise OwnershipError("Invalid Windows process identifier in runtime state.")
            kernel = _windows_kernel()
            handle = kernel.OpenProcess(0x101000, False, pid)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
            if not handle:
                code = ctypes.get_last_error()
                if code == 87:  # ERROR_INVALID_PARAMETER: this valid PID no longer exists.
                    return None
                raise _windows_error(pid, "OpenProcess", code)
            try:
                return _windows_process_info(kernel, handle, pid)
            finally:
                kernel.CloseHandle(handle)
        if sys.platform == "darwin":
            # libproc gives microsecond birth time; ps lstart alone has only
            # second resolution and is not sufficient to rule out PID reuse.
            class BsdInfo(ctypes.Structure):
                _fields_ = (
                    [
                        (name, ctypes.c_uint32)
                        for name in (
                            "flags",
                            "status",
                            "xstatus",
                            "pid",
                            "ppid",
                            "uid",
                            "gid",
                            "ruid",
                            "rgid",
                            "svuid",
                            "svgid",
                            "rfu",
                        )
                    ]
                    + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
                    + [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid", "nice")]
                    + [("sec", ctypes.c_uint64), ("usec", ctypes.c_uint64)]
                )

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
            ctypes.set_errno(0)
            if lib.proc_pidpath(pid, path, len(path)) <= 0:
                if ctypes.get_errno() != errno.ENOENT:
                    raise OwnershipError(f"Cannot inspect executable for PID {pid}.")
                # A runtime update can move/unlink a running executable. Its
                # vnode path disappears while BSD birth identity stays valid.
                # Only an existing complete record may use this exception.
                return {
                    "pid": pid,
                    "birth": f"{info.sec}:{info.usec}",
                    "exe": "",
                    "exe_unavailable": "ENOENT",
                    "pgid": info.pgid,
                    "ppid": info.ppid,
                    "uid": info.uid,
                    "sid": os.getsid(pid),
                }
            return {
                "pid": pid,
                "birth": f"{info.sec}:{info.usec}",
                "exe": os.fsdecode(path.value),
                "pgid": info.pgid,
                "ppid": info.ppid,
                "uid": info.uid,
                "sid": os.getsid(pid),
            }
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
        current
        and Path(record.get("exe", "")).name == "env"
        and Path(current.get("exe", "")).name in {"node", "nodejs"}
        and all(key in record and record[key] == current.get(key) for key in ("uid", "pgid", "sid"))
        # libproc does not supply cwd on macOS. Keep requiring it elsewhere,
        # and compare it whenever either identity includes it.
        and (
            (sys.platform == "darwin" and "cwd" not in record and "cwd" not in current)
            or ("cwd" in record and record["cwd"] == current.get("cwd"))
        )
    )
    missing_macos_path = bool(
        sys.platform == "darwin"
        and current
        and current.get("exe") == ""
        and current.get("exe_unavailable") == "ENOENT"
        and all(key in record and key in current and record[key] == current[key] for key in ("uid", "pgid", "sid"))
    )
    return bool(
        current
        and all(record.get(key) == current.get(key) for key in ("pid", "birth"))
        and record.get("birth")
        and record.get("exe")
        and (record["exe"] == current.get("exe") or npm_exec or missing_macos_path)
        and all(record.get(key) == current.get(key) for key in ("uid", "pgid", "sid", "cwd") if key in record)
    )


def group_members(pgid: int) -> list[dict]:
    if sys.platform == "win32":
        return []  # Windows uses individually verified process handles.
    if sys.platform.startswith("linux"):
        pids = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    else:
        result = subprocess.run(["ps", "-axo", "pid=,pgid="], capture_output=True, text=True, check=False)
        if result.returncode:
            raise OwnershipError("Cannot inspect process groups.")
        pids = [
            int(parts[0])
            for line in result.stdout.splitlines()
            if len(parts := line.split()) == 2 and parts[1] == str(pgid)
        ]
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
    """Pin identities and validate ancestry across two checked Toolhelp snapshots."""
    from ctypes import wintypes

    class Entry(ctypes.Structure):
        _fields_ = [
            ("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
            ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
            ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
            ("exe", wintypes.WCHAR * 260),
        ]

    kernel = _windows_kernel()
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]

    def snapshot():
        handle = kernel.CreateToolhelp32Snapshot(2, 0)
        if handle == ctypes.c_void_p(-1).value:
            raise _windows_error(pid, "CreateToolhelp32Snapshot", ctypes.get_last_error())
        try:
            entry = Entry()
            entry.size = ctypes.sizeof(entry)
            parents = {}
            operation = "Process32FirstW"
            more = kernel.Process32FirstW(handle, ctypes.byref(entry))
            while more:
                parents[entry.pid] = entry.parent
                operation = "Process32NextW"
                more = kernel.Process32NextW(handle, ctypes.byref(entry))
            code = ctypes.get_last_error()
            if code != 18:  # ERROR_NO_MORE_FILES is the only successful end.
                raise _windows_error(pid, operation, code)
            return parents
        finally:
            kernel.CloseHandle(handle)

    handles = []
    def inspect(child):
        handle = kernel.OpenProcess(0x101000, False, child)
        if not handle:
            code = ctypes.get_last_error()
            if code == 87:
                return None
            raise _windows_error(child, "OpenProcess", code)
        handles.append(handle)
        return _windows_process_info(kernel, handle, child)

    try:
        root = inspect(pid)
        if not root:
            return []
        parents = snapshot()
        identities = {pid: root}
        pending = [pid]
        while pending:
            parent = pending.pop()
            for child, owner in parents.items():
                if owner != parent or child in identities:
                    continue
                info = inspect(child)
                if info and int(info["birth"]) >= int(identities[parent]["birth"]):
                    identities[child] = info
                    pending.append(child)
        # PIDs may recycle between the first snapshot and OpenProcess. With
        # all accepted handles pinned, recheck the parent links before adoption.
        current = snapshot()
        accepted = {pid: root}
        while additions := {
            child: info for child, info in identities.items()
            if child not in accepted and current.get(child) == parents.get(child)
            and current.get(child) in accepted
        }:
            accepted.update(additions)
        return list(accepted.values())
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)

def atomic_json(path: Path, value: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(11):
            try:
                os.replace(name, path)
                break
            except OSError as error:
                # Windows readers/antivirus can briefly deny delete sharing.
                # Keep the existing complete file and fail on sustained denial.
                if sys.platform != "win32" or getattr(error, "winerror", None) not in {5, 32, 33} or attempt == 10:
                    raise
                time.sleep(min(0.01 * 2**attempt, 0.1))
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
        self.processes: dict[int, subprocess.Popen] = {}
        self.inspection_errors: dict[int, str] = {}

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
            if (
                not isinstance(state, dict)
                or state.get("version") != 1
                or state.get("root") != str(self.root)
                or not isinstance(state.get("services"), dict)
                or not isinstance(state.get("instance"), str)
            ):
                raise ValueError()
            if any(
                not isinstance(record, dict) or not isinstance(record.get("pid"), int)
                for record in state["services"].values()
            ):
                raise ValueError()
            return state
        except FileNotFoundError:
            return None
        except (ValueError, TypeError):
            # No guesses from corrupted state: ports still protect startup.
            raise OwnershipError(
                "Runtime state is malformed or belongs to another repository; no process was stopped."
            ) from None

    def begin(self, profile: str | None = None) -> None:
        launcher = process_info(os.getpid())
        if not launcher or not launcher.get("exe"):
            raise OwnershipError("Could not establish launcher identity.")
        self.stop_path.unlink(missing_ok=True)
        self.state = {
            "version": 1,
            "root": str(self.root),
            "instance": uuid.uuid4().hex,
            "launcher_pid": os.getpid(),
            "launcher": launcher,
            "started_at": datetime.now(UTC).isoformat(),
            "services": {},
        }
        if profile is not None:
            self.state["profile"] = profile
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
        child = self.processes.get(pid)
        if sys.platform == "win32" and getattr(child, "_handle", None):
            info = _windows_process_info(_windows_kernel(), int(child._handle), pid)
        else:
            info = process_info(pid)
        if not info:
            raise OwnershipError(f"{name}: PID {pid}, status=STOPPED; exited before ownership could be recorded. Log: {log_path(name)}")
        if not info.get("exe"):
            raise OwnershipError(f"Cannot establish executable identity for {name}.")
        if sys.platform != "win32" and (info.get("pgid") != pid or info.get("sid") != pid):
            raise OwnershipError(f"{name} did not start in an isolated process group.")
        self.state["services"][name] = {**info, "port": port, "members": [info]}
        atomic_json(self.path, self.state)

    def _snapshot_members(self, record: dict) -> list[dict]:
        members = windows_children(record["pid"]) if sys.platform == "win32" else group_members(record["pid"])
        if sys.platform == "win32":
            root = next((info for info in members if info["pid"] == record["pid"]), None)
            if root and not matches(record, root):
                raise OwnershipError(f"PID {record['pid']}: status=UNOWNED; process identity changed during enumeration.")
            # A child may have outlived/reparented away from its wrapper. Keep
            # its saved proof, including when a later snapshot cannot see it.
            combined = {(info["pid"], info.get("birth")): info for info in record.get("members", [])}
            combined.update({(info["pid"], info.get("birth")): info for info in members})
            members = list(combined.values())
            if root and matches(record, root):
                record.pop("tree_unverified", None)
                record.pop("inspection_error", None)
        saved = {info["pid"]: info for info in [record, *record.get("members", [])]}
        # Retain the previously verified executable if its path has vanished.
        # Otherwise losing the leader would discard a child's ownership proof.
        return [
            {**info, "exe": saved[info["pid"]]["exe"]}
            if not info.get("exe") and info["pid"] in saved and matches(saved[info["pid"]], info)
            else info
            for info in members
        ]

    def diagnostic(self, name, record, error=None):
        status = self.service_status(record)
        detail = str(error) if error else self.inspection_errors.get(record["pid"], record.get("inspection_error", ""))
        child = self.processes.get(record["pid"])
        code = getattr(child, "returncode", None)
        exit_detail = f", exit_code={code}" if code is not None else ""
        path = profile_log_paths(ACTIVE_PROFILE).get(name, self.root / ".dev-logs")
        return f"{name}: PID {record['pid']}, status={status}{exit_detail}; {detail or 'ownership/liveness checked'}. Log: {path}"

    def refresh(self) -> None:
        self.check_stop()
        for name, record in self.state["services"].items():
            if child := self.processes.get(record["pid"]):
                child.poll()
            try:
                if matches(record, process_info(record["pid"])):
                    record["members"] = self._snapshot_members(record)
            except OwnershipError as error:
                self.inspection_errors[record["pid"]] = str(error)
                raise OwnershipError(self.diagnostic(name, record, error)) from None
        atomic_json(self.path, self.state)

    def service_status(self, record: dict) -> str:
        try:
            if child := self.processes.get(record["pid"]):
                child.poll()
            current = process_info(record["pid"])
            if not record.get("birth") or not record.get("exe"):
                return "UNKNOWN"  # Registration failed; absence cannot clear unrecorded descendants.
            if matches(record, current):
                return "RUNNING"
            if current:
                return "UNOWNED"
            if sys.platform == "win32":
                statuses = []
                for saved in record.get("members", []):
                    member = process_info(saved["pid"])
                    statuses.append("RUNNING" if matches(saved, member) else "UNOWNED" if member else "STOPPED")
                if "UNOWNED" in statuses:
                    return "UNOWNED"
                if "RUNNING" in statuses:
                    return "PARTIAL"
            else:
                members = group_members(record["pid"])
                if any(matches(saved, member) for saved in record.get("members", []) for member in members):
                    return "PARTIAL"
                if members:
                    return "UNOWNED"
            return "UNKNOWN" if record.get("tree_unverified") else "STOPPED"
        except (OwnershipError, KeyError, TypeError) as error:
            self.inspection_errors[record["pid"]] = str(error)
            return "UNKNOWN"

    def terminate(self, record: dict, timeout: float = 5) -> bool:
        status = self.service_status(record)
        if status == "STOPPED":
            return True
        if status not in {"RUNNING", "PARTIAL"}:
            if sys.platform == "win32":
                record["tree_unverified"] = True
                record["inspection_error"] = self.inspection_errors.get(record["pid"], "Unresolved process identity/tree")
                # Individual saved handles may still be verifiable even when
                # another member is denied/reused. Preserve the unresolved record.
                self._windows_terminate(record, force=True)
            return False
        pid = record["pid"]
        snapshot_error = None
        if status == "RUNNING":
            try:
                record["members"] = self._snapshot_members(record)
            except OwnershipError as error:
                if sys.platform != "win32":
                    raise
                # A failed enumeration must not prevent known members/sibling
                # services from being cleaned. Retain this record for retry.
                snapshot_error = error
                record["tree_unverified"] = True
                record["inspection_error"] = str(error)
                self.inspection_errors[pid] = str(error)
            if sys.platform != "win32" and not matches(record, process_info(pid)):
                return False
        if sys.platform == "win32":
            self._windows_terminate(record, force=False)
        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.service_status(record) == "STOPPED":
                return snapshot_error is None
            time.sleep(0.1)
        status = self.service_status(record)
        if status not in {"RUNNING", "PARTIAL"}:
            return status == "STOPPED" and snapshot_error is None
        if sys.platform == "win32":
            self._windows_terminate(record, force=True)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                return True
        for _ in range(30):
            if self.service_status(record) == "STOPPED":
                return snapshot_error is None
            time.sleep(0.1)
        return False

    def _windows_terminate(self, record: dict, *, force: bool) -> None:
        # TerminateProcess is asynchronous and targets the SAME handle whose
        # birth/executable we just verified. Never use taskkill /T on bare PIDs.
        kernel = _windows_kernel()
        errors = []
        seen = set()
        for saved in reversed([record, *record.get("members", [])]):
            identity = (saved["pid"], saved.get("birth"), saved.get("exe"))
            if identity in seen:
                continue
            seen.add(identity)
            if type(saved["pid"]) is not int or not 0 < saved["pid"] <= 0xFFFFFFFF:
                errors.append("Invalid Windows PID; status=UNKNOWN; ownership unverified.")
                continue
            handle = kernel.OpenProcess(0x101001, False, saved["pid"])
            if not handle:
                code = ctypes.get_last_error()
                if code != 87:
                    errors.append(str(_windows_error(saved["pid"], "OpenProcess", code)))
                continue
            try:
                current = _windows_process_info(kernel, handle, saved["pid"])
                if matches(saved, current) and not kernel.TerminateProcess(handle, 1):
                    code = ctypes.get_last_error()
                    _windows_query_failed(kernel, handle, saved["pid"], "TerminateProcess", code)
            except OwnershipError as error:
                errors.append(str(error))
            finally:
                kernel.CloseHandle(handle)
        if errors:
            raise OwnershipError("; ".join(errors))

    def stop_services(self, say) -> bool:
        state = self.state or self.load()
        if not state:
            return True
        remaining = {}
        state["ready"] = False
        for name, record in reversed(list(state["services"].items())):
            error = None
            try:
                stopped = self.terminate(record)
            except OwnershipError as failure:
                error, stopped = failure, False
                self.inspection_errors[record["pid"]] = str(failure)
            if stopped:
                say("OK", name, "stopped")
            else:
                remaining[name] = record
                say("WARN", name, self.diagnostic(name, record, error) + "; runtime record retained; inspect and retry stop")
        state["services"] = remaining
        if remaining:
            atomic_json(self.path, state)
            return False
        self.path.unlink(missing_ok=True)
        self.stop_path.unlink(missing_ok=True)
        self.state = None
        return True



ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if __name__ == "__main__":
    sys.modules.setdefault("scripts.dev", sys.modules[__name__])
CONFIG = ROOT / ".env.dev.local"
VENV = ROOT / ".venv"
DB_NAME = "sbom_analyser_dev"
POSTGRES_PORT = 55439
REDIS_PORT = 56379
MAILPIT_SMTP_PORT = 1025
MAILPIT_UI_PORT = 8025
MAILPIT_READY_TIMEOUT = 15.0
DEV_API_PORT = 18000
DEV_FRONTEND_PORT = 13000
BEAT_LOCK = ROOT / ".dev-beat.pid"
VERBOSE = False
ACTIVE_RUNTIME: Runtime | None = None
ACTIVE_PROFILE = "legacy"
ACTIVE_LEGACY_CONFIG = "managed"


class SetupError(RuntimeError):
    """A local prerequisite needs developer attention."""


def runtime_environment(env: dict[str, str]) -> dict[str, str]:
    values = dict(env)
    values["SBOM_DEV_PROFILE"] = ACTIVE_PROFILE
    values["SBOM_DEV_STATE_DIR"] = str(GreenfieldStack.STATE if ACTIVE_PROFILE == "greenfield" else ROOT / ".dev-logs")
    values["SBOM_DEV_INSTANCE"] = (
        (ACTIVE_RUNTIME.state or {}).get("instance", "unmanaged") if ACTIVE_RUNTIME else "unmanaged"
    )
    values["PYTHONPATH"] = str(ROOT)
    return values


def worker_node(role: str, instance: str, profile=None) -> str:
    return f"sbom-{profile or ACTIVE_PROFILE}-{instance[:12]}-{role}@{socket.gethostname()}"


def heartbeat_path(env: dict[str, str], role: str) -> Path:
    return Path(env["SBOM_DEV_STATE_DIR"]) / f"{role}-health.json"


def write_service_heartbeat(env, role, **metadata):
    path = heartbeat_path(env, role)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    atomic_json(path, {"instance": env["SBOM_DEV_INSTANCE"], "pid": os.getpid(), "time": time.time(), **metadata})


def configure_local_schedule(app, profile):
    if profile == "greenfield" and "security-mail-outbox" in app.conf.beat_schedule:
        schedule = dict(app.conf.beat_schedule)
        schedule["security-mail-outbox"] = {**schedule["security-mail-outbox"], "schedule": 10.0}
        app.conf.beat_schedule = schedule


def local_celery_app():
    """Expose the real application tasks with local lifecycle instrumentation."""
    cached = globals().get("_LOCAL_CELERY_APP")
    if cached is not None:
        return cached
    import threading

    from app.workers.celery_app import celery_app
    from celery.signals import worker_ready, worker_shutdown

    env = dict(os.environ)
    role = env.get("SBOM_DEV_WORKER_ROLE", "default")
    if not env.get("SBOM_DEV_INSTANCE") or not env.get("SBOM_DEV_STATE_DIR"):
        raise SetupError("Local Celery must be started by python scripts/dev.py; its ownership context is missing.")
    configure_local_schedule(celery_app, env.get("SBOM_DEV_PROFILE"))
    stopped = threading.Event()

    def ready(sender=None, **kwargs):
        def emit():
            while not stopped.is_set():
                try:
                    queues = [q.name for q in sender.task_consumer.queues]
                    write_service_heartbeat(
                        env,
                        role,
                        node=sender.hostname,
                        queues=queues,
                        connected=bool(sender.connection and sender.connection.connected),
                    )
                except (AttributeError, OSError, ValueError):
                    # No false readiness if the consumer is reconnecting or its
                    # health record cannot be published; the parent times out.
                    pass
                stopped.wait(2)

        threading.Thread(target=emit, name="sbom-local-health", daemon=True).start()

    worker_ready.connect(ready, weak=False)
    worker_shutdown.connect(lambda **kwargs: stopped.set(), weak=False)
    globals()["_LOCAL_CELERY_APP"] = celery_app
    return celery_app


def local_scheduler_class():
    import redis
    from celery.beat import PersistentScheduler

    class LocalScheduler(PersistentScheduler):
        """One scheduler per profile/database, with progress after real ticks."""

        def tick(self, *args, **kwargs):
            env = dict(os.environ)
            token = env["SBOM_DEV_INSTANCE"]
            client = redis.Redis.from_url(env["REDIS_URL"], socket_connect_timeout=2, socket_timeout=2)
            target = urlsplit(env["DATABASE_URL"])
            key = f"sbom:dev:beat:{env['SBOM_DEV_PROFILE']}:{target.hostname}:{target.port}:{target.path}"
            owned = client.eval(
                "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('expire',KEYS[1],20) else return 0 end",
                1,
                key,
                token,
            )
            deadline = time.monotonic() + 25
            while not owned and not client.set(key, token, nx=True, ex=20):
                if time.monotonic() >= deadline:
                    raise SetupError(
                        "Another scheduler holds this database/profile lease; it was not stopped. Inspect its own launcher."
                    )
                time.sleep(0.5)
            interval = super().tick(*args, **kwargs)
            write_service_heartbeat(env, "beat", scheduled_tasks=len(self.schedule))
            self._local_lease = (client, key, token)
            return min(interval, 5)

        def close(self):
            try:
                super().close()
            finally:
                if lease := getattr(self, "_local_lease", None):
                    client, key, token = lease
                    client.eval(
                        "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end",
                        1,
                        key,
                        token,
                    )

    return LocalScheduler


def __getattr__(name):
    # Celery imports these symbols only in its managed worker/Beat processes;
    # help, status and prerequisite diagnosis stay standard-library-only.
    if name == "celery_app":
        return local_celery_app()
    if name == "LocalScheduler":
        return local_scheduler_class()
    raise AttributeError(name)


def verify_data_connectivity(env):
    import psycopg
    import redis

    target = urlsplit(env["DATABASE_URL"])
    try:
        with psycopg.connect(
            env["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1),
            connect_timeout=3,
            options="-c default_transaction_read_only=on -c statement_timeout=3000",
        ) as connection:
            observed = connection.execute("SELECT current_database()").fetchone()[0]
            if observed != target.path.lstrip("/"):
                raise SetupError("PostgreSQL returned a different database; no service was started.")
    except psycopg.Error as error:
        raise SetupError(
            f"PostgreSQL {target.hostname}:{target.port or 5432} connectivity failed ({type(error).__name__}, SQLSTATE {error.sqlstate or 'unavailable'}). Check this profile's server and saved credentials."
        ) from None
    try:
        client = redis.Redis.from_url(env["REDIS_URL"], socket_connect_timeout=2, socket_timeout=2)
        if not client.ping():
            raise ValueError("no PONG")
    except (redis.RedisError, ValueError) as error:
        raise SetupError(
            f"Redis connectivity failed ({type(error).__name__}). Check this profile's Redis service, port and saved credentials."
        ) from None


def celery_control(env):
    from celery import Celery

    app = Celery("sbom-local-health", broker=env["CELERY_BROKER_URL"])
    app.conf.update(
        broker_connection_timeout=2, broker_transport_options={"socket_connect_timeout": 2, "socket_timeout": 2}
    )
    return app


def reject_foreign_workers(env):
    try:
        with celery_control(env) as control:
            nodes = control.control.inspect(timeout=1).ping() or {}
    except Exception as error:
        raise service_failure(
            "Celery worker",
            f"broker control connection failed ({type(error).__name__}); check the selected profile's saved broker and Redis availability",
        ) from None
    if nodes:
        raise SetupError(
            "Unmanaged Celery workers are already using the selected broker. Stop them through their own manager before startup; no foreign process was terminated."
        )


def background_commands(env):
    instance = env["SBOM_DEV_INSTANCE"]
    base = [str(venv_python()), "-B", "-m", "celery", "-A", "scripts.dev:celery_app"]
    commands = {}
    for component, role, queue in (
        ("Celery worker", "default", "celery"),
        ("Celery reports worker", "reports", "reports"),
    ):
        command = [
            *base,
            "worker",
            "--loglevel=info",
            "--queues=" + queue,
            "--hostname=" + worker_node(role, instance, env["SBOM_DEV_PROFILE"]),
            "--concurrency=1",
            "--prefetch-multiplier=1",
        ]
        command += (
            ["--pool=prefork", "--max-tasks-per-child=20"] if sys.platform.startswith("linux") else ["--pool=solo"]
        )
        commands[component] = command
    folder = Path(env["SBOM_DEV_STATE_DIR"])
    commands["Celery Beat"] = [
        *base,
        "beat",
        "--loglevel=info",
        "--scheduler=scripts.dev:LocalScheduler",
        "--schedule="
        + str(
            folder / ("security-mail-schedule" if env["SBOM_DEV_PROFILE"] == "greenfield" else "celerybeat-schedule")
        ),
        # Celery's stale-lock probe uses os.kill(pid, 0), which is not a
        # read-only liveness check on Windows. Keep a real PID lock, scoped to
        # this exclusively owned runtime instance; never probe an old PID.
        "--pidfile=" + str(folder / (f"celerybeat-{instance}.pid" if sys.platform == "win32" else "celerybeat.pid")),
    ]
    return commands


def service_failure(component, reason):
    path = profile_log_paths(ACTIVE_PROFILE).get(component, ROOT / ".dev-logs")
    return SetupError(
        f"{component}: {reason}. Log: {path}. Correct the component/configuration, then run python scripts/dev.py restart --profile {ACTIVE_PROFILE}."
    )


def service_pid_matches(runtime, record, pid):
    if type(pid) is not int:
        return False
    if sys.platform != "win32":
        return pid == record["pid"]
    saved = next((info for info in [record, *record.get("members", [])] if info["pid"] == pid), None)
    if not saved:
        return False
    try:
        return matches(saved, process_info(pid))
    except OwnershipError as error:
        runtime.inspection_errors[record["pid"]] = str(error)
        return False


def background_health(runtime, env, *, require_control=False):
    state = runtime.state or runtime.load() or {}
    records = state.get("services", {})
    expected = {}
    for component, role, queues in (
        ("Celery worker", "default", {"celery"}),
        ("Celery reports worker", "reports", {"reports"}),
        ("Celery Beat", "beat", None),
    ):
        record = records.get(component)
        if not record:
            raise service_failure(component, "status=STOPPED; no owned process was registered")
        if runtime.service_status(record) != "RUNNING":
            raise OwnershipError(runtime.diagnostic(component, record))
        path = heartbeat_path(env, role)
        try:
            if path.is_symlink():
                raise ValueError()
            value = json.loads(path.read_text())
            if (
                value.get("instance") != state.get("instance")
                or not service_pid_matches(runtime, record, value.get("pid"))
                or not 0 <= time.time() - value.get("time", 0) <= 20
            ):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            raise service_failure(
                component, "health/progress heartbeat is missing, stale or from another instance"
            ) from None
        if queues is not None:
            node = worker_node(role, state["instance"], env["SBOM_DEV_PROFILE"])
            if not value.get("connected") or value.get("node") != node or set(value.get("queues", [])) != queues:
                raise service_failure(component, "worker is disconnected or is consuming the wrong queues")
            expected[node] = (component, value["pid"], queues)
    if require_control:
        with celery_control(env) as control:
            inspector = control.control.inspect(destination=list(expected), timeout=2)
            pings, active, statistics = inspector.ping() or {}, inspector.active_queues() or {}, inspector.stats() or {}
        for node, (component, pid, queues) in expected.items():
            if pings.get(node, {}).get("ok") != "pong":
                raise service_failure(component, "worker did not answer its control ping")
            if {q["name"] for q in active.get(node, [])} != queues or statistics.get(node, {}).get("pid") != pid:
                raise service_failure(component, "control response does not match the owned worker PID/assigned queues")


def wait_for_background(runtime, env, timeout=90):
    deadline = time.monotonic() + timeout
    problem = None
    while time.monotonic() < deadline:
        runtime.refresh()
        for component in background_commands(env):
            record = runtime.state["services"].get(component)
            if record and runtime.service_status(record) != "RUNNING":
                raise OwnershipError(runtime.diagnostic(component, record))
        try:
            background_health(runtime, env, require_control=True)
            return
        except SetupError as error:
            problem = error
        time.sleep(1)
    raise problem or service_failure("Celery worker", "startup timed out")


def start_background(runtime, env, cwd):
    verify_data_connectivity(env)
    reject_foreign_workers(env)
    processes = {}
    for name, command in background_commands(env).items():
        child_env = dict(env)
        if name != "Celery Beat":
            child_env["SBOM_DEV_WORKER_ROLE"] = "reports" if name == "Celery reports worker" else "default"
        processes[name] = start_process(name, command, child_env, cwd)
    wait_for_background(runtime, env)
    say("OK", "Background", "default/reports worker responses and queues verified; one Beat is making progress")
    return processes


def wait_http_component(runtime, env, component, urls, *, context=None, timeout=90):
    deadline = time.monotonic() + timeout
    problem = "HTTP readiness did not complete"
    while time.monotonic() < deadline:
        runtime.refresh()
        record = runtime.state["services"][component]
        if runtime.service_status(record) != "RUNNING":
            raise OwnershipError(runtime.diagnostic(component, record))
        try:
            background_health(runtime, env)
            for url, expected in urls:
                with urlopen(url, context=context if url.startswith("https:") else None, timeout=3) as response:
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
                    if expected:
                        payload = json.load(response)
                        if expected == "iam" and payload.get("ready") is not True:
                            raise ValueError("IAM readiness is false")
                        if expected == "database" and payload.get("database", {}).get("available") is not True:
                            raise ValueError("API database connectivity is unavailable")
            return
        except (OSError, ValueError, SetupError) as error:
            problem = redact(str(error), env)
        time.sleep(0.5)
    raise service_failure(component, problem)


def api_command(env, port):
    command = [
        str(venv_python()),
        "-B",
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--no-proxy-headers",
    ]
    if env.get("RELOAD", "false").lower() == "true":
        command.extend(["--reload", "--reload-dir", str(ROOT / "app")])
    return command


def launch_services(env, api_port, frontend_port, frontend_command, *, cwd, frontend_cwd, tls_context):
    if ACTIVE_RUNTIME is None:
        raise SetupError("Application startup requires the canonical ownership registry.")
    runtime = ACTIVE_RUNTIME
    env = runtime_environment(env)
    env.update(DEV_API_PORT=str(api_port), DEV_FRONTEND_PORT=str(frontend_port))
    processes = start_background(runtime, env, cwd)
    processes["API"] = start_process(
        "API",
        api_command(env, api_port),
        env,
        cwd,
    )
    api = f"http://127.0.0.1:{api_port}"
    api_checks = [(api + "/health", "database")]
    if env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true":
        api_checks.append((api + "/ready/iam", "iam"))
    wait_http_component(runtime, env, "API", api_checks)
    processes["Frontend"] = start_process("Frontend", frontend_command, env, frontend_cwd)
    wait_http_component(
        runtime,
        env,
        "Frontend",
        [
            (
                f"https://localhost:{frontend_port}/native-sign-in"
                if env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true"
                else f"https://localhost:{frontend_port}/",
                None,
            )
        ],
        context=tls_context,
    )
    background_health(runtime, env, require_control=True)
    runtime.state["ready"] = True
    atomic_json(runtime.path, runtime.state)
    say("OK", "Application", f"ready: https://localhost:{frontend_port}; API {api}; all queues and scheduler healthy")
    return processes, env


def supervise_runtime(runtime, env, processes):
    next_health = time.monotonic() + 5
    while True:
        runtime.refresh()
        for name, process in processes.items():
            if process.poll() is not None:
                runtime.state["ready"] = False
                atomic_json(runtime.path, runtime.state)
                raise service_failure(name, f"process exited with code {process.returncode}")
        if time.monotonic() >= next_health:
            try:
                verify_data_connectivity(env)
                background_health(runtime, env)
            except Exception as error:
                runtime.state["ready"] = False
                atomic_json(runtime.path, runtime.state)
                if isinstance(error, (SetupError, OwnershipError)):
                    raise
                raise service_failure(
                    "Celery worker", f"background health check failed ({type(error).__name__})"
                ) from None
            next_health = time.monotonic() + 5
        time.sleep(0.5)


def launcher_command(platform_name: str | None = None) -> str:
    """The command a developer should type on this platform."""
    return "python scripts/dev.py" if (platform_name or os.name) == "nt" else "python3 scripts/dev.py"


def explain_failed_command(result: subprocess.CompletedProcess, env: dict[str, str] | None = None) -> None:
    """Show the redacted tail of a failed setup command when --verbose is off.

    Only callers running a required setup step (venv, pip, npm, Compose,
    Alembic) use this; routine probes stay silent. Application service logs
    are never printed here.
    """
    if result.returncode == 0 or VERBOSE:
        return
    lines = redact("\n".join(filter(None, (result.stdout, result.stderr))), env).splitlines()
    if lines:
        print("[DETAIL] Failed command output (last 35 lines):", file=sys.stderr)
        for line in lines[-35:]:
            print("  " + line, file=sys.stderr)
    else:
        print(f"[DETAIL] Command exited with code {result.returncode} without output.", file=sys.stderr)


def validate_python_version(version: tuple[int, ...] | None = None) -> None:
    version = tuple(version or sys.version_info[:3])
    if version >= MIN_PYTHON:
        return
    found = ".".join(str(part) for part in version)
    required = ".".join(str(part) for part in MIN_PYTHON)
    if Path(sys.prefix).resolve() == VENV.resolve():
        raise SetupError(
            f"The existing .venv uses Python {found}; Python {required}+ is required. "
            "Move or delete .venv, then rerun with a Python 3.11+ interpreter."
        )
    raise SetupError(f"Python {found} is too old. Install Python {required} or newer and rerun.")


def pre_uuid_revisions(script) -> set[str]:
    """Strict ancestors of the UUID baseline: revisions an upgrade would carry across revision 100."""
    return {revision.revision for revision in script.iterate_revisions(GREENFIELD_UUID_BASELINE, "base")} - {
        GREENFIELD_UUID_BASELINE
    }


def check_pre_uuid_crossing(revision: str | None, populated: list[str]) -> None:
    """Fail closed before Alembic instead of relying on revision 100's in-migration refusal."""
    if populated:
        raise SetupError(
            f"sbom_analyser_dev is at pre-UUID revision {revision} and has rows in {', '.join(populated)}. "
            f"Revision {GREENFIELD_UUID_BASELINE} refuses populated application tables and no supported "
            "in-place upgrade exists. Alembic was not run and nothing was changed. Keep this database, and "
            "see docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md before choosing a fresh development database."
        )


def node_version() -> tuple[int, int, int] | None:
    """Return the installed Node.js version, or None when node is missing or unreadable."""
    node = GreenfieldStack.node_binary()
    if not node:
        return None
    try:
        result = run([str(node), "--version"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode:
        return None
    # Leading numbers only, so prerelease/nightly suffixes (v23.0.0-rc.1) still parse.
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", (result.stdout or "").strip())
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def node_problem(version: tuple[int, int, int] | None) -> str | None:
    required = ".".join(str(part) for part in MIN_NODE)
    if version is None:
        return f"Node.js was not found or did not report a version. Install Node.js {required}+."
    if version < MIN_NODE:
        found = ".".join(str(part) for part in version)
        return f"Node.js {found} is too old for the locked Next.js release. Install Node.js {required}+."
    return None


def validate_repository_layout() -> None:
    required = REQUIRED_FILES
    missing = [name for name in required if not (ROOT / name).is_file()]
    if missing:
        raise SetupError("Incomplete checkout. Missing: " + ", ".join(missing) + ". Restore the complete repository.")


def resolve_profile(requested: str = "auto") -> str:
    state = Path.home() / ".sbom-greenfield-uuid"
    profile = ("greenfield" if state.exists() or state.is_symlink() else "legacy") if requested == "auto" else requested
    if profile not in {"greenfield", "legacy"}:
        raise SetupError("Unknown profile; select --profile greenfield or --profile legacy.")
    if profile == "greenfield":
        required = ("environment.json", "runtime-password", "setup-password", "docker-identities.json")
        # Docker identity validation happens before container operations. Selection
        # itself deliberately does not open private credentials.
        missing = [name for name in required[:3] if not (state / name).is_file() or (state / name).is_symlink()]
        if state.is_symlink() or not state.is_dir() or missing:
            raise SetupError(
                "Greenfield installation is absent/incomplete. Restore its private installation and credentials; "
                "see docs/uuid-migration/GREENFIELD_UUID_ACCEPTANCE.md. No fallback to Legacy occurred."
            )
    return profile


def validate_greenfield_installation(state=None):
    state = GreenfieldStack.STATE if state is None else state
    if (
        state.is_symlink()
        or not state.is_dir()
        or any(
            not (state / name).is_file() or (state / name).is_symlink()
            for name in ("environment.json", "runtime-password", "setup-password")
        )
    ):
        raise SetupError(
            "Greenfield installation is incomplete. Restore its private files; no fallback or credential regeneration occurred."
        )


def select_legacy_configuration(requested="auto"):
    if requested != "auto":
        return requested
    if CONFIG.exists():
        return "managed"
    return "windows" if (ROOT / ".windows/sbom.env.ps1").exists() else "managed"


def pin_legacy_configuration(requested, state):
    recorded = (state or {}).get("legacy_config")
    if (state or {}).get("profile") == "legacy" and recorded:
        if requested not in {"auto", recorded}:
            raise SetupError(
                "Recorded Legacy configuration differs. Stop using its recorded configuration before switching."
            )
        return recorded
    return select_legacy_configuration(requested)


def read_literal_windows_configuration(path):
    """Read the saved assignment data; never invoke a PowerShell interpreter."""
    if path.is_symlink():
        raise SetupError("Saved Windows configuration must not be redirected.")
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*\$env:([A-Za-z_][A-Za-z_0-9]*)\s*=\s*'((?:[^']|'')*)'\s*", line)
        if not match:
            raise SetupError(
                "Saved Windows configuration contains executable/nonliteral content. Convert it to literal $env:NAME = 'value' assignments; it was not executed or modified."
            )
        result[match[1]] = match[2].replace("''", "'")
    return result


def existing_legacy_environment(configuration):
    from dotenv import dotenv_values

    path = ROOT / ".windows/sbom.env.ps1" if configuration == "windows" else ROOT / ".env"
    if not path.is_file():
        raise SetupError(
            f"Selected Legacy {configuration} configuration is absent: {path}. No alternate database was selected."
        )
    values = (
        read_literal_windows_configuration(path)
        if configuration == "windows"
        else dict(dotenv_values(path, interpolate=False))
    )
    frontend = ROOT / "frontend/.env.local"
    front_values = dict(dotenv_values(frontend, interpolate=False)) if frontend.is_file() else {}
    env = {
        **os.environ,
        **{key: value for key, value in front_values.items() if value is not None},
        **{key: value for key, value in values.items() if value is not None},
    }
    target = urlsplit(env.get("DATABASE_URL", ""))
    if (
        target.scheme not in {"postgresql", "postgresql+psycopg"}
        or target.hostname not in {"localhost", "127.0.0.1", "::1"}
        or not target.path.strip("/")
        or target.path.strip("/") in {"postgres", "template0", "template1", "sbom_greenfield_uuid"}
        or target.port == 56044
    ):
        raise SetupError(
            "Saved Legacy configuration must identify its own local development PostgreSQL database, outside Greenfield. No configuration or data was changed."
        )
    env.setdefault("DEV_API_PORT", "8000")
    env.setdefault("DEV_FRONTEND_PORT", "3000")
    native = env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true"
    env.setdefault("AUTH_ENABLED", "true")
    env.setdefault("NATIVE_AUTH_ENABLED", "false")
    env.setdefault("HCL_AUTH_ENABLED", "false" if native else "true")
    env.setdefault("NEXT_PUBLIC_HCL_AUTH_ENABLED", "false" if native else "true")
    env.setdefault("NEXT_PUBLIC_NATIVE_AUTH_ENABLED", "true" if native else "false")
    env.setdefault("REDIS_URL", "redis://127.0.0.1:6379/0")
    env.setdefault("CELERY_BROKER_URL", env["REDIS_URL"])
    env.setdefault("CELERY_RESULT_BACKEND", env["REDIS_URL"])
    if env.get("CELERY_USE_DATABASE_BROKER", "false").lower() == "true":
        raise SetupError(
            "Local worker-response verification requires Redis. Configure this saved Legacy installation's Redis broker explicitly; its database-broker setting was not changed."
        )
    env["PYTHONPATH"] = str(ROOT)
    return env


def profile_environment(profile):
    if profile == "greenfield":
        return runtime_environment(GreenfieldStack.settings())
    if ACTIVE_LEGACY_CONFIG != "managed":
        return runtime_environment(existing_legacy_environment(ACTIVE_LEGACY_CONFIG))
    values = read_config()
    if not values.get("DATABASE_URL"):
        raise SetupError("Legacy configuration has not been prepared. Run python scripts/dev.py first.")
    return runtime_environment({**os.environ, **values})


def verify_existing_schema(env):
    import psycopg
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    try:
        with psycopg.connect(
            env["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1),
            connect_timeout=3,
            options="-c default_transaction_read_only=on -c statement_timeout=3000",
        ) as connection:
            row = connection.execute("SELECT version_num FROM public.alembic_version").fetchone()
    except psycopg.Error as error:
        raise SetupError(
            f"Legacy schema preflight failed ({type(error).__name__}). Use setup with explicitly confirmed database initialization/upgrade; startup did not modify this database."
        ) from None
    if not row or row[0] != head:
        raise SetupError(
            "Legacy schema is not current. Review python scripts/dev.py setup --migrate --confirm-database <saved-database-name>; startup made no schema changes."
        )
    return head


def setup_application(args):
    global ACTIVE_PROFILE, ACTIVE_LEGACY_CONFIG
    profile = args.profile
    if profile == "auto":
        profile = "greenfield" if GreenfieldStack.STATE.exists() else "legacy"
    ACTIVE_PROFILE = profile
    ACTIVE_LEGACY_CONFIG = select_legacy_configuration(args.legacy_config)
    state = Runtime(ROOT).load() or {}
    if state.get("services") and any((args.provision_greenfield, args.initialize_database, args.migrate)):
        raise SetupError(
            "Stop the managed runtime before explicit provisioning or schema setup. No database changes were made."
        )
    validate_repository_layout()
    validate_prerequisites()
    ensure_virtualenv()
    ensure_dependencies()
    if profile == "greenfield":
        if args.provision_greenfield or args.initialize_database:
            if args.confirm_database != GreenfieldStack.DB:
                raise SetupError(
                    "Explicit Greenfield setup requires --confirm-database sbom_greenfield_uuid. Existing databases are never reset."
                )
        if args.provision_greenfield:
            LocalHttps.ensure_certificate(GreenfieldStack.STATE, prepare=True)
            GreenfieldStack.provision()
        else:
            resolve_profile("greenfield")
            LocalHttps.ensure_certificate(GreenfieldStack.STATE, prepare=True)
        ensure_frontend(certificate=False)
        if args.initialize_database:
            previous, directory = dict(os.environ), Path.cwd()
            try:
                GreenfieldStack.bootstrap()
            finally:
                os.environ.clear()
                os.environ.update(previous)
                os.chdir(directory)
        if args.migrate:
            from scripts import greenfield_migrations

            greenfield_migrations.ensure_current()
        if args.frontend_build:
            env = GreenfieldStack.settings()
            env["NODE_ENV"] = "production"
            result = run(
                [
                    str(GreenfieldStack.node_binary()),
                    str(ROOT / "frontend/node_modules/next/dist/bin/next"),
                    "build",
                    "--webpack",
                ],
                env=env,
                cwd=GreenfieldStack.frontend_workspace("frontend-build"),
            )
            if result.returncode:
                raise SetupError(
                    "Local frontend build failed. Rerun setup --frontend-build --verbose for the redacted diagnostic."
                )
    else:
        if args.frontend_build:
            raise SetupError("--frontend-build selects the isolated Greenfield workspace; use --profile greenfield.")
        ensure_frontend()
        legacy_https_context()
        if args.provision_greenfield:
            raise SetupError("--provision-greenfield cannot be used with Legacy.")
        if args.initialize_database or args.migrate:
            env = (
                prepare_managed_legacy()
                if ACTIVE_LEGACY_CONFIG == "managed"
                else existing_legacy_environment(ACTIVE_LEGACY_CONFIG)
            )
            name = urlsplit(env["DATABASE_URL"]).path.lstrip("/")
            if args.confirm_database != name:
                raise SetupError("Database setup requires --confirm-database matching the saved local database name.")
            if args.initialize_database:
                from scripts.bootstrap_fresh_database import bootstrap

                previous = dict(os.environ)
                try:
                    os.environ.update(env)
                    bootstrap(env["DATABASE_URL"], name)
                finally:
                    os.environ.clear()
                    os.environ.update(previous)
            else:
                validate_existing_schema(env["DATABASE_URL"], validate_target=ACTIVE_LEGACY_CONFIG == "managed")
                run_migrations(env)
    say(
        "OK",
        "Setup",
        "project dependencies and local HTTPS prepared; existing configuration retained; no application processes started",
    )


def check_profile_ownership(runtime, profile: str) -> None:
    state = runtime.load()
    if not state:
        return
    recorded = state.get("profile")
    if recorded is None:
        # Upgrade an old registry interpretation without rewriting it or
        # trusting process names/ports. Only recorded PID equality identifies
        # which historical profile created these already-owned children.
        try:
            processes = json.loads((Path.home() / ".sbom-greenfield-uuid/processes.json").read_text())
            managed = {item["pid"] for item in processes.values()}
        except (OSError, ValueError, KeyError, TypeError):
            managed = set()
        pids = {item["pid"] for item in state["services"].values()}
        recorded = "greenfield" if pids and pids <= managed else "legacy"
    if recorded != profile:
        raise SetupError(
            f"This checkout has a {recorded} profile runtime; requested {profile}. "
            f"Use --profile {recorded} to inspect/stop it first. No process was stopped."
        )


def control_profile(requested: str) -> str:
    """Stop/status must remain available even if an installation credential is lost."""
    state = Runtime(ROOT).load()
    if state and state.get("profile") in {"greenfield", "legacy"}:
        return state["profile"] if requested == "auto" else requested
    if requested in {"greenfield", "legacy"}:
        return requested
    return "greenfield" if (Path.home() / ".sbom-greenfield-uuid").exists() else "legacy"


def platform_spawn_options() -> dict:
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    if sys.platform == "darwin" or sys.platform.startswith("linux"):
        return {"start_new_session": True}
    raise SetupError("The launcher supports Windows, macOS and Linux adapters only.")


def validate_prerequisites() -> None:
    if sys.version_info < (3, 11):  # noqa: UP036 - this script is the initial Python prerequisite probe
        raise SetupError("Python 3.11 or newer is required. Install it from python.org, then rerun this launcher.")
    platform_spawn_options()
    node = GreenfieldStack.node_binary()
    try:
        result = subprocess.run([str(node), "--version"], capture_output=True, text=True, timeout=10)
        match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", result.stdout.strip())
        parts = tuple(int(match[i]) for i in (1, 2, 3)) if match else ()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SetupError(
            "A working Node.js 20.9+ runtime is required. Install Node.js LTS from nodejs.org "
            "(Windows/macOS) or your Linux package manager; reopen the terminal."
        ) from None
    if result.returncode or parts < MIN_NODE:
        raise SetupError("Node.js 20.9+ is required by Next.js. Install a current Node.js LTS and reopen the terminal.")
    npm = shutil.which("npm", path=str(node.parent) + os.pathsep + os.environ.get("PATH", ""))
    if not npm:
        raise SetupError("npm is missing. Install Node.js LTS including npm, then reopen the terminal.")
    env = dict(os.environ)
    env["PATH"] = str(node.parent) + os.pathsep + env.get("PATH", "")
    try:
        npm_result = subprocess.run(
            normalize_command([npm, "--version"]), env=env, capture_output=True, text=True, timeout=15
        )
        if npm_result.returncode:
            raise ValueError()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SetupError(
            "npm cannot run with the selected Node.js runtime. Repair/reinstall Node.js LTS including npm and reopen the terminal."
        ) from None
    say("OK", "Prerequisites", f"Python {platform.python_version()}, Node {result.stdout.strip()}, npm found")


def doctor(args) -> None:
    """Read-only prerequisite inspection; never creates a venv, credentials or DB."""
    global ACTIVE_PROFILE
    validate_repository_layout()
    validate_prerequisites()
    profile = resolve_profile(args.profile)
    ACTIVE_PROFILE = profile
    say("OK", "Profile", profile)
    if profile == "greenfield":
        # Check trust before reading application passwords or resuming containers.
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise SetupError(
                "Project cryptography dependency is missing. Run python scripts/dev.py start to prepare the project virtualenv, then rerun doctor."
            ) from None
        LocalHttps.ensure_certificate(GreenfieldStack.STATE, prepare=False)
        GreenfieldProfile.inventory()
        say("OK", "Greenfield", "existing container identities and HTTPS trust verified")
    else:
        if not docker_available():
            if not service_available("postgres", 5432) or not service_available("redis", 6379):
                raise SetupError(
                    "Docker is unavailable and local PostgreSQL/Redis are not both reachable. "
                    "Install/start Docker Desktop (Windows/macOS) or Docker Engine with Compose (Linux), "
                    "or start your explicitly configured local services."
                )
        say(
            "OK",
            "Configuration",
            "existing .env.dev.local will be preserved"
            if CONFIG.is_file()
            else "first start will prepare private Legacy settings",
        )
    if (Runtime(ROOT).load() or {}).get("services"):
        if not application_status(profile):
            raise SetupError(
                "Doctor found an unhealthy managed runtime. Inspect the named component logs and restart after correcting it."
            )
    say("OK", "Doctor", "read-only checks finished; native authentication/browser acceptance is separate")


def profile_log_paths(profile: str) -> dict[str, Path]:
    if profile == "greenfield":
        return {
            "API": GreenfieldStack.STATE / "backend.log",
            "Frontend": GreenfieldStack.STATE / "frontend.log",
            "Celery worker": GreenfieldStack.STATE / "worker.log",
            "Celery reports worker": GreenfieldStack.STATE / "reports-worker.log",
            "Celery Beat": GreenfieldStack.STATE / "beat.log",
        }
    return {
        name: ROOT / ".dev-logs" / (name.lower().replace(" ", "-") + ".log")
        for name in ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")
    }


def display_logs(args) -> None:
    if args.service in {"postgres", "redis", "mailpit"}:
        display_data_logs(args)
        return
    paths = profile_log_paths(args.profile)
    if args.service != "all":
        if args.service not in paths:
            raise SetupError(
                f"Service {args.service} has no separate log in {args.profile}. Choose: " + ", ".join(paths)
            )
        paths = {args.service: paths[args.service]}
    env = (
        (read_config() if ACTIVE_LEGACY_CONFIG == "managed" else existing_legacy_environment(ACTIVE_LEGACY_CONFIG))
        if args.profile == "legacy"
        else json.loads(GreenfieldStack.read_private("environment.json"))
    )
    # Runtime password is separate from environment.json; keep it only in
    # memory to redact any accidentally logged URL/password text.
    if args.profile == "greenfield":
        env["RUNTIME_PASSWORD"] = GreenfieldStack.read_private("runtime-password")
    for name, path in paths.items():
        print(f"{name}: {path}")
        if not path.exists():
            print("No log yet. Start the selected profile first.")
            continue
        if path.is_symlink() or not path.is_file():
            raise SetupError("Refusing a redirected/non-regular development log: " + str(path))
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - 1024 * 1024))
            content = stream.read().decode("utf-8", errors="replace")
        # Redact before tailing so a PEM beginning above the requested tail
        # still protects its following lines. A byte-bounded read can itself
        # start inside a PEM, so discard any such prefix through its END marker.
        content = re.sub(
            r"\A(?:(?!-----BEGIN [^-]*PRIVATE KEY-----).)*?-----END [^-]*PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
            content,
            flags=re.S,
        )
        print("\n".join(deque(redact(content, env).splitlines(), maxlen=args.lines)))


def display_data_logs(args):
    """Read only verified profile containers; never guess ownership from a port."""
    if args.profile == "greenfield":
        GreenfieldProfile.inventory()
        identities = json.loads(GreenfieldStack.read_private("docker-identities.json"))
        container = identities.get(f"sbom-greenfield-uuid-dev-{args.service}-1")
        command = GreenfieldStack.docker_command()
    elif ACTIVE_LEGACY_CONFIG == "managed" and compose_container(args.service):
        result = run(["docker", "compose", "ps", "-q", args.service])
        container, command = result.stdout.strip(), ["docker"]
    else:
        raise SetupError(
            f"{args.service} is externally managed. Read logs through its configured OS/service manager; no container ownership was inferred."
        )
    if not container:
        raise SetupError(f"No recorded {args.service} container. Run doctor to check the selected installation.")
    result = run(command + ["logs", "--tail", str(args.lines), container])
    if result.returncode:
        raise SetupError(f"Unable to read {args.service} Docker logs. Check Docker availability and run doctor.")
    env = profile_environment(args.profile)
    print(redact((result.stdout or "") + (result.stderr or ""), env))


class LocalHttps:
    """Native trust and private certificate adapters; never modifies root trust."""

    HOSTS = ("localhost", "127.0.0.1", "::1")

    class HttpsTrustError(SetupError):
        pass

    @staticmethod
    def private_directory(path):
        info = path.lstat()
        if sys.platform == "win32":
            if not stat.S_ISDIR(info.st_mode) or LocalHttps._windows_reparse(info):
                raise LocalHttps.HttpsTrustError("HTTPS state must be an owned, nonsymlink private directory")
            LocalHttps._windows_access(path, private=True)
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 448:
            raise LocalHttps.HttpsTrustError("HTTPS state must be an owned, nonsymlink private directory (0700)")

    @staticmethod
    def read_file(path, *, key=False):
        path = Path(path)
        before = path.lstat()
        if sys.platform == "win32" and (stat.S_ISLNK(before.st_mode) or LocalHttps._windows_reparse(before)):
            raise LocalHttps.HttpsTrustError("HTTPS material must not be a symlink or reparse point")
        if sys.platform == "win32":
            LocalHttps._windows_access(path, private=key)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise LocalHttps.HttpsTrustError("HTTPS material must be owned, regular, single-link files")
            if sys.platform != "win32" and info.st_uid != os.getuid():
                raise LocalHttps.HttpsTrustError("HTTPS material must be owned by the current user")
            if key and sys.platform != "win32" and (stat.S_IMODE(info.st_mode) != 384):
                raise LocalHttps.HttpsTrustError("HTTPS private key must have mode 0600")
            if sys.platform == "win32":
                LocalHttps._windows_access(path, private=key)
            data = source.read(131073)
            if len(data) > 131072:
                raise LocalHttps.HttpsTrustError("Unexpected HTTPS material size")
            return data

    @staticmethod
    def _windows_reparse(info):
        return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))

    @staticmethod
    def _windows_access(path, *, private):
        """Require current-user ownership and a restrictive native Windows DACL.

        Administrators and SYSTEM are permitted. Never infer security from POSIX
        chmod bits on Windows, and never change the user's ACL or trust settings.
        """
        import json

        env = LocalHttps.clean_environment()
        env["SBOM_TLS_ACL_PATH"] = str(Path(path).absolute())
        powershell = shutil.which("powershell.exe", path=env["PATH"])
        if not powershell:
            raise LocalHttps.HttpsTrustError(
                "PowerShell is required to verify Windows private-file ACLs; install/restore Windows PowerShell."
            )
        script = "$ErrorActionPreference='Stop';$acl=Get-Acl -LiteralPath $env:SBOM_TLS_ACL_PATH;$rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { @{sid=$_.IdentityReference.Value;type=[int]$_.AccessControlType;rights=[int]$_.FileSystemRights} });@{owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value;current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;protected=$acl.AreAccessRulesProtected;rules=$rules} | ConvertTo-Json -Compress -Depth 4"
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode:
                raise ValueError()
            acl = json.loads(result.stdout)
            if not acl.get("current") or acl.get("owner") != acl["current"]:
                raise ValueError()
            allowed = {acl["current"], "S-1-5-18", "S-1-5-32-544"}
            mutable_rights = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288
            rules = acl.get("rules")
            if not isinstance(rules, list) or not rules:
                raise ValueError()
            for rule in rules:
                if rule["type"] == 0 and rule["sid"] not in allowed:
                    if private or int(rule["rights"]) & mutable_rights:
                        raise ValueError()
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
            raise LocalHttps.HttpsTrustError(
                "Windows file ownership/private ACL verification failed. Restrict this path to your user, SYSTEM and Administrators using Windows Security/Advanced permissions, then rerun doctor; no ACL was changed."
            ) from None

    @staticmethod
    def clean_environment():
        if sys.platform == "win32":
            names = (
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
            )
            env = {name: os.environ[name] for name in names if name in os.environ}
            env.update(HOME=str(Path.home()), PATH=os.environ.get("PATH", os.defpath), LC_ALL="C")
            return env
        return {"HOME": str(Path.home()), "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}

    @staticmethod
    def system_trusted(cert, *, hostname=None):
        if sys.platform == "win32":
            return LocalHttps._windows_system_trusted(cert, hostname=hostname)
        if sys.platform == "darwin":
            args = ["/usr/bin/security", "verify-cert", "-c", str(cert), "-p", "ssl" if hostname else "basic"]
            if hostname:
                args += ["-s", hostname]
        elif sys.platform.startswith("linux"):
            executable = shutil.which("openssl", path=LocalHttps.clean_environment()["PATH"])
            if not executable:
                raise LocalHttps.HttpsTrustError(
                    "OpenSSL is required to verify Linux system certificate trust; install your distribution's openssl package."
                )
            args = [executable, "verify"]
            if hostname:
                args += ["-purpose", "sslserver", "-verify_hostname", hostname]
            args += [str(Path(cert).absolute())]
        else:
            raise LocalHttps.HttpsTrustError("HTTPS system trust verification supports Windows, macOS and Linux only.")
        try:
            return (
                subprocess.run(args, env=LocalHttps.clean_environment(), capture_output=True, timeout=15).returncode
                == 0
            )
        except (OSError, subprocess.TimeoutExpired):
            raise LocalHttps.HttpsTrustError(
                "System certificate trust verification could not run; restore the native trust tools and rerun doctor."
            ) from None

    @staticmethod
    def _windows_system_trusted(cert, *, hostname=None):
        """Trust only roots in the Windows ROOT store, for direct local-CA leaves.

        mkcert leaves are directly issued by their local root. The signature,
        validity, SAN, key and exact expected CA are also checked by validate_pair.
        An explicit Python CA bundle is never treated as Windows system trust.
        """
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization

        try:
            candidate = x509.load_pem_x509_certificate(LocalHttps.read_file(cert))
            native_roots = ssl.enum_certificates("ROOT")
            now = datetime.now(UTC)
            for raw, encoding, trust in native_roots:
                if encoding != "x509_asn" or (trust is not True and "1.3.6.1.5.5.7.3.1" not in trust):
                    continue
                root = x509.load_der_x509_certificate(raw)
                if not root.not_valid_before_utc <= now <= root.not_valid_after_utc:
                    continue
                if hostname is None:
                    if candidate.public_bytes(serialization.Encoding.DER) == raw:
                        return True
                    continue
                if not candidate.not_valid_before_utc <= now <= candidate.not_valid_after_utc:
                    return False
                try:
                    usages = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                    if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in usages:
                        return False
                except x509.ExtensionNotFound:
                    pass
                sans = candidate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if hostname not in sans.get_values_for_type(x509.DNSName):
                    return False
                try:
                    candidate.verify_directly_issued_by(root)
                    if root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                        return True
                except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                    continue
            return False
        except (AttributeError, OSError, ValueError, TypeError, x509.ExtensionNotFound):
            raise LocalHttps.HttpsTrustError(
                "Windows native ROOT store verification failed; review local CA trust and rerun doctor."
            ) from None

    @staticmethod
    def local_ca():
        executable = shutil.which("mkcert", path=LocalHttps.clean_environment()["PATH"])
        if not executable:
            raise LocalHttps.HttpsTrustError(
                "mkcert is required. Install it, then independently approve local CA trust setup."
            )
        result = subprocess.run(
            [executable, "-CAROOT"],
            env=LocalHttps.clean_environment(),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        root = Path(result.stdout.strip()) / "rootCA.pem"
        if not root.is_file() or root.is_symlink():
            raise LocalHttps.HttpsTrustError(
                "No existing mkcert CA. Operator confirmation is required before running mkcert -install."
            )
        LocalHttps.read_file(root)
        if not LocalHttps.system_trusted(root):
            raise LocalHttps.HttpsTrustError(
                "Local mkcert CA is not trusted by the operating system. Operator confirmation is required before mkcert -install; no trust-store change was made."
            )
        return (executable, root)

    @staticmethod
    def validate_pair(cert_path, key_path, root_path):
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization

        cert = x509.load_pem_x509_certificate(LocalHttps.read_file(cert_path))
        root = x509.load_pem_x509_certificate(LocalHttps.read_file(root_path))
        key = serialization.load_pem_private_key(LocalHttps.read_file(key_path, key=True), password=None)
        now = datetime.now(UTC)
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now + timedelta(days=7):
            raise LocalHttps.HttpsTrustError(
                "Local HTTPS certificate is not valid or expires within seven days; prepare a renewed leaf"
            )
        try:
            sans = {
                str(item.value) for item in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            }
            if sans != set(LocalHttps.HOSTS):
                raise ValueError()
            cert.verify_directly_issued_by(root)
            public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if cert.public_key().public_bytes(*public_format) != key.public_key().public_bytes(*public_format):
                raise ValueError()
        except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound) as exc:
            raise LocalHttps.HttpsTrustError(
                "HTTPS leaf must match its key and the trusted local CA, covering exactly localhost/IPv4/IPv6"
            ) from exc
        if not LocalHttps.system_trusted(cert_path, hostname="localhost"):
            raise LocalHttps.HttpsTrustError(
                "HTTPS certificate is not trusted by the operating system for localhost; browser readiness is blocked"
            )
        return {
            "certificate_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "issuer_sha256": root.fingerprint(hashes.SHA256()).hex(),
            "issuer": cert.issuer.rfc4514_string(),
            "sans": sorted(sans),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "macos_trusted": sys.platform == "darwin",
            "system_trusted": True,
            "trust_platform": sys.platform,
        }

    @staticmethod
    def ensure_certificate(state, *, prepare=False):
        if prepare:
            state.mkdir(mode=0o700, exist_ok=True)
        LocalHttps.private_directory(state)
        executable, root = LocalHttps.local_ca()
        cert, key = (state / "cert.pem", state / "cert-key.pem")
        for path, is_key in ((cert, False), (key, True)):
            if path.exists() or path.is_symlink():
                LocalHttps.read_file(path, key=is_key)
        try:
            metadata = LocalHttps.validate_pair(cert, key, root)
            return (cert, key, root, metadata)
        except (LocalHttps.HttpsTrustError, FileNotFoundError, ValueError) as exc:
            if not prepare:
                raise LocalHttps.HttpsTrustError(
                    "HTTPS trust check failed. Run python scripts/dev.py start --profile greenfield after reviewing the existing trusted CA; no application passwords or trust settings were changed."
                ) from exc
        with tempfile.TemporaryDirectory(prefix="https-staging-", dir=state) as directory:
            staging = Path(directory)
            candidate_cert, candidate_key = (staging / "cert.pem", staging / "cert-key.pem")
            old_mask = os.umask(0o077)
            try:
                subprocess.run(
                    [executable, "-cert-file", str(candidate_cert), "-key-file", str(candidate_key), *LocalHttps.HOSTS],
                    env=LocalHttps.clean_environment(),
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
            finally:
                os.umask(old_mask)
            candidate_key.chmod(384)
            candidate_cert.chmod(384)
            metadata = LocalHttps.validate_pair(candidate_cert, candidate_key, root)
            archive = Path(tempfile.mkdtemp(prefix="https-previous-", dir=state))
            for path in (cert, key):
                if path.exists():
                    path.rename(archive / path.name)
            candidate_key.rename(key)
            candidate_cert.rename(cert)
        return (cert, key, root, metadata)

    @staticmethod
    def client_context(state):
        _, _, root, _ = LocalHttps.ensure_certificate(state)
        return ssl.create_default_context(cafile=str(root))

    @staticmethod
    def verify_endpoint():
        env = LocalHttps.clean_environment()
        executable = (
            "/usr/bin/curl"
            if sys.platform == "darwin"
            else shutil.which("curl.exe" if sys.platform == "win32" else "curl", path=env["PATH"])
        )
        if not executable:
            raise LocalHttps.HttpsTrustError(
                "System curl is required to verify served HTTPS with native trust; install/restore curl and rerun doctor."
            )
        result = subprocess.run(
            [
                executable,
                "--disable",
                "--noproxy",
                "*",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                "--output",
                os.devnull,
                "https://localhost:13000/native-sign-in",
            ],
            env=env,
            capture_output=True,
            timeout=15,
        )
        if result.returncode:
            raise LocalHttps.HttpsTrustError(
                "Served HTTPS failed default system trust/HTTP verification. Check certificate selection and Chrome trust; no TLS bypass is permitted."
            )


class GreenfieldStack:
    """Private profile settings and verified existing resources; no provisioning on start."""

    ROOT = ROOT
    STATE = Path.home() / ".sbom-greenfield-uuid"
    DB = "sbom_greenfield_uuid"

    class ServicePortError(SetupError):
        pass

    @staticmethod
    def docker_command():
        executable = shutil.which("docker")
        if not executable:
            raise SetupError(
                "Docker is required for Greenfield. Install/start Docker Desktop (Windows/macOS) or Docker Engine with Compose (Linux)."
            )
        if sys.platform == "win32":
            return [executable]
        socket_path = Path.home() / ".docker/run/docker.sock"
        if not socket_path.exists():
            socket_path = Path("/var/run/docker.sock")
        return [executable, "--host", "unix://" + str(socket_path)]

    @staticmethod
    def current_revision():
        from scripts.greenfield_migration_graph import discover

        return discover(GreenfieldStack.ROOT).head

    @staticmethod
    def read_private(name):
        if Path(name).name != name:
            raise SetupError("Invalid private Greenfield filename.")
        LocalHttps.private_directory(GreenfieldStack.STATE)
        return LocalHttps.read_file(GreenfieldStack.STATE / name, key=True).decode("utf-8")

    @staticmethod
    def private_file(name, content):
        if Path(name).name != name:
            raise SetupError("Invalid private Greenfield filename.")
        GreenfieldStack.STATE.mkdir(mode=0o700, exist_ok=True)
        LocalHttps.private_directory(GreenfieldStack.STATE)
        path = GreenfieldStack.STATE / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
        LocalHttps.read_file(path, key=True)
        return path

    @staticmethod
    def settings():
        path = GreenfieldStack.STATE / "environment.json"
        if not path.exists():
            raise SetupError(
                "Greenfield environment.json is missing. Restore the private installation; no credentials were regenerated."
            )
        env = {k: v for k, v in os.environ.items() if k in ("HOME", "PATH", "TMPDIR", "LANG", "TERM")}
        if sys.platform == "win32":
            for name in (
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
            ):
                if name in os.environ:
                    env[name] = os.environ[name]
        try:
            saved = json.loads(GreenfieldStack.read_private("environment.json"))
        except ValueError:
            raise SetupError(
                "Private Greenfield environment.json is malformed. Restore valid JSON; no credentials were replaced."
            ) from None
        if not isinstance(saved, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in saved.items()
        ):
            raise SetupError(
                'Private Greenfield environment.json must map environment names to strings (for example, "true"). Restore its existing values; no credentials were replaced.'
            )
        env.update(saved)
        if "NATIVE_SECURITY_OUTBOX_KEY" not in env:
            if not (GreenfieldStack.STATE / "security-mail-key").exists():
                raise SetupError(
                    "Existing security-mail key is missing. Restore the original private key; it was not regenerated."
                )
            env["NATIVE_SECURITY_OUTBOX_KEY"] = GreenfieldStack.read_private("security-mail-key")
        if "AI_CONFIG_ENCRYPTION_KEY" not in env:
            if not (GreenfieldStack.STATE / "provider-storage-key").exists():
                raise SetupError(
                    "Existing provider storage key is missing. Restore the original key; it was not regenerated."
                )
            env["AI_CONFIG_ENCRYPTION_KEY"] = base64.b64encode(
                base64.urlsafe_b64decode(GreenfieldStack.read_private("provider-storage-key"))
            ).decode()
        env.update(
            {
                "PYTHON_DOTENV_DISABLED": "1",
                "GREENFIELD_STATE": str(GreenfieldStack.STATE),
                "PYTHONPATH": str(GreenfieldStack.ROOT),
                "PYTHONDONTWRITEBYTECODE": "1",
                "DATABASE_URL": GreenfieldStack.url("greenfield_app", "runtime-password"),
                "AUTH_ENABLED": "true",
                "HCL_AUTH_ENABLED": "false",
                "NATIVE_AUTH_ENABLED": "true",
                "ENTRA_ENABLED": "false",
                "NATIVE_JWT_VERIFICATION_KEYS_JSON": "{}",
                "DEV_DEFAULT_TENANT": "false",
                "NATIVE_IAM_PRODUCTION": "false",
                "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
                "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": "redis://127.0.0.1:56381/3",
                "API_AUTH_MODE": "none",
                "NATIVE_USER_CREATION_ENABLED": "true",
                "NATIVE_PASSWORD_RESET_FRONTEND_URL": "https://localhost:13000/reset-password",
                "API_RATE_LIMIT_ENABLED": "true",
                "NATIVE_JWT_ISSUER": "https://greenfield.local",
                "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
                "NATIVE_JWT_ACCESS_TOKEN_TTL_SECONDS": "3600",
                "AUTHORIZATION_CATALOG_MODE": "DATABASE",
                "AUTHORIZATION_CATALOG_FAIL_CLOSED": "true",
                "TENANT_ROLE_ASSIGNMENT_MODE": "DATABASE",
                "TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED": "true",
                "EMAIL_DELIVERY_ENABLED": "true",
                "EMAIL_FROM_ADDRESS": "sbom-greenfield@example.test",
                "EMAIL_VERIFICATION_FRONTEND_URL": "https://localhost:13000/verify-email",
                "NATIVE_ACTIVATION_FRONTEND_URL": "https://localhost:13000/activate-account",
                "REPORT_NOTIFICATIONS_ENABLED": "true",
                "REPORT_NOTIFICATION_BASE_URL": "https://localhost:13000",
                "REPORT_ARTIFACT_STORAGE_PATH": str(GreenfieldStack.STATE / "reports"),
                "SMTP_HOST": "127.0.0.1",
                "SMTP_PORT": "1026",
                "SMTP_USE_STARTTLS": "false",
                "NVD_ENABLED": "false",
                "ANALYSIS_SOURCES": "OSV",
                "SBOM_WORKSPACE_STORAGE_DIR": str(GreenfieldStack.STATE / "workspaces"),
                "NEXT_PUBLIC_AUTH_ENABLED": "true",
                "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true",
                "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
                "NEXT_PUBLIC_ENTRA_ENABLED": "false",
                "NEXT_PUBLIC_API_URL": "http://127.0.0.1:18000",
                "SBOM_API_URL": "http://127.0.0.1:18000",
                "APP_ORIGIN": "https://localhost:13000",
                "CORS_ORIGINS": "https://localhost:13000",
                "AUTH_SESSION_STORE": "redis",
                "AUTH_SESSION_REDIS_URL": "redis://127.0.0.1:56381/1",
                "REDIS_URL": "redis://127.0.0.1:56381/0",
                "CELERY_BROKER_URL": "redis://127.0.0.1:56381/0",
                "CELERY_RESULT_BACKEND": "redis://127.0.0.1:56381/2",
                "SBOM_AUTO_REPAIR_ENABLED": "true",
                "NODE_ENV": "development",
                "LOG_FILE": "",
            }
        )
        return env

    @staticmethod
    def url(user, filename, database=DB):
        from sqlalchemy.engine import URL

        if database not in {
            GreenfieldStack.DB,
            "postgres",
            GreenfieldStack.DB + "_repro_test",
            GreenfieldStack.DB + "_integrity_test",
            GreenfieldStack.DB + "_regression_test",
        }:
            raise RuntimeError("Database outside the greenfield task scope")
        if (user, filename) not in {("greenfield_app", "runtime-password"), ("greenfield_setup", "setup-password")}:
            raise RuntimeError("Unexpected greenfield credential selection")
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=GreenfieldStack.read_private(filename),
            host="127.0.0.1",
            port=56044,
            database=database,
        ).render_as_string(hide_password=False)

    @staticmethod
    def verify_resources():
        identities = json.loads(GreenfieldStack.read_private("docker-identities.json"))
        names = {"sbom-greenfield-uuid-dev-" + service + "-1" for service in ("postgres", "redis", "mailpit")}
        if set(identities) != names:
            raise RuntimeError("Unexpected greenfield resource inventory")
        for name, expected in identities.items():
            actual = json.loads(
                subprocess.check_output(GreenfieldStack.docker_command() + ["inspect", name], text=True)
            )[0]
            labels = actual["Config"]["Labels"]
            if actual["Id"] != expected or labels.get("com.docker.compose.project") != "sbom-greenfield-uuid-dev":
                raise RuntimeError("Greenfield resource identity changed")
            if set(actual["NetworkSettings"]["Networks"]) != {"sbom-greenfield-uuid-dev_access"}:
                raise RuntimeError("Unexpected greenfield network attachment")
            service = name.removeprefix("sbom-greenfield-uuid-dev-").removesuffix("-1")
            publications = {
                "postgres": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56044"}]},
                "redis": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56381"}]},
                "mailpit": {
                    "1025/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1026"}],
                    "8025/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8026"}],
                },
            }
            if actual["HostConfig"]["PortBindings"] != publications[service]:
                raise SetupError(
                    f"Greenfield {service} publication changed. Restore its verified loopback ports; no container was changed."
                )
            if service == "redis" and [m["Name"] for m in actual["Mounts"] if m["Type"] == "volume"] != [
                "sbom-greenfield-uuid-dev_redisdata"
            ]:
                raise SetupError("Greenfield Redis storage changed. Restore its existing volume; no data was changed.")
            if name.endswith("-postgres-1"):
                if actual["Image"] != "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54":
                    raise RuntimeError("Unexpected PostgreSQL image")
                if actual["HostConfig"]["PortBindings"] != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56044"}]}:
                    raise RuntimeError("Unexpected PostgreSQL publication")
                volumes = [m["Name"] for m in actual["Mounts"] if m["Type"] == "volume"]
                if volumes != ["sbom-greenfield-uuid-dev_pgdata"]:
                    raise RuntimeError("Unexpected PostgreSQL storage")

    @staticmethod
    def frontend_workspace(name):
        if name not in {"frontend", "frontend-build"}:
            raise RuntimeError("Unexpected frontend workspace")
        ui = GreenfieldStack.STATE / name
        if ui.is_symlink() or (ui.exists() and LocalHttps._windows_reparse(ui.lstat())):
            raise SetupError("Greenfield frontend workspace must not be redirected. Restore its private directory.")
        ui.mkdir(exist_ok=True)
        for name in ("src", "public"):
            if not (GreenfieldStack.ROOT / "frontend" / name).exists():
                continue
            destination = ui / name
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(GreenfieldStack.ROOT / "frontend" / name, destination)
        for path in (GreenfieldStack.ROOT / "frontend").iterdir():
            if (
                path.is_file()
                and (not path.name.startswith(".env"))
                and (path.suffix in (".json", ".js", ".ts", ".mjs", ".cjs"))
            ):
                shutil.copy2(path, ui / path.name)
        modules = ui / "node_modules"
        expected = GreenfieldStack.ROOT / "frontend/node_modules"
        if modules.exists():
            if not os.path.samefile(modules, expected):
                raise SetupError(
                    "Greenfield node_modules points to a different installation. Restore its project dependency link."
                )
        else:
            try:
                modules.symlink_to(expected, target_is_directory=True)
            except OSError:
                raise SetupError(
                    "Cannot create the private frontend dependency link. On Windows, enable approved Developer Mode/symlink permission, "
                    "then rerun; no permissions or system policies were changed."
                ) from None
        return ui

    @staticmethod
    def node_binary():
        bundled = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
        return bundled if bundled.exists() else Path(shutil.which("node") or "node")

    @staticmethod
    def check_service_ports(ports=(18000, 13000)):
        for port in ports:
            with socket.socket() as sock:
                if sys.platform != "win32":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError as error:
                    if error.errno in (errno.EADDRINUSE, 10048):
                        raise GreenfieldStack.ServicePortError(
                            f"Greenfield application port {port} on 127.0.0.1 is already in use. Inspect with: lsof -nP -iTCP:{port} -sTCP:LISTEN. Stop a separately launched instance using its own launcher. No process was stopped."
                        ) from None
                    raise GreenfieldStack.ServicePortError(
                        f"Cannot bind Greenfield application port {port} on 127.0.0.1 (OS error {error.errno}). No service was started."
                    ) from None

    @staticmethod
    def initialize_private_state():
        files = ("environment.json", "runtime-password", "setup-password")
        present = [name for name in files if (GreenfieldStack.STATE / name).exists()]
        if present:
            if len(present) != len(files):
                raise SetupError(
                    "Partial Greenfield private configuration; restore the existing files. No credentials were replaced."
                )
            for name in files:
                GreenfieldStack.read_private(name)
            return
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        values = {
            "NATIVE_JWT_PRIVATE_KEY": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode(),
            "NATIVE_JWT_PUBLIC_KEY": key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode(),
            **{
                name: base64.b64encode(os.urandom(32)).decode()
                for name in ("AUTH_SESSION_ENCRYPTION_KEY", "AI_CONFIG_ENCRYPTION_KEY", "NATIVE_SECURITY_OUTBOX_KEY")
            },
        }
        GreenfieldStack.private_file("setup-password", secrets.token_urlsafe(36))
        GreenfieldStack.private_file("runtime-password", secrets.token_urlsafe(36))
        GreenfieldStack.private_file("environment.json", json.dumps(values))

    @staticmethod
    def provision():
        projects = subprocess.check_output(
            GreenfieldStack.docker_command() + ["ps", "-a", "--format", '{{.Label "com.docker.compose.project"}}'],
            text=True,
        ).splitlines()
        existing = "sbom-greenfield-uuid-dev" in projects
        if existing:
            GreenfieldStack.verify_resources()
        else:
            for port in (56044, 56381, 1026, 8026):
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", port))
            for kind, name in [
                ("volume", "sbom-greenfield-uuid-dev_pgdata"),
                ("volume", "sbom-greenfield-uuid-dev_redisdata"),
                ("network", "sbom-greenfield-uuid-dev_access"),
            ]:
                if (
                    subprocess.run(
                        GreenfieldStack.docker_command() + [kind, "inspect", name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    ).returncode
                    == 0
                ):
                    raise RuntimeError("Unowned greenfield resource collision")
        GreenfieldStack.initialize_private_state()
        env = GreenfieldStack.settings()
        subprocess.run(
            GreenfieldStack.docker_command()
            + [
                "compose",
                "-f",
                str(GreenfieldStack.ROOT / "infra/greenfield-uuid/compose.yml"),
                "up",
                "-d",
                "--pull",
                "never",
                "--no-build",
                "--no-recreate",
            ],
            env=env,
            check=True,
        )
        for _ in range(30):
            result = subprocess.check_output(
                GreenfieldStack.docker_command()
                + ["inspect", "sbom-greenfield-uuid-dev-postgres-1", "--format", "{{.State.Health.Status}}"],
                env=env,
                text=True,
            )
            if result.strip() == "healthy":
                if not existing:
                    names = [
                        "sbom-greenfield-uuid-dev-" + service + "-1" for service in ("postgres", "redis", "mailpit")
                    ]
                    observations = json.loads(
                        subprocess.check_output(GreenfieldStack.docker_command() + ["inspect", *names], text=True)
                    )
                    GreenfieldStack.private_file(
                        "docker-identities.json",
                        json.dumps({x["Name"].lstrip("/"): x["Id"] for x in observations}, indent=2),
                    )
                return
            time.sleep(2)
        raise RuntimeError("Greenfield PostgreSQL did not become healthy")

    @staticmethod
    def bootstrap(database=DB):
        if database not in {GreenfieldStack.DB, GreenfieldStack.DB + "_repro_test"}:
            raise RuntimeError("Only this task's greenfield databases are permitted")
        GreenfieldStack.verify_resources()
        env = GreenfieldStack.settings()
        os.environ.clear()
        os.environ.update(env)
        os.chdir(GreenfieldStack.STATE)
        from app.greenfield_schema import application_metadata
        from app.iam_schema import apply_user_uuid_revision
        from app.resource_schema import apply_resource_uuid_revision, revision100_metadata

        metadata = revision100_metadata(application_metadata())
        from app.public_identity import TABLES, install_guards
        from sqlalchemy import create_engine, inspect, text
        from sqlalchemy.pool import NullPool

        engine = create_engine(
            GreenfieldStack.url("greenfield_setup", "setup-password", database),
            hide_parameters=True,
            poolclass=NullPool,
        )
        try:
            with engine.begin() as connection:
                if inspect(connection).has_table("alembic_version"):
                    marker = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                    if marker != GreenfieldStack.current_revision():
                        raise RuntimeError("Unexpected existing greenfield revision")
                    print("Existing marker observed; structural verification follows without schema repair")
                else:
                    if inspect(connection).get_table_names():
                        raise RuntimeError("Refusing partially initialized database")
                    password = GreenfieldStack.read_private("runtime-password")
                    from psycopg import sql

                    raw = connection.connection.driver_connection
                    with raw.cursor() as cur:
                        for role, login in (("greenfield_owner", False), ("greenfield_app", True)):
                            cur.execute(
                                "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",
                                (role,),
                            )
                            existing = cur.fetchone()
                            if existing is not None:
                                if tuple(existing) != (login, False, False, False, False, False):
                                    raise RuntimeError("Unexpected task-owned role privileges")
                                continue
                            query = sql.SQL(
                                "CREATE ROLE {} {} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                            ).format(sql.Identifier(role), sql.SQL("LOGIN" if login else "NOLOGIN"))
                            if login:
                                query += sql.SQL(" PASSWORD {}").format(sql.Literal(password))
                            cur.execute(query)
                    connection.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
                    connection.exec_driver_sql("ALTER SCHEMA public OWNER TO greenfield_owner")
                    connection.exec_driver_sql("SET LOCAL ROLE greenfield_owner")
                    metadata.create_all(connection)
                    install_guards(connection)
                    actual = inspect(connection)
                    if set(actual.get_table_names()) != set(metadata.tables):
                        raise RuntimeError("Metadata/table parity failed")
                    for table in metadata.tables.values():
                        if set(c["name"] for c in actual.get_columns(table.name)) != set(table.columns.keys()):
                            raise RuntimeError(f"Column parity failed: {table.name}")
                    for name in TABLES:
                        col = next(c for c in actual.get_columns(name) if c["name"] == "public_id")
                        if col["nullable"] or str(col["type"]) != "UUID" or "gen_random_uuid" not in col["default"]:
                            raise RuntimeError("Final UUID definition mismatch")
                    from sqlalchemy.orm import Session

                    from scripts.greenfield_references import seed_catalog

                    with Session(bind=connection) as seed_session:
                        seed_catalog(seed_session)
                    connection.exec_driver_sql(
                        "CREATE TABLE public.alembic_version(version_num varchar(128) PRIMARY KEY)"
                    )
                    connection.execute(
                        text("INSERT INTO public.alembic_version(version_num) VALUES(:revision)"),
                        {"revision": "100_greenfield_uuid_final"},
                    )
                    apply_user_uuid_revision(connection)
                    apply_resource_uuid_revision(connection)
                    from scripts.greenfield_auto_migrations import apply_fresh_tail

                    apply_fresh_tail(connection)
                    connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO greenfield_app")
                    connection.exec_driver_sql(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO greenfield_app"
                    )
                    connection.exec_driver_sql("REVOKE ALL ON public.alembic_version FROM greenfield_app")
                    connection.exec_driver_sql("GRANT SELECT ON public.alembic_version TO greenfield_app")
                    connection.exec_driver_sql(
                        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO greenfield_app"
                    )
                    connection.exec_driver_sql(
                        "REVOKE ALL ON FUNCTION public.uuid_public_identity_guard_v1() FROM PUBLIC"
                    )
                    connection.exec_driver_sql(
                        "GRANT EXECUTE ON FUNCTION public.uuid_public_identity_guard_v1() TO greenfield_app"
                    )
            with engine.connect() as reader:
                reader.exec_driver_sql("SET TRANSACTION READ ONLY")
                from scripts.greenfield_auto_migrations import validate_current_tail

                validate_current_tail(reader)
                print(
                    "Committed revision:",
                    reader.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one(),
                )
                print("Application tables:", len(metadata.tables))
                reader.rollback()
        finally:
            engine.dispose()
        from scripts.greenfield_schema_check import verify

        verify(database)


class GreenfieldProfile:
    """Existing UUID profile lifecycle. Schema/provisioning remains explicitly guarded."""

    @staticmethod
    def inventory():
        try:
            GreenfieldStack.verify_resources()
        except SetupError:
            raise
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            detail = str(error) if type(error) is RuntimeError else type(error).__name__
            raise SetupError(
                "Greenfield resource identity validation failed: "
                + detail
                + ". Check Docker and the private installation; no container was changed."
            ) from None
        identities = json.loads(GreenfieldStack.read_private("docker-identities.json"))
        result = subprocess.run(
            GreenfieldStack.docker_command() + ["inspect", *identities.values()],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode:
            raise SetupError("Greenfield Docker inventory failed. Start its Docker engine/context and retry doctor.")
        return json.loads(result.stdout)

    @staticmethod
    def commands(node, cert, key, ui, env):
        return {
            **{name: (command, GreenfieldStack.STATE) for name, command in background_commands(env).items()},
            "API": (
                api_command(env, 18000),
                GreenfieldStack.STATE,
            ),
            "Frontend": (
                [
                    str(node),
                    str(ROOT / "frontend/node_modules/next/dist/bin/next"),
                    "dev",
                    "--webpack",
                    "--hostname",
                    "127.0.0.1",
                    "--port",
                    "13000",
                    "--experimental-https",
                    "--experimental-https-key",
                    str(key),
                    "--experimental-https-cert",
                    str(cert),
                ],
                ui,
            ),
        }

    @staticmethod
    def start_services(runtime):
        GreenfieldStack.check_service_ports()
        cert, key, _, _ = LocalHttps.ensure_certificate(GreenfieldStack.STATE, prepare=True)
        GreenfieldStack.verify_resources()
        env = runtime_environment(GreenfieldStack.settings())
        node = GreenfieldStack.node_binary()
        env["PATH"] = str(node.parent) + os.pathsep + os.environ.get("PATH", "")
        ui = GreenfieldStack.frontend_workspace("frontend")
        frontend = GreenfieldProfile.commands(node, cert, key, ui, env)["Frontend"][0]
        return launch_services(
            env,
            18000,
            13000,
            frontend,
            cwd=GreenfieldStack.STATE,
            frontend_cwd=ui,
            tls_context=LocalHttps.client_context(GreenfieldStack.STATE),
        )

    @staticmethod
    def start(args, runtime):
        from scripts import greenfield_migrations as migrations

        validate_greenfield_installation()
        LocalHttps.ensure_certificate(GreenfieldStack.STATE, prepare=not args.check)
        observed = GreenfieldProfile.inventory()
        if args.check:
            say(
                "OK",
                "Greenfield",
                "private installation, container identity and HTTPS trust verified; no services started",
            )
            return
        if runtime is None:
            raise SetupError("Greenfield startup requires the unified launcher's ownership registry.")
        runtime.check_stop()
        stopped = [item["Id"] for item in observed if not item["State"]["Running"]]
        if stopped:
            result = subprocess.run(
                GreenfieldStack.docker_command() + ["start", *stopped], capture_output=True, timeout=60
            )
            if result.returncode:
                raise SetupError(
                    "Could not resume verified Greenfield containers. Check Docker engine and container logs."
                )
        deadline = time.monotonic() + 60
        while True:
            runtime.check_stop()
            observed = GreenfieldProfile.inventory()
            healthy = all(item["State"]["Running"] for item in observed) and all(
                item["State"].get("Health", {}).get("Status") == "healthy"
                for item in observed
                if item["Name"].endswith("-postgres-1")
            )
            if healthy:
                break
            if time.monotonic() >= deadline:
                raise SetupError(
                    "Greenfield data services are not healthy. Inspect their Docker logs; resources were retained."
                )
            time.sleep(0.5)
        migrations.ensure_current(confirm=lambda: "")
        processes, env = GreenfieldProfile.start_services(runtime)
        print("Press Ctrl+C to stop application processes; data services remain running.", flush=True)
        supervise_runtime(runtime, env, processes)


def say(kind: str, name: str, value: str) -> None:
    print(f"[{kind}] {name:<18} {value}", flush=True)


def run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    if ACTIVE_RUNTIME:
        ACTIVE_RUNTIME.check_stop()
    execution_env = dict(os.environ if env is None else env)
    execution_env["PATH"] = str(GreenfieldStack.node_binary().parent) + os.pathsep + execution_env.get("PATH", "")
    result = subprocess.run(
        normalize_command(command),
        cwd=cwd,
        env=execution_env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if ACTIVE_RUNTIME:
        ACTIVE_RUNTIME.check_stop()
    if VERBOSE:
        print(redact(result.stdout, env), end="", flush=True)
        print(redact(result.stderr, env), end="", file=sys.stderr, flush=True)
    return result


def redact(output: str | None, env: dict[str, str] | None) -> str:
    text = output or ""
    for key, value in (env or os.environ).items():
        if (
            value
            and len(value) >= 4
            and any(word in key.upper() for word in ("PASSWORD", "SECRET", "KEY", "TOKEN", "DATABASE_URL"))
        ):
            text = text.replace(value, "[REDACTED]")
        if key.upper().endswith("_URL") and value:
            try:
                password = urlsplit(value).password
            except ValueError:
                password = None
            if password and len(password) >= 4:
                text = text.replace(password, "[REDACTED]")
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
        "[REDACTED PRIVATE KEY]",
        text,
        flags=re.S,
    )
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9_.~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)([a-z][a-z0-9+.-]*://[^\s/:]+:)[^\s@]+@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"""(?i)((?:["']?(?:password|api[_-]?key(?:_encrypted)?|access[_-]?token|refresh[_-]?token|client[_-]?secret)["']?)\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;}]+)""",
        r"\1[REDACTED]",
        text,
    )
    return text


def normalize_command(command: list[str]) -> list[str]:
    """Use npm's JavaScript CLI on Windows, never a shell/batch interpreter."""
    if sys.platform == "win32" and Path(command[0]).suffix.lower() in {".cmd", ".bat"}:
        executable = Path(command[0])
        if executable.stem.lower() != "npm":
            raise SetupError("A native executable is required; the unified launcher does not execute batch wrappers.")
        cli = executable.parent / "node_modules/npm/bin/npm-cli.js"
        if not cli.is_file():
            raise SetupError(
                "Cannot locate npm-cli.js beside npm.cmd. Repair the Node.js LTS installation including npm."
            )
        return [str(GreenfieldStack.node_binary()), str(cli), *command[1:]]
    return command


def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def service_available(service: str, port: int) -> bool:
    """A listening port must actually answer as the expected service."""
    if service == "mailpit":
        return reachable("127.0.0.1", port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
            connection.settimeout(1)
            if service == "postgres":
                connection.sendall(struct.pack("!II", 8, 80877103))
                return connection.recv(1) in (b"S", b"N")
            if service == "redis":
                connection.sendall(b"*1\r\n$4\r\nPING\r\n")
                reply = b""
                while not reply.endswith(b"\r\n") and len(reply) < 64:
                    chunk = connection.recv(64)
                    if not chunk:
                        break
                    reply += chunk
                return reply == b"+PONG\r\n"
    except OSError:
        return False
    return False


def mailpit_ready() -> bool:
    try:
        with urlopen(f"http://127.0.0.1:{MAILPIT_UI_PORT}/api/v1/info", timeout=2) as response:
            return response.status == 200 and "Version" in json.load(response)
    except (OSError, ValueError):
        return False


def wait_for_mailpit_ready(
    timeout: float = MAILPIT_READY_TIMEOUT,
    poll_interval: float = 0.5,
) -> bool:
    """Wait until both Mailpit's SMTP listener and HTTP API are ready."""
    deadline = time.monotonic() + timeout
    while True:
        if reachable("127.0.0.1", MAILPIT_SMTP_PORT) and mailpit_ready():
            return True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(poll_interval, remaining))


def ensure_mailpit_ready(timeout: float = MAILPIT_READY_TIMEOUT) -> None:
    """Wait for a selected Mailpit service or raise a concise setup error."""
    if reachable("127.0.0.1", MAILPIT_SMTP_PORT) and mailpit_ready():
        return

    say("...", "Mailpit", "waiting for HTTP API...")
    if wait_for_mailpit_ready(timeout):
        return

    if reachable("127.0.0.1", MAILPIT_SMTP_PORT):
        detail = "Mailpit SMTP is reachable, but its HTTP API did not become ready"
    else:
        detail = f"Mailpit did not become reachable on SMTP port {MAILPIT_SMTP_PORT} or ready through its HTTP API"
    raise SetupError(
        f"{detail} on http://127.0.0.1:{MAILPIT_UI_PORT} within {timeout:g} seconds. Check the Mailpit container logs."
    )


def docker_available() -> bool:
    return bool(shutil.which("docker") and run(["docker", "info"]).returncode == 0)


def compose_container(service: str) -> bool:
    result = run(["docker", "compose", "ps", "-q", service])
    if result.returncode != 0 or not result.stdout.strip():
        return False
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", result.stdout.strip()])
    if state.returncode != 0 or state.stdout.strip() != "true":
        return False
    internal, expected = {
        "postgres": (5432, POSTGRES_PORT),
        "redis": (6379, REDIS_PORT),
        "mailpit": (1025, MAILPIT_SMTP_PORT),
    }[service]
    mapped = run(["docker", "compose", "port", service, str(internal)])
    if mapped.returncode or not mapped.stdout.strip().endswith(f":{expected}"):
        raise SetupError(
            f"Project {service} is running without expected host port {expected}. Check its mapping or a port conflict; no container was changed."
        )
    return True


def legacy_redis_container() -> bool:
    """Recognize the older SBOM Native Redis container by exact name and port."""
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", "sbom-native-redis"])
    if state.returncode or state.stdout.strip() != "true":
        return False
    mapped = run(["docker", "port", "sbom-native-redis", "6379"])
    return (
        mapped.returncode == 0
        and mapped.stdout.strip() == f"127.0.0.1:{REDIS_PORT}"
        and service_available("redis", REDIS_PORT)
    )


def start_compose(service: str, env: dict[str, str]) -> None:
    result = run(["docker", "compose", "up", "-d", service], env=env)
    if result.returncode and not compose_container(service):
        # Docker Desktop can report a transient container-start failure.
        time.sleep(1)
        result = run(["docker", "compose", "up", "-d", service], env=env)
    if result.returncode and not compose_container(service):
        error = SetupError(f"Could not start project {service} service. Check Docker Compose and its fixed port.")
        error.failed_result = result
        raise error


def wait_for_service(service: str, port: int) -> bool:
    for _ in range(20):
        if service_available(service, port):
            return True
        time.sleep(0.5)
    return False


def select_service(
    service: str, docker_port: int, local_port: int, *, check: bool, env: dict[str, str], preferred: str | None = None
) -> tuple[str, int]:
    """Pin saved infrastructure; never switch an existing installation's database."""
    if preferred not in (None, "docker", "local"):
        raise SetupError(f"Saved {service} provider must be docker or local.")
    docker = docker_available()
    order = (preferred,) if preferred else ("docker", "local")
    for provider in order:
        if provider == "local":
            if service_available(service, local_port):
                return "local", local_port
            continue
        if not docker:
            continue
        if service == "redis" and legacy_redis_container():
            return "Docker (sbom-native-redis)", docker_port
        if compose_container(service):
            if wait_for_service(service, docker_port):
                return "Docker", docker_port
            raise SetupError(
                f"Project {service} is running but port {docker_port} is unreachable. Check its port mapping."
            )
        if reachable("127.0.0.1", docker_port):
            if not preferred and service_available(service, local_port) and local_port != docker_port:
                continue
            raise SetupError(
                f"Port {docker_port} is occupied, so project {service} cannot start. Stop the owner of that port or use a local {service} service. No process was changed."
            )
        if check:
            return "Docker (available to start)", docker_port
        try:
            start_compose(service, env)
        except SetupError as error:
            if not preferred and service_available(service, local_port) and local_port != docker_port:
                continue
            if getattr(error, "failed_result", None) is not None:
                explain_failed_command(error.failed_result, env)
            raise
        if wait_for_service(service, docker_port):
            return "Docker", docker_port
        raise SetupError(f"Project {service} started but port {docker_port} is unreachable. Check Docker port mapping.")
    raise SetupError(
        f"{service.title()} is unavailable"
        + (f" on its saved {preferred} provider; no provider fallback occurred" if preferred else "")
        + ". Start the configured service or Docker engine, then rerun python scripts/dev.py doctor."
    )


def select_mailpit(*, check: bool, env: dict[str, str]) -> str:
    """Select a compatible Mailpit service and wait for full startup when needed."""
    old_mailpit = (
        docker_available()
        and run(["docker", "inspect", "-f", "{{.State.Running}}", "sbom-mailpit"]).stdout.strip() == "true"
    )
    if old_mailpit and reachable("127.0.0.1", MAILPIT_SMTP_PORT):
        if not check:
            ensure_mailpit_ready()
            return "Docker (sbom-mailpit)"
        if mailpit_ready():
            return "Docker (sbom-mailpit)"

    mailpit, _ = select_service(
        "mailpit",
        MAILPIT_SMTP_PORT,
        MAILPIT_SMTP_PORT,
        check=check,
        env=env,
    )
    if not check:
        ensure_mailpit_ready()
    return mailpit


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_virtualenv() -> None:
    if not venv_python().exists():
        result = run([sys.executable, "-m", "venv", str(VENV)])
        if result.returncode:
            explain_failed_command(result)
            raise SetupError("Could not create .venv. Install Python 3.11+ with venv support.")
    if Path(sys.prefix).resolve() != VENV.resolve():
        command = [str(venv_python()), str(Path(__file__).resolve()), *sys.argv[1:]]
        if sys.platform == "win32":
            # Windows execv can release the shell while the new Python still
            # reads its console. Keep this parent alive, with inherited stdio
            # and the same console group so Ctrl+C reaches the child directly.
            # A Python handler (not SIG_IGN) avoids inheriting ignored Ctrl+C.
            previous_handler = signal.signal(signal.SIGINT, lambda signum, frame: None)
            try:
                child = subprocess.Popen(command)
                raise SystemExit(child.wait())
            finally:
                signal.signal(signal.SIGINT, previous_handler)
        os.execv(command[0], command)


def ensure_dependencies() -> None:
    """Install only when the requirements file changes or core imports are missing."""
    import hashlib

    stamp = VENV / ".sbom-requirements-sha256"
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()
    try:
        import alembic  # noqa: F401
        import celery  # noqa: F401
        import cryptography  # noqa: F401
        import psycopg  # noqa: F401
        import uvicorn  # noqa: F401

        installed = stamp.exists() and stamp.read_text().strip() == digest
    except ImportError:
        installed = False
    if installed:
        return
    say("...", "Dependencies", "installing requirements.txt")
    stamp.unlink(missing_ok=True)
    result = run([str(venv_python()), "-m", "pip", "install", "-r", "requirements.txt"])
    if result.returncode:
        explain_failed_command(result)
        raise SetupError(
            "Python dependency installation failed. Check the pip diagnostic above and network/index access, then retry."
        )
    stamp.write_text(digest)


def read_config(path: Path = CONFIG) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if not separator or not key.isidentifier():
            raise SetupError(".env.dev.local is malformed. Fix its KEY=VALUE lines.")
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SetupError(f".env.dev.local has an invalid value for {key}.") from exc
            if not isinstance(value, str):
                raise SetupError(f".env.dev.local value {key} must be a string.")
        else:
            value = raw
        values[key] = value
    return values


def write_config(values: dict[str, str], path: Path = CONFIG) -> None:
    # Replace atomically so interrupted setup cannot leave half a keypair.
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("# Local Native IAM development only. Never commit this file.\n")
            for key, value in sorted(values.items()):
                stream.write(f"{key}={json.dumps(value)}\n")
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def generate_keys(values: dict[str, str]) -> None:
    has_private = "NATIVE_JWT_PRIVATE_KEY" in values
    has_public = "NATIVE_JWT_PUBLIC_KEY" in values
    if has_private != has_public:
        raise SetupError("Local JWT keypair is incomplete. Restore both keys in .env.dev.local before continuing.")
    if not has_private:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        values["NATIVE_JWT_PRIVATE_KEY"] = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        values["NATIVE_JWT_PUBLIC_KEY"] = (
            private.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
    for key in ("NATIVE_SECURITY_OUTBOX_KEY", "AUTH_SESSION_ENCRYPTION_KEY"):
        values.setdefault(key, base64.b64encode(secrets.token_bytes(32)).decode())
    validate_secrets(values)


def validate_secrets(values: dict[str, str]) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        private = serialization.load_pem_private_key(values["NATIVE_JWT_PRIVATE_KEY"].encode(), password=None)
        public = serialization.load_pem_public_key(values["NATIVE_JWT_PUBLIC_KEY"].encode())
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size < 2048:
            raise ValueError()
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
            raise ValueError()
        if private.public_key().public_numbers() != public.public_numbers():
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise SetupError(
            "Local Native JWT keypair is invalid or does not match. Restore .env.dev.local from a safe copy."
        ) from None
    for name in ("NATIVE_SECURITY_OUTBOX_KEY", "AUTH_SESSION_ENCRYPTION_KEY"):
        try:
            encoded = values[name]
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode() != encoded:
                raise ValueError()
        except (KeyError, ValueError, TypeError, binascii.Error):
            raise SetupError(f"{name} must be a valid 32-byte base64 key in .env.dev.local.") from None


def validate_database_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise SetupError(
            f"DATABASE_URL must target local PostgreSQL database {DB_NAME}; refusing another database."
        ) from None
    if (
        parsed.scheme != "postgresql+psycopg"
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or parsed.path != "/" + DB_NAME
        or not port
        or parsed.query
        or parsed.fragment
    ):
        raise SetupError(f"DATABASE_URL must target local PostgreSQL database {DB_NAME}; refusing another database.")


def provider_name(label: str) -> str:
    return "docker" if label.startswith("Docker") else "local"


def default_database_url(provider: str, port: int) -> str:
    user = "sbom" if provider == "docker" else "postgres"
    password = "sbom" if provider == "docker" else ""
    return f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}@127.0.0.1:{port}/{DB_NAME}"


def local_database_url(user: str, password: str, port: int) -> str:
    return f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}@127.0.0.1:{port}/{DB_NAME}"


def repository_database_candidate(path: Path, port: int) -> str | None:
    """Reuse only credentials from a repository URL for this local server."""
    if not path.exists():
        return None
    from dotenv import dotenv_values

    raw = dotenv_values(path).get("DATABASE_URL")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = urlsplit(raw)
        source_port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"postgresql", "postgresql+psycopg"}
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or source_port != port
        or parsed.username is None
        or parsed.query
        or parsed.fragment
    ):
        return None
    return local_database_url(unquote(parsed.username), unquote(parsed.password or ""), port)


def default_pgpass_path(
    *,
    platform_name: str | None = None,
    environment: dict[str, str] | None = None,
    home: Path | None = None,
) -> Path | None:
    platform_name = platform_name or os.name
    environment = environment if environment is not None else os.environ
    if platform_name == "nt":
        appdata = environment.get("APPDATA")
        return Path(appdata) / "postgresql" / "pgpass.conf" if appdata else None
    return (home or Path.home()) / ".pgpass"


def split_pgpass_line(line: str) -> list[str]:
    fields = [""]
    escaped = False
    for character in line:
        if escaped:
            fields[-1] += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("")
        else:
            fields[-1] += character
    if escaped:
        fields[-1] += "\\"
    return fields


def pgpass_database_candidates(path: Path | None, port: int) -> list[str]:
    if path is None or not path.is_file():
        return []
    candidates = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw_line in lines:
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = split_pgpass_line(raw_line)
        if len(fields) != 5:
            continue
        host, saved_port, database, user, password = fields
        if (
            host not in {"localhost", "127.0.0.1", "*"}
            or saved_port not in {str(port), "*"}
            or database not in {DB_NAME, "*"}
            or not user
            or user == "*"
        ):
            continue
        candidates.append(local_database_url(user, password, port))
    return candidates


def read_password(prompt: str) -> str:
    if sys.platform != "win32":
        return getpass.getpass(prompt)

    import msvcrt

    print(prompt, end="", flush=True)
    characters: list[str] = []
    try:
        while True:
            character = msvcrt.getwch()
            if character in {"\x00", "\xe0"}:
                msvcrt.getwch()  # Discard the scan code following a special key.
            elif character in {"\r", "\n"}:
                return "".join(characters)
            elif character == "\x03":
                raise KeyboardInterrupt
            elif character in {"\x1a", ""}:
                raise EOFError
            elif character == "\b":
                if characters:
                    characters.pop()
                    print("\b \b", end="", flush=True)
            elif character.isprintable():
                characters.append(character)
                print("*", end="", flush=True)
    finally:
        print()


def read_postgres_credentials(
    default_user: str = "postgres",
    *,
    input_fn=input,
    password_fn=None,
) -> tuple[str, str]:
    try:
        user = input_fn(f"PostgreSQL user [{default_user}]: ").strip() or default_user
        password = (password_fn or read_password)("PostgreSQL password: ")
        return user, password
    except (KeyboardInterrupt, EOFError):
        raise SetupError("PostgreSQL credential entry cancelled. Rerun the launcher to try again.") from None


def resolve_local_database_url(
    saved_url: str | None,
    port: int,
    *,
    repository_env: Path,
    pgpass_path: Path | None,
    interactive: bool,
    input_fn=input,
    password_fn=None,
) -> str:
    candidates = []
    if saved_url:
        validate_database_url(saved_url)
        candidates.append(saved_url)
    else:
        repository_url = repository_database_candidate(repository_env, port)
        if repository_url:
            candidates.append(repository_url)
        candidates.extend(pgpass_database_candidates(pgpass_path, port))
        candidates.append(default_database_url("local", port))

    for candidate in dict.fromkeys(candidates):
        try:
            ensure_database(candidate)
            return candidate
        except SetupError:
            pass

    if not interactive:
        raise SetupError(
            f"PostgreSQL credentials are required for {DB_NAME}. Run python scripts/dev.py in an interactive terminal."
        )

    print(f"[INFO] Local PostgreSQL detected at 127.0.0.1:{port}")
    print(f"[INFO] PostgreSQL credentials are required for {DB_NAME}.")
    for attempt in range(3):
        user, password = read_postgres_credentials(input_fn=input_fn, password_fn=password_fn)
        candidate = local_database_url(user, password, port)
        try:
            ensure_database(candidate)
            return candidate
        except SetupError:
            if attempt < 2:
                print(
                    "[ERROR] PostgreSQL credentials were not accepted or cannot create the development database. Try again."
                )
    raise SetupError("PostgreSQL credentials were not accepted after 3 attempts. Check the local login and rerun.")


def configure_local_database(
    values: dict[str, str],
    saved: dict[str, str],
    port: int,
    *,
    config_path: Path = CONFIG,
    repository_env: Path | None = None,
    pgpass_path: Path | None = None,
    interactive: bool,
    input_fn=input,
    password_fn=None,
) -> None:
    saved_url = saved.get("DATABASE_URL") if saved.get("DATABASE_URL") == values.get("DATABASE_URL") else None
    values["DATABASE_URL"] = resolve_local_database_url(
        saved_url,
        port,
        repository_env=repository_env or ROOT / ".env",
        pgpass_path=pgpass_path if pgpass_path is not None else default_pgpass_path(),
        interactive=interactive,
        input_fn=input_fn,
        password_fn=password_fn,
    )
    if values != saved:
        write_config(values, config_path)


def resolve_config(
    saved: dict[str, str],
    pg_port: int,
    redis_port: int,
    smtp_port: int,
    pg_provider: str | None = None,
    redis_provider: str | None = None,
) -> dict[str, str]:
    values = dict(saved)
    pg_provider = pg_provider or ("docker" if pg_port == POSTGRES_PORT else "local")
    redis_provider = redis_provider or ("docker" if redis_port == REDIS_PORT else "local")
    previous_provider = saved.get("DEV_POSTGRES_PROVIDER")
    if "DATABASE_URL" in values:
        validate_database_url(values["DATABASE_URL"])
    if "DATABASE_URL" not in values or (previous_provider and previous_provider != pg_provider):
        values["DATABASE_URL"] = default_database_url(pg_provider, pg_port)
    elif urlsplit(values["DATABASE_URL"]).port != pg_port:
        raise SetupError(
            "Saved DATABASE_URL points to a different local PostgreSQL port. Check .env.dev.local before continuing."
        )
    values["DEV_POSTGRES_PROVIDER"] = pg_provider
    values["DEV_REDIS_PROVIDER"] = redis_provider
    # Local mode is explicit so a checked-in .env cannot turn on HCL or a remote mailer.
    fixed = {
        "DEV_API_PORT": str(DEV_API_PORT),
        "DEV_FRONTEND_PORT": str(DEV_FRONTEND_PORT),
        "AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "ENTRA_ENABLED": "false",
        "NATIVE_JWT_VERIFICATION_KEYS_JSON": "{}",
        "NATIVE_AUTH_ENABLED": "true",
        "NATIVE_USER_CREATION_ENABLED": "true",
        "NATIVE_IAM_PRODUCTION": "false",
        "DEV_DEFAULT_TENANT": "false",
        "AUTHORIZATION_CATALOG_MODE": "DATABASE",
        "AUTHORIZATION_CATALOG_FAIL_CLOSED": "true",
        "TENANT_ROLE_ASSIGNMENT_MODE": "DATABASE",
        "TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED": "true",
        "CELERY_USE_DATABASE_BROKER": "false",
        "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
        "NATIVE_AUTH_RATE_LIMIT_ENABLED": "true",
        "AUTH_SESSION_STORE": "redis",
        "APP_ORIGIN": f"https://localhost:{DEV_FRONTEND_PORT}",
        "NATIVE_ACTIVATION_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/activate-account",
        "NATIVE_PASSWORD_RESET_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/reset-password",
        "EMAIL_VERIFICATION_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/verify-email",
        "NATIVE_JWT_ISSUER": f"https://localhost:{DEV_FRONTEND_PORT}/native",
        "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
        "NATIVE_JWT_ACTIVE_KID": "native-dev",
        "NATIVE_JWT_ALGORITHM": "RS256",
        "EMAIL_PROVIDER": "smtp",
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_FROM_ADDRESS": "sbom-dev@localhost.test",
        "EMAIL_FROM_NAME": "SBOM Analyzer",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(smtp_port),
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "false",
        "CORS_ORIGINS": f"https://localhost:{DEV_FRONTEND_PORT}",
        "SBOM_API_URL": f"http://127.0.0.1:{DEV_API_PORT}",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{DEV_API_PORT}",
        "NEXT_PUBLIC_HCL_IAM_ISSUER": "",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "",
        "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        "CELERY_BROKER_URL": f"redis://127.0.0.1:{redis_port}/0",
        "CELERY_RESULT_BACKEND": f"redis://127.0.0.1:{redis_port}/0",
        "AUTH_SESSION_REDIS_URL": f"redis://127.0.0.1:{redis_port}/1",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": f"redis://127.0.0.1:{redis_port}/2",
    }
    values.update(fixed)
    values.setdefault("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "false")
    return values


def ensure_database(url: str) -> None:
    import psycopg

    validate_database_url(url)
    parsed = urlsplit(url)
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=parsed.port,
            user=user,
            password=password,
            dbname="postgres",
            connect_timeout=3,
            autocommit=True,
        ) as connection:
            row = connection.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)).fetchone()
            if not row:
                connection.execute(f'CREATE DATABASE "{DB_NAME}"')
    except psycopg.Error as exc:
        raise SetupError(
            "Cannot access/create the local development database. Check PostgreSQL credentials in .env.dev.local."
        ) from exc


def check_schema_objects(objects: set[str], revision: str | None, known_revisions: set[str]) -> None:
    if not objects:
        return
    if not {"alembic_version", "iam_users", "tenants"}.issubset(objects) or revision not in known_revisions:
        raise SetupError(
            "Existing sbom_analyser_dev has an unknown or incomplete schema. Alembic was not run; inspect this database before continuing."
        )


def validate_existing_schema(url: str, *, validate_target=True) -> None:
    """Refuse to migrate an unrelated database that happens to have the dev name."""
    import psycopg
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    if validate_target:
        validate_database_url(url)
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    known = {revision.revision for revision in script.walk_revisions()}
    pre_uuid = pre_uuid_revisions(script)
    populated: list[str] = []
    try:
        with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://", 1)) as connection:
            connection.read_only = True
            rows = connection.execute(
                "SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' "
                "AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')"
            ).fetchall()
            objects = {name for _, name in rows}
            public_objects = {name for schema, name in rows if schema == "public"}
            revisions = (
                [row[0] for row in connection.execute("SELECT version_num FROM public.alembic_version")]
                if "alembic_version" in public_objects
                else []
            )
            current = revisions[0] if len(revisions) == 1 else None
            if current in pre_uuid:
                # Table names come from the fixed tuple above, never from input.
                populated = [
                    table
                    for table in PUBLIC_IDENTITY_TABLES
                    if table in public_objects
                    and connection.execute(f'SELECT EXISTS (SELECT 1 FROM public."{table}")').fetchone()[0]
                ]
    except psycopg.Error as exc:
        raise SetupError("Could not inspect the development database schema before Alembic.") from exc
    check_schema_objects(public_objects if objects else set(), current, known)
    if objects and not public_objects:
        raise SetupError("Existing sbom_analyser_dev has an unknown non-empty schema. Alembic was not run.")
    check_pre_uuid_crossing(current, populated)


def run_migrations(env: dict[str, str]) -> str:
    result = run([str(venv_python()), "-m", "alembic", "upgrade", "head"], env=env)
    if result.returncode:
        explain_failed_command(result, env)
        raise SetupError(
            "Alembic upgrade failed for the development database. Fix the error above or rerun with --verbose."
        )
    import psycopg
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    with psycopg.connect(env["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)) as connection:
        current = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    if not current or current[0] != head:
        raise SetupError("Development database did not reach the current Alembic head.")
    return head


def ensure_frontend(*, certificate: bool = True) -> str:
    import hashlib

    cert = ROOT / "frontend/certificates/localhost.pem"
    key = ROOT / "frontend/certificates/localhost-key.pem"
    if certificate and (cert.exists() != key.exists() or cert.is_symlink() or key.is_symlink()):
        raise SetupError(
            "Legacy HTTPS certificate pair is incomplete or redirected. Restore both existing files; no key was replaced."
        )
    problem = node_problem(node_version())
    if problem:
        raise SetupError(problem)

    npm = shutil.which("npm", path=str(GreenfieldStack.node_binary().parent) + os.pathsep + os.environ.get("PATH", ""))
    if not npm:
        raise SetupError("Node.js/npm is missing. Install Node.js, then rerun python scripts/dev.py.")
    frontend = ROOT / "frontend"
    modules = frontend / "node_modules"
    stamp = modules / ".sbom-dependencies-sha256"
    try:
        digest = hashlib.sha256(
            (frontend / "package.json").read_bytes() + b"\0" + (frontend / "package-lock.json").read_bytes()
        ).hexdigest()
    except OSError:
        raise SetupError(
            "Cannot read frontend package.json/package-lock.json. Restore the manifests and rerun."
        ) from None
    try:
        installed = modules.is_dir() and stamp.read_text().strip() == digest
    except OSError:
        installed = False
    if not installed:
        say("...", "Frontend", "installing npm dependencies")
        # An interrupted/failed clean install must never leave a trusted stamp.
        stamp.unlink(missing_ok=True)
        result = run([npm, "ci", "--prefix", "frontend"])
        if result.returncode:
            explain_failed_command(result)
            raise SetupError(
                "Frontend npm ci failed. Check network access and package manifests; rerun with --verbose for details."
            )
        stamp.write_text(digest)
    cert = ROOT / "frontend/certificates/localhost.pem"
    key = ROOT / "frontend/certificates/localhost-key.pem"
    if certificate:
        if cert.exists() != key.exists() or cert.is_symlink() or key.is_symlink():
            raise SetupError(
                "Legacy HTTPS certificate pair is incomplete or redirected. Restore both existing files; no key was replaced."
            )
        if not cert.exists():
            create_local_certificate(cert, key)
            say(
                "NOTE",
                "HTTPS",
                "local self-signed certificate prepared. Explicit browser trust approval is required; no trust store was changed",
            )
    return npm


def create_local_certificate(cert: Path, key: Path) -> None:
    """Create the same localhost certificate files consumed by dev:https."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .sign(private, hashes.SHA256())
    )
    cert.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(
            private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def acquire_beat_lock() -> None:
    try:
        fd = os.open(BEAT_LOCK, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Inspect without signalling: on Windows os.kill(pid, 0) sends CTRL_C_EVENT
        # rather than probing, so liveness comes from the read-only process lookup.
        try:
            alive = process_info(int(BEAT_LOCK.read_text(encoding="ascii"))) is not None
        except ValueError:
            alive = False
        except OwnershipError:
            alive = True  # An uninspectable process is not proof the lock is stale.
        if not alive:
            BEAT_LOCK.unlink(missing_ok=True)
            return acquire_beat_lock()
        raise SetupError(
            f"A dev launcher already owns Celery Beat. Run {launcher_command()} status, and stop it before starting another."
        )
    with os.fdopen(fd, "w") as stream:
        stream.write(str(os.getpid()))


def log_path(name: str) -> Path:
    if ACTIVE_PROFILE == "greenfield":
        return profile_log_paths("greenfield")[name]
    return ROOT / ".dev-logs" / (name.lower().replace(" ", "-") + ".log")


def show_log(name: str, env: dict[str, str]) -> None:
    path = log_path(name)
    if VERBOSE and path.exists():
        print(redact(path.read_text(errors="replace"), env), file=sys.stderr)


def http_ready(url: str, *, json_ready: bool = False) -> bool:
    try:
        context = legacy_https_context() if url.startswith("https://localhost:") else None
        with urlopen(url, timeout=1, context=context) as response:
            if not 200 <= response.status < 400:
                return False
            return not json_ready or json.load(response).get("ready") is True
    except (OSError, ValueError, SetupError):
        return False


def legacy_https_context():
    """Pin the preserved local cert and verify localhost; never bypass TLS checks."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert_path = ROOT / "frontend/certificates/localhost.pem"
    key_path = ROOT / "frontend/certificates/localhost-key.pem"
    if cert_path.is_symlink() or key_path.is_symlink():
        raise SetupError("Legacy HTTPS material must be regular, nonredirected files.")
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        form = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = datetime.now(UTC)
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
        if (
            "localhost" not in sans
            or cert.not_valid_before_utc > now
            or cert.not_valid_after_utc <= now
            or cert.public_key().public_bytes(*form) != key.public_key().public_bytes(*form)
        ):
            raise ValueError()
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound):
        raise SetupError(
            "Legacy HTTPS certificate is expired, incomplete or mismatched. Restore a valid localhost certificate/key pair; "
            "existing keys were retained. Browser trust requires explicit approval."
        ) from None
    context = ssl.create_default_context(cafile=str(cert_path))
    # Existing Legacy material can be an mkcert leaf rather than self-signed.
    # Explicitly trust that exact preserved leaf while retaining chain/hostname
    # verification, rather than requiring/replacing its issuing root.
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def port_diagnostic(port: int) -> str:
    """Best-effort Linux socket owner name; never print arbitrary command arguments.

    Other platforms get a read-only command the developer can run to inspect the
    owner themselves; the launcher never stops a process found by port.
    """
    if sys.platform == "win32":
        return f"PID: unavailable; ownership: unrelated/unknown; inspect with: netstat -ano | findstr :{port}"
    if sys.platform == "darwin":
        return f"PID: unavailable; ownership: unrelated/unknown; inspect with: lsof -nP -iTCP:{port} -sTCP:LISTEN"
    if not sys.platform.startswith("linux"):
        return "PID: unavailable; ownership: unrelated/unknown"
    try:
        inodes = set()
        for family in ("tcp", "tcp6"):
            for line in Path(f"/proc/net/{family}").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port:
                    inodes.add(f"socket:[{fields[9]}]")
        for directory in Path("/proc").iterdir():
            if not directory.name.isdigit():
                continue
            try:
                if any(os.readlink(fd) in inodes for fd in (directory / "fd").iterdir()):
                    info = process_info(int(directory.name))
                    name = Path(info["exe"]).name if info else "exited"
                    return f"PID: {directory.name}; process: {name}; ownership: unrelated/unknown"
            except (OSError, OwnershipError):
                continue
    except OSError:
        pass
    return "PID: unavailable; ownership: unrelated/unknown"


def check_application_ports(api_port: int, frontend_port: int) -> None:
    conflicts = []
    runtime = Runtime(ROOT)
    state = runtime.load()
    for name, port in (("API", api_port), ("Frontend", frontend_port)):
        if not any(reachable(host, port) for host in ("127.0.0.1", "::1")):
            continue
        record = (state or {}).get("services", {}).get(name)
        if record and record.get("port") == port and runtime.service_status(record) == "RUNNING":
            conflicts.append(
                f"{name} port {port} belongs to the existing SBOM dev instance. Run python3 scripts/dev.py stop."
            )
        else:
            conflicts.append(f"{name} port {port} is already in use. {port_diagnostic(port)}. Nothing was killed.")
    if conflicts:
        raise SetupError("\n".join(conflicts))


def start_process(name: str, command: list[str], env: dict[str, str], cwd: Path = ROOT) -> subprocess.Popen:
    if ACTIVE_RUNTIME:
        ACTIVE_RUNTIME.check_stop()
    path = log_path(name)
    path.parent.mkdir(exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    process_env = dict(env)
    process_env["PATH"] = str(GreenfieldStack.node_binary().parent) + os.pathsep + process_env.get("PATH", "")
    kwargs = {"cwd": cwd, "env": process_env, "stdout": fd, "stderr": subprocess.STDOUT}
    kwargs.update(platform_spawn_options())
    try:
        process = subprocess.Popen(normalize_command(command), **kwargs)
    finally:
        os.close(fd)
    if ACTIVE_RUNTIME:
        try:
            ACTIVE_RUNTIME.processes[process.pid] = process
            ACTIVE_RUNTIME.register(
                name,
                process.pid,
                {
                    "API": int(env.get("DEV_API_PORT", DEV_API_PORT)),
                    "Frontend": int(env.get("DEV_FRONTEND_PORT", DEV_FRONTEND_PORT)),
                }.get(name),
            )
        except BaseException as error:
            # Always attempt exact-handle cleanup, even if state persistence
            # itself failed. Never guess ownership of unrecorded descendants.
            cleanup = []
            try:
                if name not in ACTIVE_RUNTIME.state["services"]:
                    ACTIVE_RUNTIME.state["services"][name] = {
                        "pid": process.pid, "birth": None, "exe": None, "members": [],
                    }
                    atomic_json(ACTIVE_RUNTIME.path, ACTIVE_RUNTIME.state)
            except OSError as failure:
                cleanup.append(f"runtime persistence failed ({type(failure).__name__})")
            finally:
                try:
                    stop_processes([process])
                except OSError as failure:
                    cleanup.append(f"Popen handle cleanup failed ({type(failure).__name__}, winerror={getattr(failure, 'winerror', None)})")
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                if cleanup:
                    say("WARN", name, "; ".join(cleanup))
                raise
            raise OwnershipError(
                f"{name}: registration failed ({type(error).__name__}); "
                f"{ACTIVE_RUNTIME.diagnostic(name, ACTIVE_RUNTIME.state['services'][name], error)}"
                + ("; " + "; ".join(cleanup) if cleanup else "")
            ) from None
    say("OK", name, f"running (pid {process.pid})")
    return process


def stop_processes(processes: list[subprocess.Popen]) -> None:
    for process in reversed(processes):
        if process.poll() is not None:
            continue
        if os.name == "nt":
            process.terminate()  # Popen uses its original process HANDLE, never a reopened PID/tree.
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def prepare_managed_legacy(*, check=False):
    print("SBOM Analyzer Development Setup\n", flush=True)
    say("OK", "Python", platform.python_version())
    saved = read_config()
    if check and any(
        key in saved
        for key in (
            "NATIVE_JWT_PRIVATE_KEY",
            "NATIVE_JWT_PUBLIC_KEY",
            "NATIVE_SECURITY_OUTBOX_KEY",
            "AUTH_SESSION_ENCRYPTION_KEY",
        )
    ):
        try:
            validate_secrets(saved)
        except ImportError:
            raise SetupError(
                "Cannot validate saved Native IAM keys without Python dependencies. Run python scripts/dev.py first."
            ) from None
    if not check and CONFIG.exists() and os.name != "nt":
        CONFIG.chmod(0o600)
    docker_env = os.environ.copy()
    docker_env.update(
        {
            "POSTGRES_PORT": str(POSTGRES_PORT),
            "REDIS_PORT": str(REDIS_PORT),
            "MAILPIT_SMTP_PORT": str(MAILPIT_SMTP_PORT),
            "MAILPIT_UI_PORT": str(MAILPIT_UI_PORT),
        }
    )
    postgres, pg_port = select_service(
        "postgres",
        POSTGRES_PORT,
        5432,
        check=check,
        env=docker_env,
        preferred=saved.get("DEV_POSTGRES_PROVIDER"),
    )
    redis, redis_port = select_service(
        "redis",
        REDIS_PORT,
        6379,
        check=check,
        env=docker_env,
        preferred=saved.get("DEV_REDIS_PROVIDER"),
    )
    # An older SBOM-specific Mailpit container is accepted, never an arbitrary SMTP server.
    mailpit = select_mailpit(check=check, env=docker_env)
    values = resolve_config(
        saved,
        pg_port,
        redis_port,
        MAILPIT_SMTP_PORT,
        pg_provider=provider_name(postgres),
        redis_provider=provider_name(redis),
    )
    if not check:
        generate_keys(values)
    env = os.environ.copy()
    env.update(values)
    env["PYTHONPATH"] = str(ROOT)
    api_port = int(values["DEV_API_PORT"])
    frontend_port = int(values["DEV_FRONTEND_PORT"])
    db_url = urlsplit(values["DATABASE_URL"])
    say("OK", "PostgreSQL", f"{postgres}, {db_url.hostname}:{db_url.port}")
    say("OK", "Redis", f"{redis}, 127.0.0.1:{redis_port}")
    say("OK", "Database", DB_NAME)
    say("OK", "Mailpit", f"{mailpit}, http://127.0.0.1:{MAILPIT_UI_PORT}")
    if check:
        say("OK", "Check", "no services or processes started")
        return
    check_application_ports(api_port, frontend_port)
    if postgres == "local":
        configure_local_database(values, saved, pg_port, interactive=sys.stdin.isatty())
        env["DATABASE_URL"] = values["DATABASE_URL"]
    else:
        ensure_database(values["DATABASE_URL"])
        if values != saved:
            write_config(values)
    return env


def start_application(args) -> None:
    if getattr(args, "profile", "legacy") == "greenfield":
        if not args.check:
            check_application_ports(DEV_API_PORT, DEV_FRONTEND_PORT)
            ensure_dependencies()
            ensure_frontend(certificate=False)
        GreenfieldProfile.start(args, ACTIVE_RUNTIME)
        return
    if not args.check:
        ensure_dependencies()
    if ACTIVE_LEGACY_CONFIG == "managed":
        env = prepare_managed_legacy(check=args.check)
    else:
        env = existing_legacy_environment(ACTIVE_LEGACY_CONFIG)
    if args.check:
        return
    verify_data_connectivity(env)
    head = verify_existing_schema(env)
    say("OK", "Schema", head)
    api_port, frontend_port = int(env["DEV_API_PORT"]), int(env["DEV_FRONTEND_PORT"])
    npm = ensure_frontend()
    legacy_https_context()
    check_application_ports(api_port, frontend_port)
    processes, env = launch_services(
        env,
        api_port,
        frontend_port,
        [npm, "run", "dev:https", "--", "--port", str(frontend_port)],
        cwd=ROOT,
        frontend_cwd=ROOT / "frontend",
        tls_context=legacy_https_context(),
    )
    supervise_runtime(ACTIVE_RUNTIME, env, processes)


def clean_beat_lock(owner: int | None = None) -> None:
    try:
        pid = int(BEAT_LOCK.read_text())
        if pid == owner or process_info(pid) is None:
            BEAT_LOCK.unlink(missing_ok=True)
    except (FileNotFoundError, ValueError):
        BEAT_LOCK.unlink(missing_ok=True)
    except OwnershipError:
        pass  # A live/uninspectable legacy lock is not evidence of ownership.


def application_status(profile=None):
    global ACTIVE_PROFILE
    profile = profile or ACTIVE_PROFILE
    ACTIVE_PROFILE = profile
    runtime = Runtime(ROOT)
    state = runtime.load() or {}
    names = ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")
    print(f"SBOM Analyzer {profile} runtime")
    running = True
    for name in names:
        record = state.get("services", {}).get(name)
        status = runtime.service_status(record) if record else "STOPPED"
        print(f"{name:<23} {status}")
        if record and status in {"UNKNOWN", "UNOWNED", "PARTIAL"}:
            print(runtime.diagnostic(name, record))
        running &= status == "RUNNING"
    if not running or not state.get("ready"):
        print("Application is not ready. Only verified owned processes can be managed; inspect logs or restart.")
        return False
    try:
        checking = "Celery worker"
        env = profile_environment(profile)
        env["SBOM_DEV_INSTANCE"] = state["instance"]
        verify_data_connectivity(env)
        background_health(runtime, env)
        api_port = int(env.get("DEV_API_PORT", "18000"))
        frontend_port = int(env.get("DEV_FRONTEND_PORT", "13000"))
        context = (
            LocalHttps.client_context(GreenfieldStack.STATE) if profile == "greenfield" else legacy_https_context()
        )
        checking = "API"
        with urlopen(f"http://127.0.0.1:{api_port}/health", timeout=3) as response:
            if json.load(response).get("database", {}).get("available") is not True:
                raise service_failure("API", "database readiness failed")
        if env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true":
            with urlopen(f"http://127.0.0.1:{api_port}/ready/iam", timeout=3) as response:
                if json.load(response).get("ready") is not True:
                    raise service_failure("API", "IAM readiness failed")
        checking = "Frontend"
        frontend_path = "/native-sign-in" if env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true" else "/"
        with urlopen(f"https://localhost:{frontend_port}{frontend_path}", context=context, timeout=3) as response:
            if not 200 <= response.status < 400:
                raise service_failure("Frontend", "HTTPS readiness failed")
    except Exception as error:
        detail = (
            redact(str(error), env if "env" in locals() else {})
            if isinstance(error, (SetupError, OwnershipError))
            else str(service_failure(locals().get("checking", "API"), f"readiness request failed ({type(error).__name__})"))
        )
        print("UNHEALTHY: " + detail)
        return False
    print(
        f"READY: HEALTHY: PostgreSQL, Redis, both queue consumers and scheduler progress verified; https://localhost:{frontend_port}"
    )
    return True


def stop_application(timeout: float = 30) -> None:
    print("SBOM Analyzer Development Shutdown\n", flush=True)
    runtime = Runtime(ROOT)
    requested = None
    if not runtime.acquire():
        state = runtime.load()
        if not state:
            raise SetupError("Launcher is acquiring ownership; retry stop shortly.")
        check_profile_ownership(runtime, ACTIVE_PROFILE)
        # Cooperative cancellation works on Windows too, without terminating a
        # console or guessing which process owns a reused launcher PID.
        requested = state
        atomic_json(runtime.stop_path, {"instance": state["instance"]})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if runtime.acquire():
                break
            time.sleep(0.2)
        else:
            raise SetupError(
                "Stop requested; launcher is still finishing setup/shutdown. Check status and retry stop. Nothing unverified was killed."
            )
    try:
        state = runtime.load()
        check_profile_ownership(runtime, ACTIVE_PROFILE)
        if not runtime.stop_services(say):
            raise SetupError(
                "Some processes could not be safely stopped. Runtime records were retained; inspect status."
            )
        if requested and not state:
            for name, record in reversed(list(requested["services"].items())):
                if runtime.service_status(record) != "STOPPED":
                    raise SetupError(f"{name} shutdown could not be verified; inspect status.")
                say("OK", name, "stopped")
        clean_beat_lock((state or requested or {}).get("launcher_pid"))
        # Even without records an occupied port must be reported, never killed.
        for port in (DEV_API_PORT, DEV_FRONTEND_PORT):
            if any(reachable(host, port) for host in ("127.0.0.1", "::1")):
                say("WARN", f"Port {port}", port_diagnostic(port) + "; it was not stopped.")
        say(
            "OK",
            "SBOM Analyzer",
            "development environment stopped." if state or requested else "development environment is already stopped.",
        )
    finally:
        runtime.release()


def bounded_log_lines(value):
    number = int(value)
    if not 1 <= number <= 100000:
        raise argparse.ArgumentTypeError("--lines must be between 1 and 100000")
    return number


def log_service(value):
    aliases = {
        "all": "all",
        "api": "API",
        "frontend": "Frontend",
        "worker": "Celery worker",
        "reports": "Celery reports worker",
        "beat": "Celery Beat",
        "postgres": "postgres",
        "redis": "redis",
        "mailpit": "mailpit",
    }
    aliases.update(
        {name.lower(): name for name in ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")}
    )
    try:
        return aliases[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            "Choose all, api, frontend, worker, reports, beat, postgres, redis or mailpit"
        ) from None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="One local SBOM Analyzer launcher: Windows, macOS and Linux adapters",
        epilog="Default: start. Ctrl+C stops owned application processes; data services remain running.",
    )
    parser.add_argument(
        "command", nargs="?", default="start", choices=("setup", "start", "stop", "restart", "status", "doctor", "logs")
    )
    parser.add_argument("--check", action="store_true", help="alias for read-only doctor")
    parser.add_argument("--verbose", action="store_true", help="redacted setup diagnostics")
    parser.add_argument(
        "--profile",
        choices=("auto", "greenfield", "legacy"),
        default="auto",
        help="auto chooses an installed Greenfield; no fallback from an incomplete installation",
    )
    parser.add_argument(
        "--legacy-config",
        choices=("auto", "managed", "windows", "env"),
        default="auto",
        help="preserved Legacy configuration family; executable configuration is never run",
    )
    parser.add_argument(
        "--provision-greenfield", action="store_true", help="setup only: create a new isolated Greenfield installation"
    )
    parser.add_argument(
        "--initialize-database", action="store_true", help="setup only: bootstrap a confirmed empty database"
    )
    parser.add_argument(
        "--migrate", action="store_true", help="setup only: explicitly review/perform a database upgrade"
    )
    parser.add_argument("--confirm-database", help="repeat the exact database name for controlled setup")
    parser.add_argument(
        "--frontend-build", action="store_true", help="setup only: build the isolated frontend workspace"
    )
    parser.add_argument("--lines", type=bounded_log_lines, default=80, help="bounded log tail (default 80)")
    parser.add_argument(
        "--service",
        type=log_service,
        default="all",
        help="log service: all/api/frontend/worker/reports/beat/postgres/redis/mailpit",
    )
    return parser.parse_args(argv)


def main() -> None:
    global VERBOSE, ACTIVE_RUNTIME, ACTIVE_PROFILE, ACTIVE_LEGACY_CONFIG
    args = parse_args()
    VERBOSE = args.verbose
    if args.check or args.command in {"setup", "start", "restart", "doctor"}:
        if not venv_python().exists() or Path(sys.prefix).resolve() == VENV.resolve():
            validate_python_version()
        validate_repository_layout()
        if sys.version_info < MIN_PYTHON:
            ensure_virtualenv()  # Existing supported environment performs its own checks.
    if args.command != "setup" and any(
        (args.provision_greenfield, args.initialize_database, args.migrate, args.frontend_build, args.confirm_database)
    ):
        raise SetupError("Provisioning and database changes are accepted only by the explicit setup command.")
    ACTIVE_LEGACY_CONFIG = pin_legacy_configuration(args.legacy_config, Runtime(ROOT).load())
    if args.command == "setup":
        setup_application(args)
        return
    if args.check or args.command == "doctor":
        doctor(args)
        return
    args.profile = (
        control_profile(args.profile) if args.command in {"stop", "status"} else resolve_profile(args.profile)
    )
    ACTIVE_PROFILE = args.profile
    runtime = Runtime(ROOT)
    check_profile_ownership(runtime, args.profile)
    if args.command == "status":
        return 0 if application_status(args.profile) else 3
    if args.command == "logs":
        display_logs(args)
        return
    if args.command in {"stop", "restart"}:
        stop_application()
        if args.command == "stop":
            return
    validate_repository_layout()
    validate_prerequisites()
    ensure_virtualenv()
    runtime = Runtime(ROOT)
    if not runtime.acquire():
        state = runtime.load()
        launcher = (state or {}).get("launcher_pid")
        suffix = f" (launcher PID {launcher})" if isinstance(launcher, int) else ""
        say("INFO", "SBOM Analyzer", f"development environment is already running or starting/stopping{suffix}.")
        if not (state or {}).get("ready"):
            raise SetupError(
                "Existing instance is not ready. Inspect status/logs; startup or shutdown may still be in progress."
            )
        if not application_status(args.profile):
            raise SetupError(
                "Existing instance is unhealthy. Inspect the named logs and use restart after correcting the cause."
            )
        return 0
    previous = {}
    startup_error = None
    try:
        # Recheck under the lock: another profile may have started between the
        # initial inspection and acquiring exclusive lifecycle ownership.
        check_profile_ownership(runtime, args.profile)
        stale = runtime.load()
        if not runtime.stop_services(say):
            raise SetupError("Unverified processes remain in runtime state. Nothing else was started.")
        clean_beat_lock((stale or {}).get("launcher_pid"))
        runtime.begin(args.profile)
        runtime.state["legacy_config"] = ACTIVE_LEGACY_CONFIG if args.profile == "legacy" else None
        atomic_json(runtime.path, runtime.state)
        ACTIVE_RUNTIME = runtime

        def cancelled(signum, frame):
            raise KeyboardInterrupt

        signals = [signal.SIGINT, signal.SIGTERM]
        if sys.platform == "win32" and hasattr(signal, "SIGBREAK"):
            signals.append(signal.SIGBREAK)
        for sig in signals:
            previous[sig] = signal.signal(sig, cancelled)
        start_application(args)
    except KeyboardInterrupt:
        print("\nStopping application processes...", flush=True)
    except BaseException as error:
        startup_error = error
        raise
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if ACTIVE_RUNTIME:
                try:
                    cleaned = runtime.stop_services(say)
                except (OwnershipError, OSError) as cleanup_error:
                    message = (
                        f"Cleanup failed ({type(cleanup_error).__name__}, winerror={getattr(cleanup_error, 'winerror', None)}); "
                        f"runtime persistence/shutdown is incomplete. Inspect {runtime.path} and component logs; retry stop."
                    )
                    if startup_error is None:
                        raise SetupError(message) from None
                    say("WARN", "Cleanup", message)
                else:
                    if not cleaned:
                        message = "Some processes could not be safely stopped; runtime state retained. Inspect component diagnostics and retry stop."
                        if startup_error is not None:
                            say("WARN", "Cleanup", message)
                        else:
                            raise SetupError(message)
                    else:
                        clean_beat_lock(os.getpid())
        finally:
            ACTIVE_RUNTIME = None
            runtime.release()
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def cli() -> int:
    try:
        return main() or 0
    except KeyboardInterrupt:
        print("\n[INFO] Development setup cancelled.", file=sys.stderr)
        return 130
    except (SetupError, OwnershipError) as error:
        print("[ERROR] " + redact(str(error), None), file=sys.stderr)
        return 1
    except Exception as error:
        # Never print configuration objects, connection strings or a traceback
        # that can include credential-bearing subprocess arguments.
        print(f"[ERROR] Setup failed: {type(error).__name__}. Run doctor, then inspect redacted logs.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
