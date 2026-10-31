"""Read-only instance observations, never runtime or acceptance verification.

Comparison consumes existing typed Git/registry observations. Logs are read only
from fixed private instance paths and project metadata, never message content.
No provider, application, dotenv, database or process-control adapter is used.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

if __package__:
    from . import dev_instance_plan, dev_instance_registry, dev_instance_storage, dev_workspace
else:
    import dev_instance_plan
    import dev_instance_registry
    import dev_instance_storage
    import dev_workspace

_LOGS = {
    "setup": "setup.log",
    "api": "api.log",
    "frontend": "frontend.log",
    "worker": "celery-worker.log",
    "reports": "celery-reports-worker.log",
    "beat": "celery-beat.log",
}
_PROVIDERS = frozenset({"postgres", "redis", "mailpit"})
_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL"})
_STATUSES = frozenset({"RUNNING", "STOPPED", "PARTIAL", "UNKNOWN", "UNOWNED", "BLOCKED", "FAILED"})
_EXCEPTIONS = frozenset(
    {
        "OSError",
        "PermissionError",
        "FileNotFoundError",
        "ProcessLookupError",
        "TimeoutError",
        "ValueError",
        "RuntimeError",
        "ConnectionError",
        "SSLError",
        "CertificateError",
        "SetupError",
        "OwnershipError",
    }
)
_WINERRORS = frozenset(
    {
        0,
        2,
        3,
        5,
        6,
        8,
        14,
        18,
        32,
        80,
        87,
        122,
        183,
        206,
        234,
        258,
        259,
        267,
        299,
        487,
        995,
        996,
        997,
        998,
        1168,
        1236,
        1460,
    }
)
_TIME = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?"
_DIFFERENCES = frozenset(
    {
        "COMMIT",
        "BRANCH",
        "DIRTY",
        "MODE",
        "PROPOSED_URLS",
        "PROPOSED_RESOURCES",
        "BASELINE_HEAD_DRIFT",
        "CANDIDATE_HEAD_DRIFT",
    }
)
_CODES = frozenset(
    {
        "COMPARISON_INPUT_INVALID",
        "COMPARISON_GIT_UNVERIFIED",
        "COMPARISON_REGISTRY_UNVERIFIED",
        "COMPARISON_TARGET_NOT_LISTED",
        "COMPARISON_DISTINCT_WORKTREES_REQUIRED",
        "COMPARISON_REGISTRY_ENTRY_MISSING",
        "INSTANCE_LOG_COMPONENT_INVALID",
        "INSTANCE_LOG_PATH_UNVERIFIED",
        "INSTANCE_LOG_MISSING",
        "INSTANCE_LOG_CHANGED",
        "INSTANCE_LOG_READ_BLOCKED",
        "INSTANCE_LOG_METADATA_OBSERVED",
        "INSTANCE_LOG_METADATA_INVALID",
        "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED",
        "INSTANCE_LOG_LIMIT_INVALID",
        "INSTANCE_OBSERVATION_INVALID",
    }
)
_CATEGORIES = {
    "dependencies": "INSTANCE_DEPENDENCY_READ_ADAPTER_REQUIRED",
    "configuration": "INSTANCE_CONFIGURATION_READ_ADAPTER_REQUIRED",
    "providers": "INSTANCE_PROVIDER_READ_ADAPTER_REQUIRED",
    "database": "INSTANCE_DATABASE_READ_ADAPTER_REQUIRED",
    "authentication": "INSTANCE_AUTH_READ_ADAPTER_REQUIRED",
    "tls": "INSTANCE_TLS_READ_ADAPTER_REQUIRED",
    "workers": "INSTANCE_WORKER_READ_ADAPTER_REQUIRED",
    "process_ownership": "INSTANCE_RUNTIME_READ_ADAPTER_REQUIRED",
    "health": "INSTANCE_HEALTH_READ_ADAPTER_REQUIRED",
}


class ObservationError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "INSTANCE_OBSERVATION_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise ObservationError(code) from None


def _uuid(value):
    if type(value) is not str or len(value) != 36:
        _fail("INSTANCE_OBSERVATION_INVALID")
    try:
        if str(UUID(value)) == value:
            return value
    except ValueError:
        pass
    _fail("INSTANCE_OBSERVATION_INVALID")


@dataclass(frozen=True, slots=True)
class WorktreeView:
    worktree_id: str
    head: str
    branch: str | None
    dirty: bool
    descriptor: dev_instance_plan.InstanceDescriptor | None = field(default=None, repr=False)
    reported_registry_state: str | None = None

    def __post_init__(self):
        try:
            dev_instance_plan._public_id(self.worktree_id)
        except dev_instance_plan.InstancePlanError:
            _fail("COMPARISON_GIT_UNVERIFIED")
        if (
            type(self.head) is not str
            or not dev_instance_plan._COMMIT.fullmatch(self.head)
            or type(self.dirty) is not bool
            or self.branch is not None
            and (
                type(self.branch) is not str
                or len(self.branch) > 256
                or re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", self.branch) is None
            )
        ):
            _fail("COMPARISON_GIT_UNVERIFIED")
        if self.descriptor is not None and (
            type(self.descriptor) is not dev_instance_plan.InstanceDescriptor
            or self.descriptor.worktree_id != self.worktree_id
        ):
            _fail("COMPARISON_REGISTRY_UNVERIFIED")
        if self.reported_registry_state is not None and (
            type(self.reported_registry_state) is not str
            or self.reported_registry_state not in dev_instance_registry._STATES
        ):
            _fail("COMPARISON_REGISTRY_UNVERIFIED")

    def to_dict(self):
        descriptor = self.descriptor
        urls = {"frontend": descriptor.origin} if descriptor else {}
        if descriptor:
            for component, scheme in (("api", "http"), ("mailpit_ui", "http")):
                if component in descriptor.ports:
                    urls[component] = f"{scheme}://127.0.0.1:{descriptor.ports[component]}"
        return {
            "worktree_id": self.worktree_id,
            "head": self.head,
            "branch": self.branch,
            "dirty": self.dirty,
            "instance_id": descriptor.instance_id if descriptor else None,
            "mode": descriptor.mode if descriptor else None,
            "proposed_origin": descriptor.origin if descriptor else None,
            "proposed_urls": urls,
            "proposed_resources": dict(descriptor.resources) if descriptor else {},
            "registered_head_drift": descriptor.commit != self.head if descriptor else None,
            "reported_registry_state": self.reported_registry_state,
            "runtime_verified": False,
        }


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    status: str
    baseline: WorktreeView | None = None
    candidate: WorktreeView | None = None
    differences: tuple[str, ...] = ()
    codes: tuple[str, ...] = ()

    def __post_init__(self):
        if (
            type(self.status) is not str
            or self.status not in {"OBSERVED", "BLOCKED"}
            or any(value is not None and type(value) is not WorktreeView for value in (self.baseline, self.candidate))
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        if self.status == "OBSERVED" and (self.baseline is None or self.candidate is None):
            _fail("INSTANCE_OBSERVATION_INVALID")
        if (
            type(self.differences) not in {tuple, list}
            or len(self.differences) > len(_DIFFERENCES)
            or any(type(value) is not str or value not in _DIFFERENCES for value in self.differences)
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        if (
            type(self.codes) not in {tuple, list}
            or len(self.codes) > len(_CODES)
            or any(type(value) is not str or value not in _CODES for value in self.codes)
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        object.__setattr__(self, "differences", tuple(self.differences))
        object.__setattr__(self, "codes", tuple(self.codes))

    def to_dict(self):
        return {
            "status": self.status,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "differences": list(self.differences),
            "codes": list(self.codes),
            "runtime_verified": False,
            "api_verified": False,
            "visual_verified": False,
            "acceptance_verified": False,
        }


def compare_workspaces(repository_snapshot, baseline_id, candidate_id, registry_snapshot):
    """Compare listed source/public proposals; never inspect Git or live services."""
    try:
        if (
            type(repository_snapshot) is not dev_workspace.RepositorySnapshot
            or type(registry_snapshot) is not dev_instance_registry.RegistrySnapshot
        ):
            _fail("COMPARISON_INPUT_INVALID")
        if (
            repository_snapshot.status != "PASS"
            or repository_snapshot.codes
            or repository_snapshot.repository_id is None
            or type(repository_snapshot.identity) is not dev_workspace.FilesystemIdentity
            or type(repository_snapshot.common_directory) is not dev_workspace.FilesystemIdentity
        ):
            _fail("COMPARISON_GIT_UNVERIFIED")
        if (
            type(repository_snapshot.worktrees) not in {tuple, list}
            or len(repository_snapshot.worktrees) > 128
            or any(type(value) is not dev_workspace.WorktreeSnapshot for value in repository_snapshot.worktrees)
        ):
            _fail("COMPARISON_GIT_UNVERIFIED")
        if registry_snapshot.codes not in {(), ("REGISTRY_MISSING",)}:
            _fail("COMPARISON_REGISTRY_UNVERIFIED")
        if baseline_id == candidate_id:
            _fail("COMPARISON_DISTINCT_WORKTREES_REQUIRED")
        rows, missing = [], False
        for selected in (baseline_id, candidate_id):
            matches = [value for value in repository_snapshot.worktrees if value.worktree_id == selected]
            if len(matches) != 1:
                _fail("COMPARISON_TARGET_NOT_LISTED")
            worktree = matches[0]
            if (
                worktree.status != "PASS"
                or worktree.codes
                or type(worktree.identity) is not dev_workspace.FilesystemIdentity
                or worktree.bare is not False
                or worktree.prunable is not False
                or type(worktree.detached) is not bool
            ):
                _fail("COMPARISON_GIT_UNVERIFIED")
            entries = [entry for entry in registry_snapshot.entries if entry.descriptor.worktree_id == selected]
            if len(entries) > 1 or any(
                entry.descriptor.repository_id != repository_snapshot.repository_id for entry in entries
            ):
                _fail("COMPARISON_REGISTRY_UNVERIFIED")
            entry = entries[0] if entries else None
            missing |= entry is None
            rows.append(
                WorktreeView(
                    worktree.worktree_id,
                    worktree.head,
                    worktree.branch,
                    worktree.dirty,
                    entry.descriptor if entry else None,
                    entry.state if entry else None,
                )
            )
        left, right = (row.to_dict() for row in rows)
        changed = [
            label
            for key, label in (
                ("head", "COMMIT"),
                ("branch", "BRANCH"),
                ("dirty", "DIRTY"),
                ("mode", "MODE"),
                ("proposed_urls", "PROPOSED_URLS"),
                ("proposed_resources", "PROPOSED_RESOURCES"),
            )
            if left[key] != right[key]
        ]
        changed += [
            label
            for row, label in ((left, "BASELINE_HEAD_DRIFT"), (right, "CANDIDATE_HEAD_DRIFT"))
            if row["registered_head_drift"]
        ]
        return ComparisonReport(
            "OBSERVED", *rows, tuple(changed), ("COMPARISON_REGISTRY_ENTRY_MISSING",) if missing else ()
        )
    except ObservationError as error:
        return ComparisonReport("BLOCKED", codes=(error.code,))
    except Exception:
        return ComparisonReport("BLOCKED", codes=("COMPARISON_INPUT_INVALID",))


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    results: tuple[tuple[str, str, str], ...]
    host: object = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self):
        allowed = set(_CATEGORIES.values()) | {
            "INSTANCE_METADATA_REQUIRED",
            "INSTANCE_COMPONENT_NOT_ALLOCATED",
            "HOST_CAPACITY_OBSERVED",
            "HOST_CAPACITY_UNVERIFIED",
        }
        if (
            type(self.results) not in {tuple, list}
            or len(self.results) > len(_CATEGORIES) + 1
            or any(
                type(row) not in {tuple, list}
                or len(row) != 3
                or any(type(value) is not str for value in row)
                or row[0] not in {*_CATEGORIES, "host"}
                or row[1] not in {"BLOCKED", "SKIPPED", "OBSERVED"}
                or row[2] not in allowed
                for row in self.results
            )
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        if type(self.host) not in {dict, type(MappingProxyType({}))} or any(
            type(key) is not str
            or key not in {"cpu_count", "disk_total", "disk_free"}
            or type(value) is not int
            or not 0 <= value <= 2**64 - 1
            for key, value in self.host.items()
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        object.__setattr__(self, "results", tuple(tuple(row) for row in self.results))
        object.__setattr__(self, "host", MappingProxyType(dict(self.host)))

    def to_dict(self):
        return {
            "results": [
                {"category": category, "status": status, "code": code} for category, status, code in self.results
            ],
            "host": dict(self.host),
            "runtime_verified": False,
            "api_verified": False,
            "visual_verified": False,
            "acceptance_verified": False,
        }


def _host_capacity(include_host, home):
    results = []
    host = {}
    if include_host:
        try:
            anchor = _home(home)
            root, _ = dev_instance_storage._paths(anchor / "capacity-observation", anchor)
            before = dev_instance_storage._verify(root, private=False)
            count, disk = os.cpu_count(), shutil.disk_usage(root)
            if (
                any(type(value) is not int or not 0 <= value <= 2**64 - 1 for value in (disk.total, disk.free))
                or disk.free > disk.total
            ):
                raise ValueError()
            if dev_instance_storage._identity(
                dev_instance_storage._verify(root, private=False)
            ) != dev_instance_storage._identity(before):
                raise ValueError()
            host.update(disk_total=disk.total, disk_free=disk.free)
            if type(count) is int and count > 0:
                host["cpu_count"] = count
            results.append(("host", "OBSERVED", "HOST_CAPACITY_OBSERVED"))
        except Exception:
            host.clear()
            results.append(("host", "BLOCKED", "HOST_CAPACITY_UNVERIFIED"))
    return tuple(results), host


def diagnose_instance(descriptor, *, include_host=False, home=None):
    if type(descriptor) is not dev_instance_plan.InstanceDescriptor or type(include_host) is not bool:
        _fail("INSTANCE_OBSERVATION_INVALID")
    results = []
    for category, code in _CATEGORIES.items():
        not_allocated = descriptor.mode != "isolated" and category in {"providers", "database", "workers"}
        results.append(
            (
                category,
                "SKIPPED" if not_allocated else "BLOCKED",
                "INSTANCE_COMPONENT_NOT_ALLOCATED" if not_allocated else code,
            )
        )
    capacity, host = _host_capacity(include_host, home)
    return DiagnosticReport((*results, *capacity), host)


def diagnose_unregistered(*, include_host=False, home=None):
    """Report missing instance metadata without inventing a descriptor or readiness."""
    if type(include_host) is not bool:
        _fail("INSTANCE_OBSERVATION_INVALID")
    results = tuple((category, "BLOCKED", "INSTANCE_METADATA_REQUIRED") for category in _CATEGORIES)
    capacity, host = _host_capacity(include_host, home)
    return DiagnosticReport((*results, *capacity), host)


def _timestamp(value):
    if type(value) is not str or re.fullmatch(_TIME, value) is None:
        return None
    try:
        return datetime.fromisoformat(value.replace(",", ".").replace("Z", "+00:00")).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class LogRecord:
    timestamp: str | None = None
    level: str | None = None
    exception_class: str | None = None
    winerror: int | None = None
    reported_status: str | None = None

    def __post_init__(self):
        if (
            (self.timestamp is not None and _timestamp(self.timestamp) is None)
            or self.level is not None
            and (type(self.level) is not str or self.level not in _LEVELS)
            or self.exception_class is not None
            and (type(self.exception_class) is not str or self.exception_class not in _EXCEPTIONS)
            or self.winerror is not None
            and (type(self.winerror) is not int or self.winerror not in _WINERRORS)
            or self.reported_status is not None
            and (type(self.reported_status) is not str or self.reported_status not in _STATUSES)
        ):
            _fail("INSTANCE_LOG_METADATA_INVALID")

    def to_dict(self):
        return {
            name: value
            for name in ("timestamp", "level", "exception_class", "winerror", "reported_status")
            if (value := getattr(self, name)) is not None
        }


def _record(line):
    data = {}
    try:
        parsed = json.loads(line) if line.lstrip().startswith("{") else None
    except (ValueError, RecursionError):
        parsed = None
    if type(parsed) is dict:
        data = {key: parsed.get(key) for key in ("timestamp", "level", "exception_class", "winerror", "status")}
    else:
        stamp = re.match(r"\[?(" + _TIME + r")", line)
        level = re.search(r"(?:^|[\s\[:,])(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)(?=[/\s\]:]|$)", line[:90])
        error = re.search(r"\b(?:exception_class|error_type)\s*[=:]\s*([A-Za-z][A-Za-z0-9_]*)\b", line)
        number = re.search(r"\bwinerror\s*[=:]\s*([0-9]{1,10})\b", line)
        status = re.search(r"\bstatus\s*[=:]\s*([A-Z_]+)\b", line)
        data = {
            "timestamp": stamp[1] if stamp else None,
            "level": level[1] if level else None,
            "exception_class": error[1] if error else None,
            "winerror": int(number[1]) if number else None,
            "status": status[1] if status else None,
        }
    record = LogRecord(
        _timestamp(data.get("timestamp")),
        data.get("level") if type(data.get("level")) is str and data["level"] in _LEVELS else None,
        data.get("exception_class")
        if type(data.get("exception_class")) is str and data["exception_class"] in _EXCEPTIONS
        else None,
        data.get("winerror") if type(data.get("winerror")) is int and data["winerror"] in _WINERRORS else None,
        data.get("status") if type(data.get("status")) is str and data["status"] in _STATUSES else None,
    )
    return record if record.to_dict() else None


@dataclass(frozen=True, slots=True)
class LogReport:
    instance_id: str
    component: str
    status: str
    code: str
    records: tuple[LogRecord, ...] = ()
    local_path: Path | None = field(default=None, repr=False)

    def __post_init__(self):
        _uuid(self.instance_id)
        if (
            type(self.component) is not str
            or self.component not in {*_LOGS, *_PROVIDERS}
            or type(self.status) is not str
            or self.status not in {"OBSERVED", "BLOCKED", "SKIPPED"}
            or type(self.code) is not str
            or self.code not in _CODES
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        if (
            type(self.records) not in {tuple, list}
            or len(self.records) > 200
            or any(type(value) is not LogRecord for value in self.records)
        ):
            _fail("INSTANCE_OBSERVATION_INVALID")
        object.__setattr__(self, "records", tuple(self.records))

    def to_dict(self):
        return {
            "instance_id": self.instance_id,
            "component": self.component,
            "status": self.status,
            "code": self.code,
            "records": [value.to_dict() for value in self.records],
            "runtime_verified": False,
            "content_guidance": "Open the verified local log for message content; metadata is not service readiness."
            if self.status == "OBSERVED"
            else "Preserve instance state and review preparation; no message content was exposed.",
        }


def _file(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or not info.st_ino
        or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & 1024
    ):
        _fail("INSTANCE_LOG_PATH_UNVERIFIED")
    if sys.platform == "win32":
        if __package__:
            from .dev_windows_acl import verify_access
        else:
            from dev_windows_acl import verify_access
        verify_access(path, private=True)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        _fail("INSTANCE_LOG_PATH_UNVERIFIED")
    return info


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _home(home):
    anchor = Path.home() if home is None else Path(home)
    if not anchor.is_absolute() or sys.platform == "win32" and str(anchor).startswith("\\\\"):
        _fail("INSTANCE_LOG_PATH_UNVERIFIED")
    return anchor


def _tail(instance_id, component, home, max_bytes):
    anchor = _home(home)
    directory = anchor / ".sbom-dev" / "instances" / instance_id / ".dev-logs"
    root, parts = dev_instance_storage._paths(directory, anchor)
    pinned = [(root, dev_instance_storage._identity(dev_instance_storage._verify(root, private=False)), False)]
    for part in parts:
        root = root / part
        pinned.append((root, dev_instance_storage._identity(dev_instance_storage._verify(root, private=True)), True))
    path = directory / _LOGS[component]
    before = _file(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        _fail("INSTANCE_LOG_CHANGED")
    try:
        opened = os.fstat(fd)
        # Native Windows stat APIs can expose different ctime semantics. Pin
        # the same inode/size/mtime across APIs, then compare full stamps only
        # within each API before/after the read; neither identity check is lost.
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            _fail("INSTANCE_LOG_CHANGED")
        start = max(0, before.st_size - max_bytes)
        # One preceding byte distinguishes a complete first line from a cut
        # line. The total read bound is max_bytes + 1, never the whole log.
        os.lseek(fd, start - 1 if start else 0, os.SEEK_SET)
        chunks, remaining = [], min(before.st_size, max_bytes + bool(start))
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        dev_instance_storage._revalidate(pinned)
        if _stamp(os.fstat(fd)) != _stamp(opened) or _stamp(_file(path)) != _stamp(before):
            _fail("INSTANCE_LOG_CHANGED")
    except FileNotFoundError:
        _fail("INSTANCE_LOG_CHANGED")
    finally:
        os.close(fd)
    content = b"".join(chunks)
    if start:
        boundary, content = content[:1] == b"\n", content[1:]
        if not boundary:
            content = content.partition(b"\n")[2]
    return path, content


def observe_logs(instance_id, component, *, home=None, max_bytes=32768, max_lines=80):
    _uuid(instance_id)
    if type(component) is not str or component not in {*_LOGS, *_PROVIDERS}:
        _fail("INSTANCE_LOG_COMPONENT_INVALID")
    if (
        type(max_bytes) is not int
        or not 1 <= max_bytes <= 65536
        or type(max_lines) is not int
        or not 1 <= max_lines <= 200
    ):
        _fail("INSTANCE_LOG_LIMIT_INVALID")
    if component in _PROVIDERS:
        return LogReport(instance_id, component, "BLOCKED", "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED")
    try:
        path, content = _tail(instance_id, component, home, max_bytes)
        records = tuple(
            record
            for line in content.decode("utf-8", errors="replace").splitlines()[-max_lines:]
            if (record := _record(line)) is not None
        )
        return LogReport(instance_id, component, "OBSERVED", "INSTANCE_LOG_METADATA_OBSERVED", records, path)
    except FileNotFoundError:
        return LogReport(instance_id, component, "SKIPPED", "INSTANCE_LOG_MISSING")
    except ObservationError as error:
        return LogReport(instance_id, component, "BLOCKED", error.code)
    except Exception:
        return LogReport(instance_id, component, "BLOCKED", "INSTANCE_LOG_READ_BLOCKED")
