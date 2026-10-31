"""Read-only Git worktree observations, never ownership or mutation authority.

This module uses bounded local Git plumbing with index refresh locks, hooks,
fsmonitor, external filters, submodule recursion and network transports excluded.
Snapshots are observations rather than atomic leases: callers must revalidate
before any separately authorized action. Agent ownership is always UNKNOWN.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType

_OUTPUT_LIMIT = 4 * 1024 * 1024
_COMMAND_TIMEOUT = 5.0
_DISCOVERY_TIMEOUT = 30.0
_MAX_WORKTREES = 128
_HEAD = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TRANSPORT = frozenset({"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "HOME", "USERPROFILE", "TEMP", "TMP"})


@dataclass(frozen=True)
class FilesystemIdentity:
    canonical_path: Path
    device: int
    inode: int


@dataclass(frozen=True)
class WorktreeSnapshot:
    worktree_id: str | None
    root: Path
    identity: FilesystemIdentity | None
    head: str | None
    branch: str | None
    detached: bool | None
    bare: bool | None
    dirty: bool | None
    locked: bool | None
    prunable: bool | None
    agent_owner: str = "UNKNOWN"
    status: str = "PASS"
    codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepositorySnapshot:
    repository_id: str | None
    root: Path
    identity: FilesystemIdentity | None
    head: str | None
    worktrees: tuple[WorktreeSnapshot, ...]
    common_directory: FilesystemIdentity | None
    status: str = "PASS"
    codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)


class WorkspaceError(ValueError):
    """An allowlisted category only; never Git output, remote URLs or paths."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise WorkspaceError(code) from None


def _identity(path) -> FilesystemIdentity:
    try:
        original = Path(path)
        canonical = original.resolve(strict=True)
        before = canonical.lstat()
        after = canonical.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_ino <= 0
            or before.st_dev < 0
            or (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode)
            or original.resolve(strict=True) != canonical
        ):
            raise ValueError()
        return FilesystemIdentity(canonical, before.st_dev, before.st_ino)
    except (OSError, ValueError, TypeError, RuntimeError):
        _fail("WORKSPACE_FILESYSTEM_UNVERIFIED")


def _identifier(kind, identity, repository_id=None):
    value = [kind, repository_id, os.path.normcase(str(identity.canonical_path)), identity.device, identity.inode]
    return hashlib.sha256(json.dumps(value, ensure_ascii=True).encode("ascii")).hexdigest()


def _environment() -> Mapping[str, str]:
    values = {key.upper(): value for key, value in os.environ.items() if key.upper() in _TRANSPORT}
    values.update(
        LANG="C",
        LC_ALL="C",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_ATTR_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_PROTOCOL_FROM_USER="0",
        GIT_ALLOW_PROTOCOL="",
    )
    return MappingProxyType(values)


def _run_git(command, *, cwd, environment, timeout, max_output, input_bytes=None):
    """Bound buffers/time and stop only the original short-lived Git handle."""
    process = None
    streams, threads = [], []
    output, errors = bytearray(), bytearray()
    exceeded = threading.Event()
    reason = None

    def read(stream, target):
        try:
            while chunk := stream.read(65536):
                remaining = max_output - len(target)
                target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()
        except (OSError, ValueError):
            exceeded.set()

    def write(stream):
        try:
            remaining = memoryview(input_bytes)
            while remaining:
                written = stream.write(remaining)
                if not written:
                    break
                remaining = remaining[written:]
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                exceeded.set()

    try:
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        process = subprocess.Popen(
            command, cwd=cwd, env=dict(environment), shell=False, bufsize=0,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options,
        )
        streams = [process.stdout, process.stderr]
        for stream, target in ((process.stdout, output), (process.stderr, errors)):
            thread = threading.Thread(target=read, args=(stream, target), daemon=True)
            thread.start()
            threads.append(thread)
        if input_bytes is not None:
            thread = threading.Thread(target=write, args=(process.stdin,), daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if exceeded.is_set() or time.monotonic() >= deadline:
                reason = "GIT_OUTPUT_LIMIT" if exceeded.is_set() else "GIT_TIMEOUT"
                process.kill()
                break
            time.sleep(0.01)
        process.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            _fail("GIT_PROBE_UNCONFIRMED")
        if reason or exceeded.is_set():
            _fail(reason or "GIT_OUTPUT_LIMIT")
        return CommandResult(process.returncode, bytes(output), bytes(errors))
    except WorkspaceError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError):
        _fail("GIT_PROBE_UNVERIFIED")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        for stream in streams:
            stream.close()


class _Probe:
    def __init__(self, runner):
        executable = "git" if runner is not None else shutil.which("git")
        if executable is None:
            _fail("GIT_REQUIRED")
        if runner is None:
            try:
                executable = str(Path(executable).resolve(strict=True))
                if not stat.S_ISREG(Path(executable).stat().st_mode) or Path(executable).suffix.lower() in {".cmd", ".bat"}:
                    raise ValueError()
            except (OSError, ValueError):
                _fail("GIT_EXECUTABLE_UNVERIFIED")
        self.runner = runner or _run_git
        self.environment = _environment()
        self.deadline = time.monotonic() + _DISCOVERY_TIMEOUT
        self.base = (
            executable, "--no-pager", "--no-optional-locks",
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-c", "submodule.recurse=false", "-c", "status.submoduleSummary=false",
            "-c", "core.hooksPath=" + os.devnull,
            "-c", "diff.external=", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
            "-c", "protocol.allow=never", "-c", "core.attributesFile=" + os.devnull,
        )

    def run(self, cwd, arguments, *, allowed=(0,), input_bytes=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _fail("GIT_DISCOVERY_TIMEOUT")
        if input_bytes is not None and len(input_bytes) > _OUTPUT_LIMIT:
            _fail("GIT_OUTPUT_LIMIT")
        try:
            result = self.runner(
                (*self.base, *arguments), cwd=cwd, environment=self.environment,
                timeout=min(_COMMAND_TIMEOUT, remaining), max_output=_OUTPUT_LIMIT, input_bytes=input_bytes,
            )
        except WorkspaceError:
            raise
        except Exception:
            _fail("GIT_PROBE_UNVERIFIED")
        if (
            not isinstance(result, CommandResult) or type(result.returncode) is not int
            or not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes)
        ):
            _fail("GIT_RESPONSE_UNVERIFIED")
        if max(len(result.stdout), len(result.stderr)) > _OUTPUT_LIMIT:
            _fail("GIT_OUTPUT_LIMIT")
        if result.returncode not in allowed:
            _fail("GIT_COMMAND_BLOCKED")
        return result


def _path_output(value):
    if not value.endswith(b"\n") or b"\0" in value:
        _fail("GIT_PATH_UNVERIFIED")
    path = Path(os.fsdecode(value[:-1]))
    if not path.is_absolute():
        _fail("GIT_PATH_UNVERIFIED")
    return path


def _records(data):
    if not data.endswith(b"\0\0"):
        _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
    records = []
    for block in data[:-2].split(b"\0\0"):
        fields = {}
        for item in block.split(b"\0"):
            name, separator, value = item.partition(b" ")
            if name not in {b"worktree", b"HEAD", b"branch", b"detached", b"bare", b"locked", b"prunable"} or name in fields:
                _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
            if name in {b"detached", b"bare"} and separator:
                _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
            fields[name] = value
        if b"worktree" not in fields or not Path(os.fsdecode(fields[b"worktree"])).is_absolute():
            _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
        if (b"HEAD" in fields and not _HEAD.fullmatch(fields[b"HEAD"])) or (
            b"bare" in fields and any(name in fields for name in (b"HEAD", b"branch", b"detached"))
        ):
            _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
        if b"bare" not in fields and (
            b"HEAD" not in fields or not _HEAD.fullmatch(fields[b"HEAD"])
            or (b"branch" in fields) == (b"detached" in fields)
            or (b"branch" in fields and not fields[b"branch"].startswith(b"refs/heads/"))
        ):
            _fail("GIT_WORKTREE_FORMAT_UNVERIFIED")
        records.append(fields)
    if not 1 <= len(records) <= _MAX_WORKTREES:
        _fail("GIT_WORKTREE_LIMIT")
    return records


def _dirty(probe, root):
    configuration = probe.run(
        root, ("config", "--includes", "--null", "--name-only", "--get-regexp",
               r"^(filter\.|extensions\.partialclone$|remote\..*\.promisor$)"), allowed=(0, 1),
    )
    if configuration.returncode == 0 or configuration.stdout:
        _fail("GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED")
    paths = probe.run(root, ("ls-files", "-z")).stdout
    if paths:
        if not paths.endswith(b"\0"):
            _fail("GIT_INDEX_FORMAT_UNVERIFIED")
        indexed_paths = paths.split(b"\0")[:-1]
        attributes = probe.run(root, ("check-attr", "-z", "--stdin", "filter"), input_bytes=paths).stdout.split(b"\0")
        if attributes[-1] != b"" or (len(attributes) - 1) % 3:
            _fail("GIT_ATTRIBUTES_UNVERIFIED")
        if len(attributes) - 1 != len(indexed_paths) * 3:
            _fail("GIT_ATTRIBUTES_UNVERIFIED")
        for index in range(0, len(attributes) - 1, 3):
            if attributes[index] != indexed_paths[index // 3]:
                _fail("GIT_ATTRIBUTES_UNVERIFIED")
            if attributes[index + 1] != b"filter" or attributes[index + 2] not in {b"unspecified", b"unset"}:
                _fail("GIT_FILTER_OR_PROMISOR_REVIEW_REQUIRED")
    result = probe.run(
        root, ("status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all", "--ignore-submodules=all")
    )
    if result.stdout and not result.stdout.endswith(b"\0"):
        _fail("GIT_STATUS_FORMAT_UNVERIFIED")
    for entry in result.stdout.split(b"\0")[:-1]:
        if len(entry) < 4 or entry[2:3] != b" " or entry[:2] == b"  " or any(char not in b" MADRCU?!" for char in entry[:2]):
            _fail("GIT_STATUS_FORMAT_UNVERIFIED")
    return bool(result.stdout)


def _worktree(probe, fields, common, repository_id):
    root = Path(os.fsdecode(fields[b"worktree"]))
    bare, detached = b"bare" in fields, b"detached" in fields
    raw_head = fields.get(b"HEAD")
    head = raw_head.decode("ascii") if raw_head and set(raw_head) != {ord("0")} else None
    branch = os.fsdecode(fields[b"branch"]) if b"branch" in fields else None
    identity, worktree_id, dirty = None, None, None
    codes = []
    try:
        identity = _identity(root)
        root = identity.canonical_path
        worktree_id = _identifier("wt", identity, repository_id)
        observed_common = _identity(_path_output(probe.run(root, ("rev-parse", "--path-format=absolute", "--git-common-dir")).stdout))
        if observed_common != common:
            _fail("GIT_REPOSITORY_IDENTITY_CHANGED")
        if bare:
            _fail("GIT_BARE_WORKTREE")
        if head is None:
            codes.append("GIT_HEAD_UNVERIFIED")
        dirty = _dirty(probe, root)
        if _identity(root) != identity:
            _fail("WORKSPACE_FILESYSTEM_CHANGED")
    except WorkspaceError as error:
        codes.append(error.code)
    return WorktreeSnapshot(
        worktree_id, root, identity, head, branch, detached, bare, dirty,
        b"locked" in fields, b"prunable" in fields, status="BLOCKED" if codes else "PASS", codes=tuple(codes),
    )


def discover_workspaces(root, *, runner: Callable[..., CommandResult] | None = None) -> RepositorySnapshot:
    """Discover local authoritative worktrees; the injected runner is test-only.

    Branches retain their full ``refs/heads/...`` form. No remote URL, lock/prune
    reason, dirty filename, user identity or command stderr enters the snapshot.
    Missing/unverifiable values remain None and BLOCKED, never clean or owned.
    """
    root = Path(root).absolute()
    identity, common, repository_id, worktrees, head = None, None, None, (), None
    try:
        identity = _identity(root)
        root = identity.canonical_path
        probe = _Probe(runner)
        common = _identity(_path_output(probe.run(root, ("rev-parse", "--path-format=absolute", "--git-common-dir")).stdout))
        repository_id = _identifier("repo", common)
        listing = probe.run(root, ("worktree", "list", "--porcelain", "-z")).stdout
        fields = _records(listing)
        if runner is None and len(fields) > 1:
            # Each worktree needs several guarded Git queries. Bound concurrency
            # as well as the shared deadline so a real multi-worktree Windows
            # checkout does not spend its whole budget on process startup.
            # All helpers retain their original handles and read-only policy.
            with ThreadPoolExecutor(max_workers=4) as pool:
                worktrees = tuple(pool.map(lambda item: _worktree(probe, item, common, repository_id), fields))
        else:
            worktrees = tuple(_worktree(probe, item, common, repository_id) for item in fields)
        ids = [item.worktree_id for item in worktrees if item.worktree_id is not None]
        if len(ids) != len(set(ids)):
            _fail("GIT_DUPLICATE_WORKTREE_IDENTITY")
        if _identity(common.canonical_path) != common:
            _fail("GIT_REPOSITORY_IDENTITY_CHANGED")
        if probe.run(root, ("worktree", "list", "--porcelain", "-z")).stdout != listing:
            _fail("GIT_WORKTREE_SNAPSHOT_CHANGED")
        selected = next((item for item in worktrees if item.identity == identity), None)
        if selected is None:
            _fail("GIT_WORKTREE_NOT_LISTED")
        head = selected.head
        blocked = any(item.status == "BLOCKED" for item in worktrees)
        return RepositorySnapshot(
            repository_id, root, identity, head, worktrees, common,
            "BLOCKED" if blocked else "PASS", ("WORKTREE_INSPECTION_BLOCKED",) if blocked else (),
        )
    except WorkspaceError as error:
        worktrees = tuple(replace(item, status="BLOCKED", codes=(*item.codes, error.code)) for item in worktrees)
        return RepositorySnapshot(repository_id, root, identity, head, worktrees, common, "BLOCKED", (error.code,))
