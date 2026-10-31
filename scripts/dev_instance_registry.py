"""Protected public instance descriptors; no resources, secrets or PID control.

Read paths never create the registry or its permanent writer lock. An authorized
preparation adapter must create the private directory first. Registry identity
and UUID names are bookkeeping, not authority to adopt or mutate a resource.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

if __package__:
    from . import dev_environment, dev_instance_plan, dev_private
else:
    import dev_environment
    import dev_instance_plan
    import dev_private

_REGISTRY_CODES = frozenset(
    {
        "REGISTRY_ID_INVALID",
        "REGISTRY_OBJECT_UNVERIFIED",
        "REGISTRY_ACCESS_UNVERIFIED",
        "REGISTRY_SCHEMA_INVALID",
        "REGISTRY_DESCRIPTOR_UNVERIFIED",
        "REGISTRY_MISSING",
        "REGISTRY_CHANGED_DURING_READ",
        "REGISTRY_REPOSITORY_MISMATCH",
        "REGISTRY_ID_MISMATCH",
        "REGISTRY_RECORD_UNVERIFIED",
        "REGISTRY_LIMIT_REQUIRED",
        "REGISTRY_UNKNOWN_ARTIFACT",
        "REGISTRY_WORKTREE_CONFLICT",
        "REGISTRY_INSPECTION_FAILED",
        "REGISTRY_LOCK_UNVERIFIED",
        "REGISTRY_BUSY",
        "REGISTRY_PUBLICATION_UNCONFIRMED",
        "REGISTRY_REVISION_REQUIRED",
        "REGISTRY_REVISION_CHANGED",
        "REGISTRY_OWNERSHIP_UNVERIFIED",
        "REGISTRY_JOURNAL_CHANGED",
        "REGISTRY_PORT_CONFLICT",
    }
)
_OPERATION_CODES = frozenset(
    {
        "REGISTRY_PREPARED",
        "DEPENDENCIES_PREPARED",
        "PROVIDERS_PLANNED",
        "START_REQUESTED",
        "STOP_REQUESTED",
    }
)
_LAST_CODES = (
    _REGISTRY_CODES
    | _OPERATION_CODES
    | frozenset(
        {
            "INSTANCE_PLANNED",
            "INSTANCE_LIVE_OPERATIONS_GATED",
            "SHARED_BACKEND_REGISTRATION_REQUIRED",
            "NATIVE_ENROLLMENT_GATED",
            "HCL_REGISTRATION_APPROVAL_REQUIRED",
            "CONTAINER_ENGINE_APPROVAL_REQUIRED",
            "LOCAL_ISOLATION_POLICY_REQUIRED",
            "WORKSPACE_REGISTRY_PREPARED",
        }
    )
)
_STATES = frozenset({"PLANNED", "PREPARED", "STARTING", "READY", "STOPPED", "FAILED", "BLOCKED"})


class RegistryError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _REGISTRY_CODES else "REGISTRY_SCHEMA_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise RegistryError(code) from None


def _uuid(value):
    if type(value) is not str:
        _fail("REGISTRY_ID_INVALID")
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except ValueError:
        _fail("REGISTRY_ID_INVALID")
    return value


def _identity(info):
    return info.st_dev, info.st_ino


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _json_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _fail("REGISTRY_SCHEMA_INVALID")
        result[name] = value
    return result


def _private(path, *, directory=False, links=1):
    info = path.lstat()
    if (
        not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or getattr(info, "st_file_attributes", 0) & 1024
        or (not directory and info.st_nlink != links)
    ):
        _fail("REGISTRY_OBJECT_UNVERIFIED")
    if sys.platform == "win32":
        if __package__:
            from .dev_windows_acl import verify_access
        else:
            from dev_windows_acl import verify_access
        verify_access(path, private=True)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        _fail("REGISTRY_ACCESS_UNVERIFIED")
    return info


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    descriptor: dev_instance_plan.InstanceDescriptor
    revision: int = 1
    state: str = "PLANNED"
    last_code: str | None = None
    plan_fingerprint: str | None = None
    operations: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.descriptor) is not dev_instance_plan.InstanceDescriptor:
            _fail("REGISTRY_DESCRIPTOR_UNVERIFIED")
        try:
            descriptor = dev_instance_plan.InstanceDescriptor.from_dict(self.descriptor.to_dict())
        except Exception:
            _fail("REGISTRY_DESCRIPTOR_UNVERIFIED")
        if (
            type(self.revision) is not int
            or not 1 <= self.revision <= 2147483647
            or type(self.state) is not str
            or self.state not in _STATES
        ):
            _fail("REGISTRY_SCHEMA_INVALID")
        if self.last_code is not None and (type(self.last_code) is not str or self.last_code not in _LAST_CODES):
            _fail("REGISTRY_SCHEMA_INVALID")
        if self.plan_fingerprint is not None and (
            type(self.plan_fingerprint) is not str or re.fullmatch(r"[0-9a-f]{64}", self.plan_fingerprint) is None
        ):
            _fail("REGISTRY_SCHEMA_INVALID")
        if (
            type(self.operations) not in {list, tuple}
            or len(self.operations) > 128
            or any(type(item) is not str or item not in _OPERATION_CODES for item in self.operations)
        ):
            _fail("REGISTRY_SCHEMA_INVALID")
        object.__setattr__(self, "descriptor", descriptor)
        object.__setattr__(self, "operations", tuple(self.operations))

    def to_dict(self):
        return {
            "version": 1,
            "descriptor": self.descriptor.to_dict(),
            "revision": self.revision,
            "state": self.state,
            "last_code": self.last_code,
            "plan_fingerprint": self.plan_fingerprint,
            "operations": list(self.operations),
        }

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {
            "version",
            "descriptor",
            "revision",
            "state",
            "last_code",
            "plan_fingerprint",
            "operations",
        }:
            _fail("REGISTRY_SCHEMA_INVALID")
        if type(value["version"]) is not int or value["version"] != 1 or type(value["operations"]) is not list:
            _fail("REGISTRY_SCHEMA_INVALID")
        try:
            descriptor = dev_instance_plan.InstanceDescriptor.from_dict(value["descriptor"])
        except Exception:
            _fail("REGISTRY_DESCRIPTOR_UNVERIFIED")
        return cls(
            descriptor,
            value["revision"],
            value["state"],
            value["last_code"],
            value["plan_fingerprint"],
            tuple(value["operations"]),
        )


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    entries: tuple[RegistryEntry, ...] = ()
    codes: tuple[str, ...] = ()

    def __post_init__(self):
        if (
            type(self.entries) not in {list, tuple}
            or len(self.entries) > 128
            or any(type(entry) is not RegistryEntry for entry in self.entries)
        ):
            _fail("REGISTRY_SCHEMA_INVALID")
        if (
            type(self.codes) not in {list, tuple}
            or len(self.codes) > len(_REGISTRY_CODES)
            or any(type(code) is not str or code not in _REGISTRY_CODES for code in self.codes)
        ):
            _fail("REGISTRY_SCHEMA_INVALID")
        if self.entries and self.codes:
            _fail("REGISTRY_SCHEMA_INVALID")
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(self, "codes", tuple(self.codes))


class InstanceRegistry:
    MAX_RECORDS = 128

    def __init__(self, root, *, anchor, repository_id=None):
        self.root, self.anchor = Path(root).absolute(), Path(anchor).absolute()
        self.repository_id = repository_id

    def _root(self):
        try:
            if not self.root.exists() and not self.root.is_symlink():
                dev_private.validate_parent(self.root / "registry-record", self.anchor, allow_missing=True)
                _fail("REGISTRY_MISSING")
            dev_private.validate_parent(self.root / "registry-record", self.anchor)
            return _private(self.root, directory=True)
        except FileNotFoundError:
            _fail("REGISTRY_MISSING")
        except RegistryError:
            raise
        except Exception:
            _fail("REGISTRY_ACCESS_UNVERIFIED")

    def _read(self, path):
        try:
            before = _private(path)
            raw = dev_environment.bounded_read_bytes(path, 262144)
            if _stamp(before) != _stamp(_private(path)):
                _fail("REGISTRY_CHANGED_DURING_READ")
            entry = RegistryEntry.from_dict(json.loads(raw, object_pairs_hook=_json_object))
            if self.repository_id is not None and entry.descriptor.repository_id != self.repository_id:
                _fail("REGISTRY_REPOSITORY_MISMATCH")
            if path.name != _uuid(entry.descriptor.instance_id) + ".json":
                _fail("REGISTRY_ID_MISMATCH")
            return entry
        except RegistryError:
            raise
        except Exception:
            _fail("REGISTRY_RECORD_UNVERIFIED")

    def read(self):
        """Atomic record reads; no lock, mkdir, cleanup or adoption."""
        try:
            root_identity = _stamp(self._root())
            paths = []
            with os.scandir(self.root) as iterator:
                for index, item in enumerate(iterator):
                    if index >= self.MAX_RECORDS + 1:
                        _fail("REGISTRY_LIMIT_REQUIRED")
                    paths.append(self.root / item.name)
            entries = []
            for path in sorted(paths):
                if path.name == ".registry.lock":
                    if _private(path).st_size != 1:
                        _fail("REGISTRY_LOCK_UNVERIFIED")
                    continue
                if not re.fullmatch(r"[0-9a-f-]{36}\.json", path.name):
                    _fail("REGISTRY_UNKNOWN_ARTIFACT")
                _uuid(path.stem)
                if len(entries) >= self.MAX_RECORDS:
                    _fail("REGISTRY_LIMIT_REQUIRED")
                entries.append(self._read(path))
            if _stamp(self._root()) != root_identity:
                _fail("REGISTRY_CHANGED_DURING_READ")
            worktrees = [entry.descriptor.worktree_id for entry in entries]
            if len(set(worktrees)) != len(worktrees):
                _fail("REGISTRY_WORKTREE_CONFLICT")
            return RegistrySnapshot(tuple(entries))
        except RegistryError as error:
            return RegistrySnapshot(codes=(error.code,))
        except Exception:
            return RegistrySnapshot(codes=("REGISTRY_INSPECTION_FAILED",))

    @contextmanager
    def _lock(self):
        """Explicit writer path only. Never unlink the shared lock inode."""
        root_identity = _identity(self._root())
        anchor_identity = _identity(self.anchor.lstat())
        path = self.root / ".registry.lock"
        if not path.exists():
            try:
                dev_private.create_private_file(path, b"\0")
            except dev_private.PrivateFileError:
                if not path.exists():
                    _fail("REGISTRY_LOCK_UNVERIFIED")
        before = _private(path)
        if before.st_size != 1:
            _fail("REGISTRY_LOCK_UNVERIFIED")
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "r+b") as stream:
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                _fail("REGISTRY_LOCK_UNVERIFIED")
            try:
                if sys.platform == "win32":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                _fail("REGISTRY_BUSY")

            def verify():
                # Directory timestamps change during our own staging/link work.
                # Pin object identities and the original held lock instead.
                if _identity(self._root()) != root_identity or _identity(self.anchor.lstat()) != anchor_identity:
                    _fail("REGISTRY_LOCK_UNVERIFIED")
                current_lock = _private(path)
                held_lock = os.fstat(stream.fileno())
                if (
                    _identity(current_lock) != _identity(before)
                    or _identity(held_lock) != _identity(before)
                    or current_lock.st_size != 1
                    or held_lock.st_size != 1
                ):
                    _fail("REGISTRY_LOCK_UNVERIFIED")

            verify()
            yield verify
            verify()

    def publish(self, entry, *, expected_revision):
        """CAS of known public metadata after explicit registry-write approval.

        Callers must validate the current authoritative worktree and plan before
        entering this writer. No resource operation or privilege follows a write.
        A failed atomic publication leaves its private staging file for review.
        """
        publication = {"started": False}
        try:
            return self._publish(entry, expected_revision=expected_revision, publication=publication)
        except RegistryError:
            if publication["started"]:
                _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
            raise
        except Exception:
            _fail("REGISTRY_PUBLICATION_UNCONFIRMED")

    def _publish(self, entry, *, expected_revision, publication):
        if type(entry) is not RegistryEntry:
            _fail("REGISTRY_SCHEMA_INVALID")
        entry = RegistryEntry.from_dict(entry.to_dict())
        if self.repository_id is not None and entry.descriptor.repository_id != self.repository_id:
            _fail("REGISTRY_REPOSITORY_MISMATCH")
        if type(expected_revision) is not int or not 0 <= expected_revision < 2147483647:
            _fail("REGISTRY_REVISION_REQUIRED")
        with self._lock() as verify:
            snapshot = self.read()
            if snapshot.codes:
                _fail(snapshot.codes[0])
            existing = next(
                (item for item in snapshot.entries if item.descriptor.instance_id == entry.descriptor.instance_id), None
            )
            if (existing.revision if existing else 0) != expected_revision or entry.revision != expected_revision + 1:
                _fail("REGISTRY_REVISION_CHANGED")
            if existing is None and len(snapshot.entries) >= self.MAX_RECORDS:
                _fail("REGISTRY_LIMIT_REQUIRED")
            if existing and (
                existing.descriptor.repository_id != entry.descriptor.repository_id
                or existing.descriptor.worktree_id != entry.descriptor.worktree_id
            ):
                _fail("REGISTRY_OWNERSHIP_UNVERIFIED")
            if existing and entry.operations[: len(existing.operations)] != existing.operations:
                _fail("REGISTRY_JOURNAL_CHANGED")
            for other in snapshot.entries:
                if existing and other.descriptor.instance_id == existing.descriptor.instance_id:
                    continue
                if other.descriptor.worktree_id == entry.descriptor.worktree_id:
                    _fail("REGISTRY_WORKTREE_CONFLICT")
                if set(other.descriptor.ports.values()) & set(entry.descriptor.ports.values()):
                    _fail("REGISTRY_PORT_CONFLICT")
            destination = self.root / (_uuid(entry.descriptor.instance_id) + ".json")
            expected_stamp = _stamp(_private(destination)) if existing else None
            if existing and self._read(destination) != existing:
                _fail("REGISTRY_REVISION_CHANGED")
            staging = self.root / (".pending-" + uuid4().hex + ".json")
            payload = json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
            verify()
            dev_private.create_private_file(staging, payload)
            verify()
            stage_info = _private(staging)
            if dev_environment.bounded_read_bytes(staging, 262144) != payload or _stamp(_private(staging)) != _stamp(
                stage_info
            ):
                _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
            # Recheck all identities immediately before changing a known record.
            verify()
            if existing:
                if (
                    _stamp(_private(destination)) != expected_stamp
                    or self._read(destination) != existing
                    or _stamp(_private(destination)) != expected_stamp
                ):
                    _fail("REGISTRY_REVISION_CHANGED")
            elif destination.exists():
                _fail("REGISTRY_REVISION_CHANGED")
            verify()
            if existing:
                publication["started"] = True
                os.replace(staging, destination)
            else:
                # Atomic create-only publication; never replace an unexpected
                # destination appearing after the preceding observations.
                try:
                    os.link(staging, destination, follow_symlinks=False)
                except FileExistsError:
                    _fail("REGISTRY_REVISION_CHANGED")
                publication["started"] = True
                try:
                    verify()
                    stage_link = _private(staging, links=2)
                    destination_link = _private(destination, links=2)
                    if (
                        _identity(stage_link) != _identity(stage_info)
                        or _identity(destination_link) != _identity(stage_info)
                        or _stamp(stage_link) != _stamp(destination_link)
                        or stage_link.st_size != stage_info.st_size
                        or stage_link.st_mtime_ns != stage_info.st_mtime_ns
                    ):
                        _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
                    verify()
                    if _stamp(_private(staging, links=2)) != _stamp(stage_link):
                        _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
                    os.unlink(staging)  # Only our exact, just-reverified stage.
                except Exception:
                    # The destination may already be visible. Never remove it
                    # as rollback or delete any unverified staging replacement.
                    _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
            try:
                verify()
                if _identity(_private(destination)) != _identity(stage_info) or self._read(destination) != entry:
                    _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
            except Exception:
                _fail("REGISTRY_PUBLICATION_UNCONFIRMED")
        return entry
