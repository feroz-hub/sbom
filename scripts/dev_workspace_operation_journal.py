"""Protected append-only operation bookkeeping, never provider/Native authority.

Storage must already be explicitly prepared. Reads create nothing. A reservation
requires separate exact-category operator consent; it does not approve a resource,
database, enrollment or process operation. A new object cannot adopt an existing
claim, even if its caller supplies matching JSON. Pending/uncertain histories are
retained and block new work until independent reconciliation; no repair/delete or
automatic replay is implemented. Hash chains detect inconsistency, not a hostile
same-user writer. Request/path-derived binding hashes stay private and are omitted
from public summaries, along with claim tags and private filesystem paths.
"""

from __future__ import annotations

import ctypes as ct
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID, uuid4

if __package__:
    from . import dev_environment, dev_instance_registry, dev_private
    from . import dev_workspace_database_prepare as database
    from . import dev_workspace_dependencies as dependencies
    from . import dev_workspace_engine as engine
else:
    import dev_environment
    import dev_instance_registry
    import dev_private
    import dev_workspace_database_prepare as database
    import dev_workspace_dependencies as dependencies
    import dev_workspace_engine as engine

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE = re.compile(r"([0-9a-f-]{36})\.([0-9]{6})\.json\Z")
_CATEGORIES = {
    ("engine", "create"): "provider-resources",
    ("database", "initdb"): "database-initialization",
    ("database", "database"): "database-role-schema",
    ("database", "migrate"): "migrations",
}
_STAGES = {
    "create": ("create-network", "create-postgres", "create-redis", "create-mailpit"),
    "initdb": ("create-initdb-helper", "run-initdb-helper"),
    "database": (
        "begin-roles",
        "create-owner",
        "create-runtime",
        "commit-roles",
        "create-database",
        "begin-schema",
        "prepare-schema",
        "runtime-credential",
        "runtime-login",
        "commit-schema",
    ),
    "migrate": ("begin-migration", "migration-owner", "apply-migration", "runtime-grants", "commit-migration"),
}
_CODES = frozenset(
    {
        "JOURNAL_INPUT_INVALID",
        "JOURNAL_STORAGE_MISSING",
        "JOURNAL_ACCESS_UNVERIFIED",
        "JOURNAL_STORAGE_APPROVAL_REQUIRED",
        "JOURNAL_BINDING_CHANGED",
        "JOURNAL_CLAIM_REQUIRED",
        "JOURNAL_REPLAY_BLOCKED",
        "JOURNAL_UNRESOLVED_OPERATION",
        "JOURNAL_HISTORY_UNVERIFIED",
        "JOURNAL_UNKNOWN_ARTIFACT",
        "JOURNAL_INTERRUPTED_WRITE",
        "JOURNAL_BUSY",
        "JOURNAL_REVISION_CHANGED",
        "JOURNAL_SEQUENCE_INVALID",
        "JOURNAL_PUBLICATION_UNCONFIRMED",
        "JOURNAL_DURABILITY_UNCONFIRMED",
        "JOURNAL_OBSERVED",
    }
)
_COMMON = frozenset(
    {
        "version",
        "instance_id",
        "repository_id",
        "worktree_id",
        "provider_fingerprint",
        "operation_id",
        "kind",
        "action",
        "category",
        "request_binding",
        "claim_tag",
        "cluster_id",
        "initial_oids",
        "expected_heads",
    }
)


class JournalError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "JOURNAL_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise JournalError(code) from None


def _uuid(value):
    try:
        if type(value) is not str or str(UUID(value)) != value:
            _fail("JOURNAL_INPUT_INVALID")
        return value
    except Exception:
        _fail("JOURNAL_INPUT_INVALID")


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("JOURNAL_INPUT_INVALID")
    return value


def _public_id(value):
    return _hash(value) if type(value) is str and _HASH.fullmatch(value) else _uuid(value)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReservationConsent:
    """Explicit operator permission for bookkeeping only; not resource authority."""

    instance_id: str
    operation_id: str
    category: str
    request_binding: str = field(repr=False)

    def __post_init__(self):
        _uuid(self.instance_id)
        _uuid(self.operation_id)
        _hash(self.request_binding)
        if type(self.category) is not str or self.category not in _CATEGORIES.values():
            _fail("JOURNAL_STORAGE_APPROVAL_REQUIRED")


@dataclass(frozen=True, slots=True)
class OperationView:
    operation_id: str
    kind: str
    action: str
    category: str
    revision: int
    state: str
    stages: tuple[str, ...]
    receipts: tuple[tuple[str, str, str | int], ...]
    outcome_code: str | None
    unconfirmed_helper_ids: tuple[str, ...] = ()
    cleanup_verified: bool | None = None

    def __post_init__(self):
        _uuid(self.operation_id)
        if (
            type(self.kind) is not str
            or type(self.action) is not str
            or (self.kind, self.action) not in _CATEGORIES
            or self.category != _CATEGORIES[(self.kind, self.action)]
            or type(self.revision) is not int
            or not 1 <= self.revision <= 128
            or type(self.state) is not str
            or self.state not in {"COMPLETED", "UNCONFIRMED", "PENDING"}
            or type(self.stages) is not tuple
            or any(
                type(value) is not str or value not in {*_STAGES[self.action], "start-preparation-server"}
                for value in self.stages
            )
            or type(self.receipts) is not tuple
            or len(self.receipts) > 6
            or type(self.unconfirmed_helper_ids) is not tuple
            or len(self.unconfirmed_helper_ids) > 2048
            or len(set(self.unconfirmed_helper_ids)) != len(self.unconfirmed_helper_ids)
            or self.cleanup_verified is not None
            and type(self.cleanup_verified) is not bool
            or self.unconfirmed_helper_ids
            and (self.cleanup_verified is not False or self.state == "COMPLETED")
            or self.outcome_code is not None
            and (
                type(self.outcome_code) is not str
                or self.outcome_code not in (engine._CODES if self.kind == "engine" else database._CODES)
            )
        ):
            _fail("JOURNAL_INPUT_INVALID")
        for value in self.unconfirmed_helper_ids:
            _hash(value)
        for item in self.receipts:
            if (
                type(item) is not tuple
                or len(item) != 3
                or type(item[0]) is not str
                or item[0]
                not in {"network", "container", "volume", "initdb-helper", "cluster", "owner", "runtime", "database"}
                or type(item[1]) is not str
                or re.fullmatch(
                    r"(?:sbom-dev-[0-9a-f]{32}-(?:network|postgres|redis|mailpit|postgres-data|redis-data)|initdb-helper|cluster|owner|runtime|database)",
                    item[1],
                )
                is None
            ):
                _fail("JOURNAL_INPUT_INVALID")
            if item[0] in {"owner", "runtime", "database"}:
                if type(item[2]) is not int or not 0 < item[2] < 2**32:
                    _fail("JOURNAL_INPUT_INVALID")
            else:
                _hash(item[2])

    def to_dict(self):
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "action": self.action,
            "category": self.category,
            "revision": self.revision,
            "state": self.state,
            "stages": list(self.stages),
            "receipts": [{"kind": kind, "reference": name, "object_id": value} for kind, name, value in self.receipts],
            "outcome_code": self.outcome_code,
            "unconfirmed_helper_ids": list(self.unconfirmed_helper_ids),
            "cleanup_verified": self.cleanup_verified,
            "resource_ownership_verified": False,
        }


@dataclass(frozen=True, slots=True)
class JournalSummary:
    status: str
    code: str
    operations: tuple[OperationView, ...] = ()

    def __post_init__(self):
        if (
            type(self.status) is not str
            or self.status not in {"OBSERVED", "BLOCKED", "SKIPPED"}
            or type(self.code) is not str
            or self.code not in _CODES
            or type(self.operations) is not tuple
            or len(self.operations) > 128
            or any(type(item) is not OperationView for item in self.operations)
        ):
            _fail("JOURNAL_INPUT_INVALID")

    def to_dict(self):
        return {
            "status": self.status,
            "code": self.code,
            "operations": [item.to_dict() for item in self.operations],
            "runtime_verified": False,
            "live_authorized": False,
            "recovery_is_read_only": True,
            "guidance": "Preserve all operation files; uncertain operations require independent review.",
        }


def _binding(request, consent=None):
    if type(request) is engine.EngineActionPlan and request.consent.action == "create" and consent is None:
        descriptor = request.provider.descriptor
        kind, action, operation, public = "engine", "create", request.consent.operation_id, request.provider.fingerprint
        cluster, oids, heads = None, [], []
    elif type(request) is database.PreparationPlan and type(consent) is database.Consent:
        if (consent.action, consent.plan_fingerprint, consent.confirm_database) != (
            request.action,
            request.fingerprint,
            request.target.database,
        ):
            _fail("JOURNAL_BINDING_CHANGED")
        descriptor = request.provider_plan.descriptor
        kind, action, operation, public = (
            "database",
            request.action,
            consent.operation_id,
            request.provider_plan.fingerprint,
        )
        cluster = request.prior.cluster_id if request.prior else None
        oids = [list(item) for item in request.prior.object_oids] if request.prior else []
        heads = list(request.migration.heads) if request.migration else []
    else:
        _fail("JOURNAL_INPUT_INVALID")
    return {
        "version": 1,
        "instance_id": descriptor.instance_id,
        "repository_id": descriptor.repository_id,
        "worktree_id": descriptor.worktree_id,
        "provider_fingerprint": public,
        "operation_id": operation,
        "kind": kind,
        "action": action,
        "category": _CATEGORIES[(kind, action)],
        "request_binding": request.fingerprint,
        "cluster_id": cluster,
        "initial_oids": oids,
        "expected_heads": heads,
    }


def _events(records):
    return [item["event"] for item in records]


def _receipts(events):
    return {(item["kind"], item["reference"]): item["object_id"] for item in events if item["type"] == "RECEIPT"}


def _sequence(common, events, event):
    """Validate exact protocol order; no inference from names about ownership."""
    if events and events[-1]["type"] == "OUTCOME":
        _fail("JOURNAL_REPLAY_BLOCKED")
    if type(event) is not dict or type(event.get("type")) is not str:
        _fail("JOURNAL_SEQUENCE_INVALID")
    kind, action = common["kind"], common["action"]
    stages = [value["stage"] for value in events if value["type"] == "INTENT"]
    receipts = _receipts(events)
    token = UUID(common["instance_id"]).hex
    prefix = "sbom-dev-" + token
    if event["type"] == "RESERVE":
        if events or set(event) != {"type"}:
            _fail("JOURNAL_SEQUENCE_INVALID")
        return
    if not events or events[0] != {"type": "RESERVE"}:
        _fail("JOURNAL_CLAIM_REQUIRED")
    if event["type"] == "INTENT":
        if set(event) != {"type", "stage"} or type(event["stage"]) is not str:
            _fail("JOURNAL_SEQUENCE_INVALID")
        actual = [*stages, event["stage"]]
        if action in {"database", "migrate"} and actual[0] == "start-preparation-server":
            actual = actual[1:]
        if actual != list(_STAGES[action][: len(actual)]):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if kind == "engine" and len(stages) > 0:
            previous = stages[-1]
            reference = prefix + (
                "-network" if previous == "create-network" else "-" + previous.removeprefix("create-")
            )
            if ("network" if previous == "create-network" else "container", reference) not in receipts:
                _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            action == "initdb"
            and event["stage"] == "run-initdb-helper"
            and ("initdb-helper", "initdb-helper") not in receipts
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            action == "database"
            and event["stage"] == "create-database"
            and not {("owner", "owner"), ("runtime", "runtime")} <= receipts.keys()
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if action == "database" and event["stage"] == "begin-schema" and ("database", "database") not in receipts:
            _fail("JOURNAL_SEQUENCE_INVALID")
    elif event["type"] == "RECEIPT":
        if (
            set(event) != {"type", "kind", "reference", "object_id"}
            or any(type(event[key]) is not str for key in ("kind", "reference"))
            or not stages
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        receipt_kind, reference, value = event["kind"], event["reference"], event["object_id"]
        if (receipt_kind, reference) in receipts:
            _fail("JOURNAL_REPLAY_BLOCKED")
        if kind == "engine":
            _hash(value)
            wanted = {
                ("network", prefix + "-network"): "create-network",
                **{("container", prefix + "-" + name): "create-" + name for name in ("postgres", "redis", "mailpit")},
                ("volume", prefix + "-postgres-data"): "create-mailpit",
                ("volume", prefix + "-redis-data"): "create-mailpit",
            }
            if (receipt_kind, reference) not in wanted or stages[-1] != wanted[(receipt_kind, reference)]:
                _fail("JOURNAL_SEQUENCE_INVALID")
            if receipt_kind == "volume" and not all(
                ("container", prefix + "-" + name) in receipts for name in ("postgres", "redis", "mailpit")
            ):
                _fail("JOURNAL_SEQUENCE_INVALID")
            if any(old == value for (old_kind, _), old in receipts.items() if old_kind == receipt_kind):
                _fail("JOURNAL_REPLAY_BLOCKED")
        elif action == "initdb":
            _hash(value)
            if (
                reference != receipt_kind
                or {"initdb-helper": "create-initdb-helper", "cluster": "run-initdb-helper"}.get(receipt_kind)
                != stages[-1]
            ):
                _fail("JOURNAL_SEQUENCE_INVALID")
        elif action == "database":
            if (
                type(value) is not int
                or not 0 < value < 2**32
                or reference != receipt_kind
                or {"owner": "commit-roles", "runtime": "commit-roles", "database": "create-database"}.get(receipt_kind)
                != stages[-1]
            ):
                _fail("JOURNAL_SEQUENCE_INVALID")
        else:
            _fail("JOURNAL_SEQUENCE_INVALID")
    elif event["type"] == "OUTCOME":
        if (
            set(event)
            != {"type", "code", "completed", "oids", "cluster_id", "heads", "unconfirmed_helpers", "cleanup_verified"}
            or type(event["code"]) is not str
            or event["code"] not in (engine._CODES if kind == "engine" else database._CODES)
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if type(event["completed"]) is not list or any(type(value) is not str for value in event["completed"]):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            type(event["oids"]) is not list
            or type(event["heads"]) is not list
            or len(event["oids"]) > 3
            or len(event["heads"]) > 8
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if event["cluster_id"] is not None:
            _hash(event["cluster_id"])
        expected = list(_STAGES[action])
        actual = stages[1:] if stages[:1] == ["start-preparation-server"] else stages
        success = event["code"] in {"ENGINE_ACTION_COMPLETED", "DB_PREPARATION_COMPLETED"}
        helpers, cleanup = event["unconfirmed_helpers"], event["cleanup_verified"]
        if (
            type(helpers) is not list
            or len(helpers) > 2048
            or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in helpers)
            or len(set(helpers)) != len(helpers)
            or (cleanup is not None and type(cleanup) is not bool)
            or kind == "engine"
            and (helpers or cleanup is not None)
            or kind == "database"
            and type(cleanup) is not bool
            or helpers
            and cleanup is not False
            or success
            and kind == "database"
            and (helpers or cleanup is not True)
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if success and actual != expected:
            _fail("JOURNAL_SEQUENCE_INVALID")
        if kind == "engine":
            if success and (
                len(receipts) != 6
                or event["completed"]
                != [receipts.get(("container", prefix + "-" + name)) for name in ("postgres", "redis", "mailpit")]
            ):
                _fail("JOURNAL_SEQUENCE_INVALID")
            if any(value not in receipts.values() for value in event["completed"]):
                _fail("JOURNAL_SEQUENCE_INVALID")
        elif event["completed"] != stages[: len(event["completed"])]:
            _fail("JOURNAL_SEQUENCE_INVALID")
        if success and kind == "database" and event["completed"] != stages:
            _fail("JOURNAL_SEQUENCE_INVALID")
        if not success and (event["oids"] or event["heads"] or event["cluster_id"] is not None):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            success
            and action == "initdb"
            and (event["cluster_id"] != receipts.get(("cluster", "cluster")) or len(receipts) != 2)
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            success
            and action == "database"
            and (
                event["oids"] != [[name, receipts.get((name, name))] for name in ("owner", "runtime", "database")]
                or len(receipts) != 3
            )
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if (
            success
            and action == "migrate"
            and (event["oids"] != common["initial_oids"] or event["heads"] != common["expected_heads"])
        ):
            _fail("JOURNAL_SEQUENCE_INVALID")
        if success and action in {"database", "migrate"} and event["cluster_id"] != common["cluster_id"]:
            _fail("JOURNAL_SEQUENCE_INVALID")
    else:
        _fail("JOURNAL_SEQUENCE_INVALID")


def _move_private(source, destination):
    """Same-directory atomic create-only publication; no rollback/deletion."""
    if os.name != "nt":
        dependencies._publish_directory(source, destination)
        descriptor = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    function = ct.WinDLL("kernel32", use_last_error=True).MoveFileExW
    function.argtypes, function.restype = [ct.c_wchar_p, ct.c_wchar_p, ct.c_uint32], ct.c_int32
    # WRITE_THROUGH; never REPLACE_EXISTING/COPY_ALLOWED/DELAY_UNTIL_REBOOT.
    if not function(str(source), str(destination), 0x8):
        _fail("JOURNAL_PUBLICATION_UNCONFIRMED")


class OperationJournal:
    MAX_FILES, MAX_OPERATIONS, MAX_REVISIONS = 4096, 128, 128

    def __init__(self, *, home, instance_id):
        self.instance_id = _uuid(instance_id)
        self.home = Path(home)
        if not self.home.is_absolute():
            _fail("JOURNAL_INPUT_INVALID")
        self.root = self.home / ".sbom-dev" / "instances" / instance_id / "operations"
        self._store = dev_instance_registry.InstanceRegistry(self.root, anchor=self.home)
        self._approval = self._bound = self._last = None
        self._database_consent = None
        self._verify_step = 0
        self._pins = None
        self._uncertain = False

    def arm(self, approval):
        """Memory-only exact storage consent before DBExecutor calls claim()."""
        if (
            type(approval) is not ReservationConsent
            or approval.instance_id != self.instance_id
            or self._bound is not None
        ):
            _fail("JOURNAL_STORAGE_APPROVAL_REQUIRED")
        self._approval = approval
        return self

    def _scan(self, *, recovery=False):
        before = dev_instance_registry._stamp(self._store._root())
        paths, issue = [], None
        with os.scandir(self.root) as items:
            for index, item in enumerate(items):
                if index >= self.MAX_FILES:
                    _fail("JOURNAL_HISTORY_UNVERIFIED")
                path = self.root / item.name
                if item.name == ".registry.lock":
                    if dev_instance_registry._private(path).st_size != 1:
                        _fail("JOURNAL_ACCESS_UNVERIFIED")
                    continue
                if item.name.startswith(".pending-journal-"):
                    if not recovery:
                        _fail("JOURNAL_INTERRUPTED_WRITE")
                    issue = "JOURNAL_INTERRUPTED_WRITE"
                    continue
                match = _FILE.fullmatch(item.name)
                if match is None:
                    if not recovery:
                        _fail("JOURNAL_UNKNOWN_ARTIFACT")
                    issue = issue or "JOURNAL_UNKNOWN_ARTIFACT"
                    continue
                _uuid(match[1])
                paths.append(path)
        groups = {}
        for path in sorted(paths):
            info = dev_instance_registry._private(path)
            raw = dev_environment.bounded_read_bytes(path, 16384)
            if dev_instance_registry._stamp(dev_instance_registry._private(path)) != dev_instance_registry._stamp(info):
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            value = json.loads(raw, object_pairs_hook=dev_instance_registry._json_object)
            if type(value) is not dict or set(value) != _COMMON | {"revision", "previous", "event", "digest"}:
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            _uuid(value["operation_id"])
            _uuid(value["claim_tag"])
            _public_id(value["repository_id"])
            _public_id(value["worktree_id"])
            for key in ("provider_fingerprint", "request_binding", "digest"):
                _hash(value[key])
            if (
                type(value["initial_oids"]) is not list
                or len(value["initial_oids"]) > 3
                or any(
                    type(item) is not list
                    or len(item) != 2
                    or type(item[0]) is not str
                    or item[0] not in {"owner", "runtime", "database"}
                    or type(item[1]) is not int
                    or not 0 < item[1] < 2**32
                    for item in value["initial_oids"]
                )
                or len({item[0] for item in value["initial_oids"]}) != len(value["initial_oids"])
                or type(value["expected_heads"]) is not list
                or len(value["expected_heads"]) > 8
                or any(
                    type(item) is not str or re.fullmatch(r"[A-Za-z0-9_]{1,128}", item) is None
                    for item in value["expected_heads"]
                )
            ):
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            if value["cluster_id"] is not None:
                _hash(value["cluster_id"])
            if (
                value["version"] != 1
                or type(value["version"]) is not int
                or value["instance_id"] != self.instance_id
                or (value["kind"], value["action"]) not in _CATEGORIES
                or value["category"] != _CATEGORIES[(value["kind"], value["action"])]
                or type(value["revision"]) is not int
                or not 1 <= value["revision"] <= self.MAX_REVISIONS
                or path.name != value["operation_id"] + f".{value['revision']:06d}.json"
            ):
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            body = {key: item for key, item in value.items() if key != "digest"}
            if _digest(body) != value["digest"]:
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            existing = groups.setdefault(value["operation_id"], [])
            if (
                len(groups) > self.MAX_OPERATIONS
                or value["revision"] != len(existing) + 1
                or value["previous"] != (existing[-1]["digest"] if existing else None)
            ):
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            common = {key: value[key] for key in _COMMON}
            if existing and common != {key: existing[0][key] for key in _COMMON}:
                _fail("JOURNAL_HISTORY_UNVERIFIED")
            _sequence(common, _events(existing), value["event"])
            existing.append(value)
        if dev_instance_registry._stamp(self._store._root()) != before:
            _fail("JOURNAL_REVISION_CHANGED")
        return (groups, issue) if recovery else groups

    def read_summary(self):
        """Read-only recovery metadata; no lock creation, adoption or repair."""
        try:
            groups, issue = self._scan(recovery=True)
            views = []
            for operation_id, records in sorted(groups.items()):
                first, last = records[0], records[-1]
                events = _events(records)
                outcome = events[-1] if events[-1]["type"] == "OUTCOME" else None
                code = outcome["code"] if outcome else None
                state = (
                    "COMPLETED"
                    if code in {"ENGINE_ACTION_COMPLETED", "DB_PREPARATION_COMPLETED"}
                    else "UNCONFIRMED"
                    if outcome
                    else "PENDING"
                )
                views.append(
                    OperationView(
                        operation_id,
                        first["kind"],
                        first["action"],
                        first["category"],
                        last["revision"],
                        state,
                        tuple(event["stage"] for event in events if event["type"] == "INTENT"),
                        tuple((kind, name, value) for (kind, name), value in _receipts(events).items()),
                        code,
                        tuple(outcome["unconfirmed_helpers"]) if outcome else (),
                        outcome["cleanup_verified"] if outcome else None,
                    )
                )
            return JournalSummary(
                "BLOCKED" if issue or any(view.state != "COMPLETED" for view in views) else "OBSERVED",
                issue or "JOURNAL_OBSERVED",
                tuple(views),
            )
        except dev_instance_registry.RegistryError as error:
            return JournalSummary(
                "SKIPPED" if error.code == "REGISTRY_MISSING" else "BLOCKED",
                "JOURNAL_STORAGE_MISSING" if error.code == "REGISTRY_MISSING" else "JOURNAL_ACCESS_UNVERIFIED",
            )
        except JournalError as error:
            return JournalSummary("BLOCKED", error.code)
        except Exception:
            return JournalSummary("BLOCKED", "JOURNAL_HISTORY_UNVERIFIED")

    def _owned(self, groups):
        if self._uncertain or self._bound is None or self._last is None:
            _fail("JOURNAL_CLAIM_REQUIRED")
        records = groups.get(self._bound["operation_id"], [])
        if (
            not records
            or {key: records[0][key] for key in _COMMON} != self._bound
            or (records[-1]["revision"], records[-1]["digest"]) != self._last[:2]
        ):
            _fail("JOURNAL_REVISION_CHANGED")
        path = self.root / (self._bound["operation_id"] + f".{self._last[0]:06d}.json")
        if dev_instance_registry._identity(dev_instance_registry._private(path)) != self._last[2]:
            _fail("JOURNAL_REVISION_CHANGED")
        return records

    def _verify_pins(self):
        if self._pins is None:
            _fail("JOURNAL_CLAIM_REQUIRED")
        actual = (
            dev_instance_registry._identity(self._store._root()),
            dev_instance_registry._identity(self.home.lstat()),
            dev_instance_registry._identity(dev_instance_registry._private(self.root / ".registry.lock")),
        )
        if actual != self._pins:
            _fail("JOURNAL_ACCESS_UNVERIFIED")

    def _publish(self, common, records, event, verify):
        _sequence(common, _events(records), event)
        revision = len(records) + 1
        if revision > self.MAX_REVISIONS:
            _fail("JOURNAL_HISTORY_UNVERIFIED")
        body = {**common, "revision": revision, "previous": records[-1]["digest"] if records else None, "event": event}
        value = {**body, "digest": _digest(body)}
        payload = _json(value)
        stage = self.root / (".pending-journal-" + uuid4().hex + ".json")
        destination = self.root / (common["operation_id"] + f".{revision:06d}.json")
        verify()
        with os.scandir(self.root) as items:
            for count, _ in enumerate(items, 1):
                if count >= self.MAX_FILES:
                    _fail("JOURNAL_HISTORY_UNVERIFIED")
        dev_private.validate_parent(stage, self.home)
        dev_private.create_private_file(stage, payload)  # Private from creation; fsync before return.
        info = dev_instance_registry._private(stage)
        verify()
        if dev_environment.bounded_read_bytes(stage, 16384) != payload or dev_instance_registry._stamp(
            dev_instance_registry._private(stage)
        ) != dev_instance_registry._stamp(info):
            _fail("JOURNAL_PUBLICATION_UNCONFIRMED")
        verify()
        _move_private(stage, destination)
        verify()
        final = dev_instance_registry._private(destination)
        if (
            dev_instance_registry._identity(final) != dev_instance_registry._identity(info)
            or dev_environment.bounded_read_bytes(destination, 16384) != payload
        ):
            _fail("JOURNAL_PUBLICATION_UNCONFIRMED")
        self._bound, self._last = common, (revision, value["digest"], dev_instance_registry._identity(final))
        self._pins = (
            dev_instance_registry._identity(self._store._root()),
            dev_instance_registry._identity(self.home.lstat()),
            dev_instance_registry._identity(dev_instance_registry._private(self.root / ".registry.lock")),
        )

    def reserve(self, request, approval, *, consent=None):
        """Explicit new reservation only. Existing claims always remain foreign."""
        common = _binding(request, consent)
        if (
            type(approval) is not ReservationConsent
            or (approval.instance_id, approval.operation_id, approval.category, approval.request_binding)
            != (self.instance_id, common["operation_id"], common["category"], common["request_binding"])
            or common["instance_id"] != self.instance_id
        ):
            _fail("JOURNAL_STORAGE_APPROVAL_REQUIRED")
        if self._bound is not None or self._uncertain:
            return False
        try:
            with self._store._lock() as verify:
                groups = self._scan()
                if common["operation_id"] in groups:
                    return False
                if any(
                    any(
                        records[0][key] != common[key]
                        for key in ("repository_id", "worktree_id", "provider_fingerprint")
                    )
                    for records in groups.values()
                ):
                    _fail("JOURNAL_BINDING_CHANGED")
                if common["action"] != "migrate" and any(
                    (records[0]["kind"], records[0]["action"]) == (common["kind"], common["action"])
                    for records in groups.values()
                ):
                    _fail("JOURNAL_REPLAY_BLOCKED")
                if len(groups) >= self.MAX_OPERATIONS or any(
                    records[-1]["event"].get("code") not in {"ENGINE_ACTION_COMPLETED", "DB_PREPARATION_COMPLETED"}
                    for records in groups.values()
                ):
                    _fail("JOURNAL_UNRESOLVED_OPERATION")
                common = {**common, "claim_tag": str(uuid4())}
                self._publish(common, [], {"type": "RESERVE"}, verify)
                self._database_consent = consent
            return True
        except BaseException:
            self._uncertain = True
            raise JournalError("JOURNAL_PUBLICATION_UNCONFIRMED") from None

    def claim(self, plan, consent):
        if self._approval is None:
            _fail("JOURNAL_STORAGE_APPROVAL_REQUIRED")
        return self.reserve(plan, self._approval, consent=consent)

    def _match(self, request, consent=None):
        current = _binding(request, consent)
        if self._bound is None or any(self._bound[key] != value for key, value in current.items()):
            _fail("JOURNAL_BINDING_CHANGED")

    def verify_reservation(self, request):
        self._match(request)
        try:
            self._verify_pins()
            with self._store._lock() as verify:
                records = self._owned(self._scan())
                expected = (
                    ("RESERVE", None),
                    ("INTENT", "create-network"),
                    ("RECEIPT", "network"),
                    ("RECEIPT", "container"),
                    ("RECEIPT", "container"),
                )
                event = records[-1]["event"]
                if (
                    self._verify_step >= len(expected)
                    or (event["type"], event.get("stage", event.get("kind"))) != expected[self._verify_step]
                ):
                    _fail("JOURNAL_REPLAY_BLOCKED")
                if self._verify_step in {3, 4} and event.get("reference") != "sbom-dev-" + UUID(
                    self.instance_id
                ).hex + ("-postgres" if self._verify_step == 3 else "-redis"):
                    _fail("JOURNAL_SEQUENCE_INVALID")
                verify()
                self._verify_step += 1
        except Exception:
            self._uncertain = True
            _fail("JOURNAL_CLAIM_REQUIRED")

    def _append(self, event):
        try:
            self._verify_pins()
            with self._store._lock() as verify:
                records = self._owned(self._scan())
                self._publish(self._bound, records, event, verify)
        except BaseException:
            self._uncertain = True
            raise JournalError("JOURNAL_PUBLICATION_UNCONFIRMED") from None

    def record_intent(self, request):
        self._match(request)
        records = self._owned(self._scan())
        count = sum(event["type"] == "INTENT" for event in _events(records))
        if count >= len(_STAGES["create"]):
            _fail("JOURNAL_SEQUENCE_INVALID")
        self._append({"type": "INTENT", "stage": _STAGES["create"][count]})

    def record_receipt(self, request, kind, logical_name, object_id):
        self._match(request)
        self._append({"type": "RECEIPT", "kind": kind, "reference": logical_name, "object_id": object_id})

    def _database_match(self, plan):
        if self._bound is None or self._database_consent is None:
            _fail("JOURNAL_CLAIM_REQUIRED")
        self._match(plan, self._database_consent)

    def intent(self, plan, stage):
        self._database_match(plan)
        self._append({"type": "INTENT", "stage": stage})

    def receipt(self, plan, kind, object_id):
        self._database_match(plan)
        self._append({"type": "RECEIPT", "kind": kind, "reference": kind, "object_id": object_id})

    def _outcome(self, code, completed, *, receipt=None, unconfirmed_helpers=(), cleanup_verified=None):
        self._append(
            {
                "type": "OUTCOME",
                "code": code,
                "completed": list(completed),
                "oids": [list(item) for item in receipt.object_oids] if receipt else [],
                "cluster_id": receipt.cluster_id if receipt else None,
                "heads": list(receipt.revisions) if receipt else [],
                "unconfirmed_helpers": list(unconfirmed_helpers),
                "cleanup_verified": cleanup_verified,
            }
        )

    def record_outcome(self, request, outcome):
        self._match(request)
        if type(outcome) is not engine.EngineOutcome:
            _fail("JOURNAL_INPUT_INVALID")
        self._outcome(outcome.code, outcome.completed_ids)

    def outcome(self, plan, outcome):
        self._database_match(plan)
        if type(outcome) is not database.PreparationOutcome:
            _fail("JOURNAL_INPUT_INVALID")
        self._outcome(
            outcome.code,
            outcome.completed,
            receipt=outcome.receipt,
            unconfirmed_helpers=outcome.unconfirmed_helper_ids,
            cleanup_verified=outcome.cleanup_verified,
        )
