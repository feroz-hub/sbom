"""Read-only instance observations; saved ready flags and proposals are not proof.

The canonical Runtime is constructed/loaded but never locked, refreshed, saved,
started or stopped. No configuration resolver/application is imported. Missing
source/HEAD/configuration does not prevent inspection of a protected runtime.
Optional provider/health callbacks must be independently approved read-only,
bounded adapters; their typed input metadata alone grants no permission.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from uuid import UUID

if __package__:
    from . import dev_environment, dev_instance_plan, dev_instance_registry, dev_instance_storage
    from . import dev_workspace_bundle as bundle
    from . import dev_workspace_engine as engine
    from . import dev_workspace_operation_journal as operations
    from . import dev_workspace_runtime as runtime_adapter
else:
    import dev_environment
    import dev_instance_plan
    import dev_instance_registry
    import dev_instance_storage
    import dev_workspace_bundle as bundle
    import dev_workspace_engine as engine
    import dev_workspace_operation_journal as operations
    import dev_workspace_runtime as runtime_adapter

_LOGS = {
    "Celery worker": "celery-worker.log",
    "Celery reports worker": "celery-reports-worker.log",
    "Celery Beat": "celery-beat.log",
    "API": "api.log",
    "Frontend": "frontend.log",
    "Launcher": "setup.log",
    "Runtime": "setup.log",
}
_COMPONENTS = frozenset(_LOGS) | {"Bundle", "Operation journal", "Providers", "Health", "Source", "Controller"}
_LEVELS = frozenset({"PASS", "WARN", "FAIL", "BLOCKED", "SKIPPED"})
_STATUSES = frozenset({"RUNNING", "STOPPED", "UNKNOWN", "PARTIAL"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WINERRORS = frozenset({2, 3, 5, 6, 8, 14, 18, 32, 33, 80, 87, 122, 183, 206, 234, 258, 299, 995, 1168, 1460})
_CODES = frozenset(
    {
        "INSPECT_INPUT_INVALID",
        "RUNTIME_PRIVATE_LOCATION_REQUIRED",
        "RUNTIME_STATE_ABSENT",
        "RUNTIME_STATE_UNVERIFIED",
        "RUNTIME_BINDING_MISMATCH",
        "RUNTIME_STATE_CHANGED",
        "PROCESS_RUNNING",
        "PROCESS_STOPPED",
        "PROCESS_PARTIAL",
        "PROCESS_IDENTITY_MISMATCH",
        "PROCESS_IDENTITY_UNVERIFIED",
        "PROCESS_GROUP_INSPECTION_REQUIRED",
        "PROCESS_RECORD_INCOMPLETE",
        "LAUNCHER_EXITED",
        "COMPONENT_RECORD_MISSING",
        "RUNTIME_RUNNING",
        "RUNTIME_STOPPED",
        "RUNTIME_PARTIAL",
        "RUNTIME_UNKNOWN",
        "JOURNAL_NOT_SELECTED",
        "JOURNAL_HISTORY_OBSERVED",
        "JOURNAL_REVIEW_REQUIRED",
        "BUNDLE_EXPECTED_RECEIPT_REQUIRED",
        "BUNDLE_CONTEXT_REQUIRED",
        "BUNDLE_FILES_UNCHANGED",
        "BUNDLE_FILES_UNVERIFIED",
        "PROVIDER_NOT_ALLOCATED",
        "PROVIDER_READ_ADAPTER_REQUIRED",
        "PROVIDER_RECORDED_IDENTITIES_REQUIRED",
        "PROVIDER_INSPECTION_OBSERVED",
        "PROVIDER_INSPECTION_UNVERIFIED",
        "READINESS_ADAPTER_REQUIRED",
        "READINESS_RUNTIME_REQUIRED",
        "READINESS_OBSERVED",
        "READINESS_UNVERIFIED",
        "SOURCE_DRIFT_NOT_CHECKED",
        "SOURCE_HEAD_CHANGED",
        "SOURCE_HEAD_UNCHANGED",
        "CONTROLLER_DRIFT_NOT_CHECKED",
        "CONTROLLER_CHANGED",
        "CONTROLLER_UNCHANGED",
    }
)


class InspectionError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "INSPECT_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise InspectionError(code) from None


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("INSPECT_INPUT_INVALID")


def _pid(value):
    return type(value) is int and 0 < value <= 0xFFFFFFFF


def _recommendation(code):
    if code.startswith("PROCESS_") or code in {
        "LAUNCHER_EXITED",
        "COMPONENT_RECORD_MISSING",
        "RUNTIME_PARTIAL",
        "RUNTIME_UNKNOWN",
    }:
        return "Preserve runtime records; use the instance's verified-ownership stop command or inspect its local log."
    if code.startswith("RUNTIME_"):
        return "Preserve state; verify the private instance location and recorded workspace binding."
    if code.startswith("BUNDLE_"):
        return "Use the protected controller's expected bundle receipt; do not adopt or regenerate an unknown bundle."
    if code.startswith("PROVIDER_"):
        return "Use an approved read-only engine adapter and recorded creation identities; do not adopt by names or labels."
    if code.startswith("READINESS_"):
        return "Run independently approved API, IAM, worker and verified HTTPS observations for this runtime."
    if code.startswith("JOURNAL_"):
        return "Preserve all operation files; interrupted or uncertain work needs independent review."
    return "Review the reported source/controller drift separately from runtime ownership."


def _set_row(rows, diagnostic):
    for index, row in enumerate(rows):
        if row.component == diagnostic.component:
            rows[index] = diagnostic
            return
    rows.append(diagnostic)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    component: str
    result: str
    code: str
    process_status: str | None = None
    pid: int | None = None
    winerror: int | None = None
    log_path: Path | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.component) is not str
            or self.component not in _COMPONENTS
            or type(self.result) is not str
            or self.result not in _LEVELS
            or type(self.code) is not str
            or self.code not in _CODES
        ):
            _fail("INSPECT_INPUT_INVALID")
        if (
            self.process_status is not None
            and (type(self.process_status) is not str or self.process_status not in _STATUSES)
            or self.pid is not None
            and not _pid(self.pid)
            or self.winerror is not None
            and (type(self.winerror) is not int or self.winerror not in _WINERRORS)
        ):
            _fail("INSPECT_INPUT_INVALID")
        if self.log_path is not None and (
            not isinstance(self.log_path, Path)
            or not self.log_path.is_absolute()
            or self.component not in _LOGS
            or self.log_path.name != _LOGS[self.component]
            or self.log_path.parent.name != ".dev-logs"
        ):
            _fail("INSPECT_INPUT_INVALID")

    def to_dict(self):
        return {
            "component": self.component,
            "result": self.result,
            "code": self.code,
            "process_status": self.process_status,
            "pid": self.pid,
            "winerror": self.winerror,
            "log_path": str(self.log_path) if self.log_path else None,
            "recommendation": _recommendation(self.code),
        }


@dataclass(frozen=True, slots=True)
class ProviderAttestation:
    """Bound read context from an approved controller; not self-authentication."""

    reference: str
    instance_id: str
    engine_identity: str
    provider_fingerprint: str
    container_ids: tuple[str, ...]

    def __post_init__(self):
        _hash(self.reference)
        try:
            if type(self.instance_id) is not str or str(UUID(self.instance_id)) != self.instance_id:
                _fail("INSPECT_INPUT_INVALID")
        except Exception:
            _fail("INSPECT_INPUT_INVALID")
        _hash(self.engine_identity)
        _hash(self.provider_fingerprint)
        if (
            type(self.container_ids) is not tuple
            or len(self.container_ids) != 3
            or any(type(value) is not str for value in self.container_ids)
            or len(set(self.container_ids)) != 3
        ):
            _fail("INSPECT_INPUT_INVALID")
        for value in self.container_ids:
            _hash(value)


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    attestation: ProviderAttestation = field(repr=False)
    process_status: str

    def __post_init__(self):
        if (
            type(self.attestation) is not ProviderAttestation
            or type(self.process_status) is not str
            or self.process_status not in _STATUSES
        ):
            _fail("INSPECT_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class ReadinessObservation:
    runtime_token: str = field(repr=False)
    pids: tuple[int, ...]
    passed: tuple[str, ...]

    def __post_init__(self):
        if (
            type(self.runtime_token) is not str
            or re.fullmatch(r"[0-9a-f]{32}", self.runtime_token) is None
            or type(self.pids) is not tuple
            or any(not _pid(value) for value in self.pids)
            or len(set(self.pids)) != len(self.pids)
            or type(self.passed) is not tuple
            or any(type(value) is not str or value not in {"api", "iam", "https", "workers"} for value in self.passed)
            or len(set(self.passed)) != len(self.passed)
        ):
            _fail("INSPECT_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class InspectionReport:
    process_status: str
    diagnostics: tuple[Diagnostic, ...]
    readiness_verified: bool = False
    operation_summary: operations.JournalSummary | None = None

    def __post_init__(self):
        if (
            type(self.process_status) is not str
            or self.process_status not in _STATUSES
            or type(self.diagnostics) is not tuple
            or any(type(value) is not Diagnostic for value in self.diagnostics)
            or type(self.readiness_verified) is not bool
            or self.operation_summary is not None
            and type(self.operation_summary) is not operations.JournalSummary
        ):
            _fail("INSPECT_INPUT_INVALID")

    def to_dict(self):
        actionable = [
            row
            for row in self.diagnostics
            if row.result in {"FAIL", "BLOCKED"}
            and row.code
            not in {"READINESS_ADAPTER_REQUIRED", "READINESS_RUNTIME_REQUIRED", "PROVIDER_READ_ADAPTER_REQUIRED"}
            or row.code == "LAUNCHER_EXITED"
        ]
        process_errors = [row for row in actionable if row.pid is not None]
        last = (
            process_errors[-1]
            if process_errors
            else actionable[-1]
            if actionable
            else next((row for row in reversed(self.diagnostics) if row.result in {"FAIL", "BLOCKED"}), None)
        )
        return {
            "process_status": self.process_status,
            "diagnostics": [row.to_dict() for row in self.diagnostics],
            "last_safe_error": last.to_dict() if last else None,
            "readiness_verified": self.readiness_verified,
            "operation_journal": self.operation_summary.to_dict() if self.operation_summary else None,
            "saved_ready_flag_trusted": False,
            "resource_mutations_authorized": False,
        }


def _safe_winerror(error):
    # Use only structured numeric metadata. Never parse OwnershipError messages
    # or Runtime.inspection_errors strings; absence remains unknown.
    if isinstance(error, OSError) or type(error).__name__ in {
        "OwnershipError",
        "AclVerificationError",
        "RuntimeAdapterError",
    }:
        value = getattr(error, "winerror", None)
        if type(value) is int and value in _WINERRORS:
            return value
    return None


def _record(record):
    return (
        type(record) is dict
        and _pid(record.get("pid"))
        and type(record.get("birth")) is str
        and 0 < len(record["birth"]) <= 256
        and type(record.get("exe")) is str
        and 0 < len(record["exe"]) <= 4096
        and not any(char in record["exe"] for char in "\r\n\0")
    )


def _root(location):
    if (
        runtime_adapter.RuntimeLocation(location.descriptor, location.root, location.anchor).identity
        != location.identity
    ):
        _fail("RUNTIME_PRIVATE_LOCATION_REQUIRED")
    for name in (".dev-runtime.json", ".dev-runtime.lock", ".dev-runtime.stop"):
        path = location.root / name
        if os.path.lexists(path) and dev_instance_registry._private(path).st_size > 1048576:
            _fail("RUNTIME_STATE_UNVERIFIED")


def _load(location, launcher):
    _root(location)
    runtime = launcher.Runtime(location.root)
    if (
        runtime.root != location.root
        or runtime.path != location.root / ".dev-runtime.json"
        or runtime.lock_path != location.root / ".dev-runtime.lock"
        or runtime.stop_path != location.root / ".dev-runtime.stop"
        or runtime.lock is not None
        or runtime.processes
    ):
        _fail("RUNTIME_STATE_UNVERIFIED")
    before = (
        dev_instance_registry._stamp(dev_instance_registry._private(runtime.path))
        if os.path.lexists(runtime.path)
        else None
    )
    raw = dev_environment.bounded_read_bytes(runtime.path, 1048576) if before is not None else None
    try:
        state = runtime.load()
    except Exception:
        _fail("RUNTIME_STATE_UNVERIFIED")
    after = (
        dev_instance_registry._stamp(dev_instance_registry._private(runtime.path))
        if os.path.lexists(runtime.path)
        else None
    )
    _root(location)
    if (
        before != after
        or raw is not None
        and hashlib.sha256(raw).hexdigest()
        != hashlib.sha256(dev_environment.bounded_read_bytes(runtime.path, 1048576)).hexdigest()
    ):
        _fail("RUNTIME_STATE_CHANGED")
    if state is None:
        return runtime, None
    expected = {
        "repository_id": location.descriptor.repository_id,
        "worktree_id": location.descriptor.worktree_id,
        "instance_id": location.descriptor.instance_id,
        "root_identity": list(location.identity),
    }
    if (
        state.get("workspace_context") != expected
        or state.get("profile") != "workspace"
        or type(state.get("instance")) is not str
        or re.fullmatch(r"[0-9a-f]{32}", state["instance"]) is None
        or type(state.get("services")) is not dict
        or set(state["services"]) - set(runtime_adapter._LOGS)
        or len(state["services"]) > 5
        or not _record(state.get("launcher"))
        or state.get("launcher_pid") != state["launcher"]["pid"]
    ):
        _fail("RUNTIME_BINDING_MISMATCH")
    runtime.state = state  # Local object only; no serialization or lock operation.
    return runtime, state


def _process(launcher, record, component, location, *, runtime=None):
    path = location.root / ".dev-logs" / _LOGS[component]
    pid = record.get("pid") if type(record) is dict and _pid(record.get("pid")) else None
    if not _record(record):
        return Diagnostic(component, "BLOCKED", "PROCESS_RECORD_INCOMPLETE", "UNKNOWN", pid, log_path=path)
    members = record.get("members", [])
    if type(members) is not list or len(members) > 256 or any(not _record(value) for value in members):
        return Diagnostic(component, "BLOCKED", "PROCESS_RECORD_INCOMPLETE", "UNKNOWN", pid, log_path=path)
    try:
        current = launcher.process_info(pid)
        if current is not None and not launcher.matches(record, current):
            return Diagnostic(component, "BLOCKED", "PROCESS_IDENTITY_MISMATCH", "UNKNOWN", pid, log_path=path)
        if component == "Launcher":
            return Diagnostic(
                component,
                "PASS" if current else "WARN",
                "PROCESS_RUNNING" if current else "LAUNCHER_EXITED",
                "RUNNING" if current else "STOPPED",
                pid,
                log_path=path,
            )
        if getattr(launcher.sys, "platform", sys.platform) == "win32":
            status = runtime.service_status(record)
            if status == "UNOWNED":
                return Diagnostic(component, "BLOCKED", "PROCESS_IDENTITY_MISMATCH", "UNKNOWN", pid, log_path=path)
            if status not in _STATUSES:
                status = "UNKNOWN"
            code = {
                "RUNNING": "PROCESS_RUNNING",
                "STOPPED": "PROCESS_STOPPED",
                "PARTIAL": "PROCESS_PARTIAL",
                "UNKNOWN": "PROCESS_IDENTITY_UNVERIFIED",
            }[status]
            return Diagnostic(
                component,
                "PASS" if status in {"RUNNING", "STOPPED"} else "WARN" if status == "PARTIAL" else "BLOCKED",
                code,
                status,
                pid,
                log_path=path,
            )
        # No unbounded POSIX process-group enumeration/ps fallback in diagnosis.
        if current:
            return Diagnostic(component, "PASS", "PROCESS_RUNNING", "RUNNING", pid, log_path=path)
        alive = False
        for saved in members:
            observed = launcher.process_info(saved["pid"])
            if observed is not None and not launcher.matches(saved, observed):
                return Diagnostic(component, "BLOCKED", "PROCESS_IDENTITY_MISMATCH", "UNKNOWN", pid, log_path=path)
            alive |= observed is not None
        return Diagnostic(
            component,
            "WARN" if alive else "BLOCKED",
            "PROCESS_PARTIAL" if alive else "PROCESS_GROUP_INSPECTION_REQUIRED",
            "PARTIAL" if alive else "UNKNOWN",
            pid,
            log_path=path,
        )
    except Exception as error:
        return Diagnostic(
            component, "BLOCKED", "PROCESS_IDENTITY_UNVERIFIED", "UNKNOWN", pid, _safe_winerror(error), path
        )


def _bundle(location, plan, expected):
    if expected is None:
        return Diagnostic("Bundle", "SKIPPED", "BUNDLE_EXPECTED_RECEIPT_REQUIRED")
    if (
        type(plan) is not bundle.BundlePlan
        or type(expected) is not bundle.BundleReceipt
        or plan.provider_plan.descriptor.instance_id != location.descriptor.instance_id
        or plan.state_root != location.root
        or expected.material_fingerprint != plan.material_fingerprint
        or not hmac.compare_digest(expected.private_binding, plan.private_binding)
    ):
        return Diagnostic("Bundle", "BLOCKED", "BUNDLE_CONTEXT_REQUIRED")
    try:
        if (
            str(UUID(plan.generation)) != plan.generation
            or plan.anchor.canonical_path != location.anchor
            or plan.directory.parent != location.root / "bundles"
            or {name for name, _ in expected.file_proofs} != {*plan.files, ".env.dev.local", ".pending.json"}
        ):
            _fail("BUNDLE_FILES_UNVERIFIED")
        # These helpers inspect known paths only; no _reuse/_revalidate or Git.
        with bundle._parents(plan, create=False) as (_, _pins, _descriptors, _identities, verify):
            before = dev_instance_registry._private(plan.directory, directory=True)
            if (before.st_dev, before.st_ino) != expected.directory_identity:
                _fail("BUNDLE_FILES_UNVERIFIED")
            raw, proof = bundle._file(plan.directory / ".receipt.json", plan.directory)
            if proof != expected.receipt_proof:
                _fail("BUNDLE_FILES_UNVERIFIED")
            wanted = {key: value for key, value in expected.private_record().items() if key != "receipt_proof"}
            if bundle.json.loads(raw, object_pairs_hook=bundle._object) != wanted:
                _fail("BUNDLE_FILES_UNVERIFIED")
            layouts = {
                plan.directory: {"provider", "keys", "tls", ".env.dev.local", ".pending.json", ".receipt.json"},
                **{
                    plan.directory / folder: {
                        Path(name).name for name, _ in expected.file_proofs if name.startswith(folder + "/")
                    }
                    for folder in ("provider", "keys", "tls")
                },
            }
            for directory, names in layouts.items():
                dev_instance_storage._verify(directory, private=True)
                found = set()
                with os.scandir(directory) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 32:
                            _fail("BUNDLE_FILES_UNVERIFIED")
                        found.add(entry.name)
                if found != names:
                    _fail("BUNDLE_FILES_UNVERIFIED")
            for name, wanted in expected.file_proofs:
                verify()
                _, actual = bundle._file(plan.directory / name, plan.directory)
                if actual != wanted:
                    _fail("BUNDLE_FILES_UNVERIFIED")
            verify()
            after = dev_instance_registry._private(plan.directory, directory=True)
            if dev_instance_registry._stamp(before) != dev_instance_registry._stamp(after):
                _fail("BUNDLE_FILES_UNVERIFIED")
        return Diagnostic("Bundle", "PASS", "BUNDLE_FILES_UNCHANGED")
    except Exception:
        return Diagnostic("Bundle", "BLOCKED", "BUNDLE_FILES_UNVERIFIED")


def inspect_instance(
    descriptor,
    *,
    root,
    anchor,
    launcher=None,
    operation_journal=None,
    bundle_plan=None,
    expected_bundle=None,
    provider_records=None,
    provider_attestation=None,
    provider_inspector=None,
    readiness=None,
    current_head=None,
    controller_changed=None,
    timeout=5,
):
    """Observe once, without acquiring/writing Runtime or contacting defaults.

    Provider callback(recorded,attestation,timeout) and health callback(token,pids,
    required,timeout) are trusted readonly adapters with their own I/O deadlines.
    The wrapper bounds waiting but never kills a thread/process on timeout.
    """
    if (
        type(descriptor) is not dev_instance_plan.InstanceDescriptor
        or type(timeout) not in {int, float}
        or not 0 < timeout <= 5
    ):
        _fail("INSPECT_INPUT_INVALID")
    if (
        current_head is not None
        and (type(current_head) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", current_head) is None)
        or controller_changed is not None
        and type(controller_changed) is not bool
        or provider_inspector is not None
        and not callable(provider_inspector)
        or readiness is not None
        and not callable(readiness)
    ):
        _fail("INSPECT_INPUT_INVALID")
    if launcher is None:
        if __package__:
            from . import dev as launcher
        else:
            import dev as launcher
    if not isinstance(launcher, ModuleType) or not all(
        callable(getattr(launcher, key, None)) for key in ("Runtime", "process_info", "matches")
    ):
        _fail("INSPECT_INPUT_INVALID")
    rows, components, state, status, location = [], [], None, "UNKNOWN", None
    try:
        location = runtime_adapter.RuntimeLocation(descriptor, Path(root), Path(anchor))
        runtime, state = _load(location, launcher)
        if state is None:
            status = "STOPPED"
            rows.append(Diagnostic("Runtime", "PASS", "RUNTIME_STATE_ABSENT", status))
        else:
            leader = _process(launcher, state["launcher"], "Launcher", location)
            rows.append(leader)
            expected_names = tuple(runtime_adapter._LOGS) if descriptor.mode == "isolated" else ("Frontend",)
            names = (*expected_names, *(name for name in state["services"] if name not in expected_names))
            for name in names:
                record = state["services"].get(name)
                if record is None:
                    item = Diagnostic(
                        name,
                        "WARN",
                        "COMPONENT_RECORD_MISSING",
                        "STOPPED",
                        log_path=location.root / ".dev-logs" / _LOGS[name],
                    )
                else:
                    item = _process(launcher, record, name, location, runtime=runtime)
                components.append(item)
            rows.extend(components)
            values = [row.process_status for row in components]
            if "UNKNOWN" in values or leader.process_status == "UNKNOWN":
                status = "UNKNOWN" if not any(value in {"RUNNING", "PARTIAL"} for value in values) else "PARTIAL"
            elif all(value == "STOPPED" for value in values):
                status = "STOPPED"
            elif (
                all(value == "RUNNING" for value in values)
                and leader.process_status == "RUNNING"
                and len(names) == len(expected_names)
            ):
                status = "RUNNING"
            else:
                status = "PARTIAL"
            rows.append(
                Diagnostic(
                    "Runtime",
                    "PASS" if status in {"RUNNING", "STOPPED"} else "WARN" if status == "PARTIAL" else "BLOCKED",
                    "RUNTIME_" + status,
                    status,
                )
            )
    except Exception as error:
        code = error.code if isinstance(error, InspectionError) else "RUNTIME_PRIVATE_LOCATION_REQUIRED"
        rows.append(
            Diagnostic(
                "Runtime",
                "BLOCKED",
                code,
                "UNKNOWN",
                winerror=_safe_winerror(error),
                log_path=location.root / ".dev-logs" / "setup.log" if location is not None else None,
            )
        )
    summary = None
    if operation_journal is None:
        rows.append(Diagnostic("Operation journal", "SKIPPED", "JOURNAL_NOT_SELECTED"))
    elif (
        type(operation_journal) is operations.OperationJournal
        and operation_journal.instance_id == descriptor.instance_id
        and location is not None
        and operation_journal.root == location.root / "operations"
    ):
        summary = operation_journal.read_summary()
        rows.append(
            Diagnostic(
                "Operation journal",
                "BLOCKED" if summary.status == "BLOCKED" else "PASS" if summary.status == "OBSERVED" else "SKIPPED",
                "JOURNAL_REVIEW_REQUIRED" if summary.status == "BLOCKED" else "JOURNAL_HISTORY_OBSERVED",
            )
        )
    else:
        rows.append(Diagnostic("Operation journal", "BLOCKED", "JOURNAL_REVIEW_REQUIRED"))
    rows.append(
        _bundle(location, bundle_plan, expected_bundle)
        if location is not None
        else Diagnostic("Bundle", "BLOCKED", "BUNDLE_CONTEXT_REQUIRED")
    )
    if descriptor.mode != "isolated":
        rows.append(Diagnostic("Providers", "SKIPPED", "PROVIDER_NOT_ALLOCATED"))
    elif provider_inspector is None:
        rows.append(Diagnostic("Providers", "BLOCKED", "PROVIDER_READ_ADAPTER_REQUIRED"))
    elif (
        type(provider_records) is not engine.ResourceRecords
        or type(provider_attestation) is not ProviderAttestation
        or provider_attestation.instance_id != descriptor.instance_id
        or provider_records.engine_identity != provider_attestation.engine_identity
        or provider_records.provider_fingerprint != provider_attestation.provider_fingerprint
        or tuple(value.object_id for value in provider_records.containers) != provider_attestation.container_ids
    ):
        rows.append(Diagnostic("Providers", "BLOCKED", "PROVIDER_RECORDED_IDENTITIES_REQUIRED"))
    else:
        try:
            observed = runtime_adapter._bounded(
                lambda: provider_inspector(provider_records, provider_attestation, timeout), timeout
            )
            if type(observed) is not ProviderObservation or observed.attestation != provider_attestation:
                _fail("PROVIDER_INSPECTION_UNVERIFIED")
            rows.append(
                Diagnostic(
                    "Providers",
                    "PASS" if observed.process_status == "RUNNING" else "WARN",
                    "PROVIDER_INSPECTION_OBSERVED",
                    observed.process_status,
                )
            )
        except Exception as error:
            rows.append(
                Diagnostic("Providers", "BLOCKED", "PROVIDER_INSPECTION_UNVERIFIED", winerror=_safe_winerror(error))
            )
    ready = False
    if readiness is None:
        rows.append(Diagnostic("Health", "BLOCKED", "READINESS_ADAPTER_REQUIRED"))
    elif status != "RUNNING" or state is None:
        rows.append(Diagnostic("Health", "BLOCKED", "READINESS_RUNTIME_REQUIRED"))
    else:
        try:
            pids = tuple(row.pid for row in components)
            required = ("api", "iam", "https", "workers") if descriptor.mode == "isolated" else ("https",)
            observed = runtime_adapter._bounded(lambda: readiness(state["instance"], pids, required, timeout), timeout)
            if (
                type(observed) is not ReadinessObservation
                or observed.runtime_token != state["instance"]
                or observed.pids != pids
                or set(observed.passed) != set(required)
            ):
                _fail("READINESS_UNVERIFIED")
            _, latest = _load(location, launcher)
            if latest != state:
                status = "UNKNOWN"
                _set_row(
                    rows,
                    Diagnostic(
                        "Runtime",
                        "BLOCKED",
                        "RUNTIME_STATE_CHANGED",
                        status,
                        log_path=location.root / ".dev-logs" / "setup.log",
                    ),
                )
                _fail("READINESS_UNVERIFIED")
            launcher_after = _process(launcher, state["launcher"], "Launcher", location)
            if launcher_after.process_status != "RUNNING":
                status = "PARTIAL"
                _set_row(rows, launcher_after)
                _set_row(rows, Diagnostic("Runtime", "WARN", "RUNTIME_PARTIAL", status))
                _fail("READINESS_UNVERIFIED")
            for row in components:
                after = _process(launcher, state["services"][row.component], row.component, location, runtime=runtime)
                if after.process_status != "RUNNING":
                    status = "PARTIAL"
                    _set_row(
                        rows,
                        Diagnostic(
                            after.component,
                            "FAIL",
                            after.code,
                            after.process_status,
                            after.pid,
                            after.winerror,
                            after.log_path,
                        ),
                    )
                    _set_row(rows, Diagnostic("Runtime", "WARN", "RUNTIME_PARTIAL", status))
                    _fail("READINESS_UNVERIFIED")
            ready = True
            rows.append(Diagnostic("Health", "PASS", "READINESS_OBSERVED"))
        except Exception as error:
            rows.append(Diagnostic("Health", "BLOCKED", "READINESS_UNVERIFIED", winerror=_safe_winerror(error)))
    if current_head is None:
        rows.append(Diagnostic("Source", "SKIPPED", "SOURCE_DRIFT_NOT_CHECKED"))
    elif type(current_head) is str and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", current_head):
        changed = current_head != descriptor.commit
        rows.append(
            Diagnostic(
                "Source", "WARN" if changed else "PASS", "SOURCE_HEAD_CHANGED" if changed else "SOURCE_HEAD_UNCHANGED"
            )
        )
    else:
        _fail("INSPECT_INPUT_INVALID")
    if controller_changed is None:
        rows.append(Diagnostic("Controller", "SKIPPED", "CONTROLLER_DRIFT_NOT_CHECKED"))
    elif type(controller_changed) is bool:
        rows.append(
            Diagnostic(
                "Controller",
                "WARN" if controller_changed else "PASS",
                "CONTROLLER_CHANGED" if controller_changed else "CONTROLLER_UNCHANGED",
            )
        )
    else:
        _fail("INSPECT_INPUT_INVALID")
    return InspectionReport(status, tuple(rows), ready, summary)
