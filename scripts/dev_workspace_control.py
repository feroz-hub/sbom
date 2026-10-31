"""Public-launcher integration; preparation is explicit, mock runtime is owned.

Check/non-TTY setup never prepares. Mock preview files have their own category;
certificate consent grants neither preview preparation nor OS/browser trust.
Native enrollment and real-backend startup have no authorization adapter here.
Stop/status recover protected descriptors without source/config/TLS adoption.
Trusted collaborators are controller code, not caller JSON or readiness markers.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

if __package__:
    from . import dev_environment
    from . import dev_instance_registry as registry
    from . import dev_instance_storage as storage
    from . import dev_windows_acl as windows_acl
    from . import dev_workspace as workspace
    from . import dev_workspace_bindings as bindings
    from . import dev_workspace_certificates as certificates
    from . import dev_workspace_engine as engine
    from . import dev_workspace_inspect as inspect
    from . import dev_workspace_observe as observe
    from . import dev_workspace_preview as preview
    from . import dev_workspace_readiness as readiness
    from . import dev_workspace_runtime as runtime
    from . import dev_workspace_setup as setup
else:
    import dev_environment
    import dev_instance_registry as registry
    import dev_instance_storage as storage
    import dev_windows_acl as windows_acl
    import dev_workspace as workspace
    import dev_workspace_bindings as bindings
    import dev_workspace_certificates as certificates
    import dev_workspace_engine as engine
    import dev_workspace_inspect as inspect
    import dev_workspace_observe as observe
    import dev_workspace_preview as preview
    import dev_workspace_readiness as readiness
    import dev_workspace_runtime as runtime
    import dev_workspace_setup as setup

_CODES = frozenset(
    {
        "CONTROL_INPUT_INVALID",
        "CONTROL_HOME_ACCESS_UNVERIFIED",
        "CONTROL_PORT_UNAVAILABLE",
        "CONTROL_SOURCE_UNVERIFIED",
        "CONTROL_SOURCE_CHANGED",
        "CONTROL_REGISTRATION_REQUIRED",
        "CONTROL_SELECTION_REQUIRED",
        "CONTROL_BINDING_REQUIRED",
        "CONTROL_BINDING_CHANGED",
        "CONTROL_CERTIFICATE_PREPARATION_REQUIRED",
        "CONTROL_PREVIEW_PREPARATION_REQUIRED",
        "CONTROL_DEPENDENCIES_REQUIRED",
        "CONTROL_PREVIEW_APPROVAL_REQUIRED",
        "CONTROL_PROVIDER_ATTESTATION_REQUIRED",
        "CONTROL_COMPILER_UNVERIFIED",
        "CONTROL_COMPILER_CLEANUP_UNCONFIRMED",
        "CONTROL_RUNTIME_UNCONFIRMED",
        "CONTROL_CANCELLED",
        "CONTROL_STATUS_OBSERVED",
        "CONTROL_PREVIEW_PREPARED",
    }
)
_RUNTIME_CODES = runtime._ERRORS | frozenset(
    {
        "INSTANCE_READY",
        "INSTANCE_STOPPED",
        "INSTANCE_STOP_REQUEST_PENDING",
        "INSTANCE_OWNERSHIP_UNCERTAIN_RECORDS_RETAINED",
        "INSTANCE_RUNTIME_ALREADY_ACTIVE",
        "INSTANCE_RUNTIME_BUSY",
        "INSTANCE_EXISTING_RUNTIME_REQUIRES_STOP",
        "INSTANCE_START_FAILED",
        "INSTANCE_START_CANCELLED",
        "INSTANCE_SUPERVISION_FAILED",
        "INSTANCE_STOP_UNCONFIRMED",
    }
)
_PREVIEW_CODES = frozenset(
    {
        "PREVIEW_BACKEND_MODE_CONFLICT",
        "PREVIEW_BACKEND_REGISTRATION_REQUIRED",
        "PREVIEW_CATEGORY_APPROVAL_REQUIRED",
        "PREVIEW_ENVIRONMENT_REQUIRED",
        "PREVIEW_EXISTING_TLS_REQUIRED",
        "PREVIEW_ISOLATED_BACKEND_BINDING_REQUIRED",
        "PREVIEW_LAUNCH_VERIFICATION_UNCONFIRMED",
        "PREVIEW_NATIVE_COMPILER_VERIFICATION_REQUIRED",
        "PREVIEW_PLAN_REQUIRED",
        "PREVIEW_PREINSTALLED_NATIVE_COMPILER_REQUIRED",
        "PREVIEW_PREPARATION_UNCONFIRMED",
        "PREVIEW_PRIVATE_STATE_REQUIRED",
        "PREVIEW_PUBLIC_CONFIGURATION_REQUIRED",
        "PREVIEW_PUBLIC_STYLE_REQUIRED",
        "PREVIEW_SHARED_AUTH_OR_TARGET_REQUIRED",
        "PREVIEW_SHARED_BACKEND_VERIFICATION_REQUIRED",
        "PREVIEW_SOURCE_CHANGED",
        "PREVIEW_SOURCE_OR_DEPENDENCY_UNVERIFIED",
        "PREVIEW_SOURCE_SELECTION_REQUIRED",
        "PREVIEW_TLS_VERIFICATION_REQUIRED",
        "PREVIEW_WORKSPACE_UNVERIFIED",
        "TLS_CA_PATH_REVIEW_REQUIRED",
    }
)
_ALLOWED_ERRORS = (
    _CODES
    | setup._CODES
    | bindings._CODES
    | certificates._CODES
    | _PREVIEW_CODES
    | readiness._CODES
    | registry._REGISTRY_CODES
    | _RUNTIME_CODES
)
_STORAGE_CODES = frozenset(
    {
        "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED",
        "INSTANCE_DIRECTORY_ACLS_UNSUPPORTED",
        "INSTANCE_DIRECTORY_ANCHOR_REDIRECTED",
        "INSTANCE_DIRECTORY_CHANGED",
        "INSTANCE_DIRECTORY_CLEANUP_UNCONFIRMED",
        "INSTANCE_DIRECTORY_CREATION_FAILED",
        "INSTANCE_DIRECTORY_DEPTH_REQUIRED",
        "INSTANCE_DIRECTORY_DESCRIPTOR_UNVERIFIED",
        "INSTANCE_DIRECTORY_IDENTITY_UNVERIFIED",
        "INSTANCE_DIRECTORY_INITIALIZATION_FAILED",
        "INSTANCE_DIRECTORY_OUTSIDE_ANCHOR",
        "INSTANCE_DIRECTORY_OWNER_UNVERIFIED",
        "INSTANCE_DIRECTORY_PATH_INVALID",
        "INSTANCE_DIRECTORY_PIN_UNVERIFIED",
        "INSTANCE_DIRECTORY_REDIRECTED",
        "INSTANCE_DIRECTORY_TARGET_REQUIRED",
        "INSTANCE_DIRECTORY_VOLUME_UNVERIFIED",
    }
)
_ACL_CATEGORIES = frozenset(
    {
        "ACE_BOUNDS",
        "API_FAILURE",
        "API_UNAVAILABLE",
        "CLEANUP_UNCONFIRMED",
        "DACL_BOUNDS",
        "DACL_UNVERIFIED",
        "INSPECTION_UNAVAILABLE",
        "INVALID_POLICY",
        "MALFORMED_ACE",
        "MALFORMED_SID",
        "NULL_SECURITY_METADATA",
        "OWNER_MISMATCH",
        "OWNER_UNVERIFIED",
        "REPARSE_POINT",
        "TOKEN_BOUNDS",
        "UNSUPPORTED_ACCESS_MASK",
        "UNSUPPORTED_ACE",
        "UNTRUSTED_GRANT",
    }
)
_ACL_OPERATIONS = frozenset(
    {
        "CloseHandle",
        "CreateFileW",
        "CreateWellKnownSid",
        "EqualSid",
        "GetAce",
        "GetAclInformation",
        "GetFileInformationByHandle",
        "GetSecurityInfo",
        "GetTokenInformation",
        "InspectMetadata",
        "IsValidAcl",
        "IsValidSid",
        "LoadLibrary",
        "LocalFree",
        "Policy",
        "OpenProcessToken",
    }
)


class ControlError(ValueError):
    def __init__(self, code, *, pid=None):
        self.code = code if type(code) is str and code in _ALLOWED_ERRORS else "CONTROL_RUNTIME_UNCONFIRMED"
        self.pid = pid if type(pid) is int and 0 < pid <= 0xFFFFFFFF else None
        super().__init__(self.code)


def _storage_diagnostic(error, component):
    """Only known structured file-security failures; never parse exception text."""
    if type(error) not in {storage.DirectoryInitializationError, windows_acl.AclVerificationError}:
        return None
    context = error.__context__ if type(error) is storage.DirectoryInitializationError else error
    acl = context if type(context) is windows_acl.AclVerificationError else None
    category = (
        acl.category
        if acl is not None and type(acl.category) is str and acl.category in _ACL_CATEGORIES
        else "INSPECTION_UNAVAILABLE"
    )
    operation = (
        acl.operation
        if acl is not None and type(acl.operation) is str and acl.operation in _ACL_OPERATIONS
        else "InspectDirectory"
    )
    code = getattr(error, "code", None)
    value = acl.winerror if acl is not None else getattr(error, "winerror", None)
    return {
        "component": component,
        "code": code if type(code) is str and code in _STORAGE_CODES else "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED",
        "category": category,
        "operation": operation,
        "winerror": value if type(value) is int and 0 <= value <= 0xFFFFFFFF else None,
        "guidance": "The active OS identity and selected directory ownership/access must satisfy the approved private-state policy. Use the approved account or request an administrator's permission review. Preserve existing directories and permissions; no ACL repair or alternate home is selected automatically.",
    }


class HomeAccessError(ControlError):
    def __init__(self, error):
        self.diagnostic = _storage_diagnostic(error, "private-home") or {
            "component": "private-home",
            "code": "INSTANCE_DIRECTORY_ACCESS_UNVERIFIED",
            "category": "INSPECTION_UNAVAILABLE",
            "operation": "InspectDirectory",
            "winerror": None,
            "guidance": "Verify that the approved OS account can inspect the selected existing home. Preserve its permissions and state; this command makes no repairs.",
        }
        super().__init__("CONTROL_HOME_ACCESS_UNVERIFIED")


def _fail(code):
    raise ControlError(code) from None


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _home(value):
    path = Path(value) if value is not None else Path.home()
    if not path.is_absolute() or path.resolve(strict=True) != path:
        _fail("CONTROL_INPUT_INVALID")
    try:
        storage._verify(path, private=False)
    except OSError as error:
        raise HomeAccessError(error) from None
    return path


def _registry(snapshot, home):
    common = snapshot.common_directory
    if (
        common is None
        or workspace._identity(common.canonical_path) != common
        or snapshot.repository_id != workspace._identifier("repo", common)
    ):
        _fail("CONTROL_SOURCE_UNVERIFIED")
    return registry.InstanceRegistry(
        home / ".sbom-dev/repositories" / snapshot.repository_id / "instances",
        anchor=home,
        repository_id=snapshot.repository_id,
    )


def _listed(snapshot, root, requested=None):
    target = Path(requested or root).absolute()
    matches = [item for item in snapshot.worktrees if os.path.normcase(str(item.root)) == os.path.normcase(str(target))]
    if len(matches) != 1 or matches[0].worktree_id is None:
        _fail("CONTROL_SELECTION_REQUIRED")
    return matches[0]


def registered(args, root, *, home=None):
    """Protected descriptor recovery; source/dependency/config/TLS absence allowed."""
    anchor, snapshot = _home(home), workspace.discover_workspaces(root)
    records = _registry(snapshot, anchor).read()
    if records.codes:
        _fail("CONTROL_REGISTRATION_REQUIRED" if records.codes == ("REGISTRY_MISSING",) else records.codes[0])
    requested = getattr(args, "instance_id", None)
    if requested is not None:
        try:
            if type(requested) is not str or str(UUID(requested)) != requested:
                _fail("CONTROL_INPUT_INVALID")
        except (ValueError, TypeError, AttributeError):
            _fail("CONTROL_INPUT_INVALID")
        entries = [entry for entry in records.entries if entry.descriptor.instance_id == requested]
        selected = next(
            (item for item in snapshot.worktrees if entries and item.worktree_id == entries[0].descriptor.worktree_id),
            None,
        )
        if getattr(args, "worktree", None) is not None and (
            selected is None or selected != _listed(snapshot, root, args.worktree)
        ):
            _fail("CONTROL_SELECTION_REQUIRED")
    else:
        selected = _listed(snapshot, root, getattr(args, "worktree", None))
        entries = [entry for entry in records.entries if entry.descriptor.worktree_id == selected.worktree_id]
    if len(entries) != 1:
        _fail("CONTROL_REGISTRATION_REQUIRED")
    return anchor, snapshot, selected, entries[0]


def _same_identity(first, second):
    before, after = first.to_dict(), second.to_dict()
    for name in ("commit", "manifest_hashes"):
        before.pop(name)
        after.pop(name)
    return before == after


class SetupSession:
    """One stable read-only plan context and its explicitly registered adapters."""

    def __init__(self, root, *, home=None, observe_options=None, clock=time.monotonic):
        self.root, self.home, self.clock = Path(root).absolute(), _home(home), clock
        self.options = dict(observe_options or {})
        if set(self.options) - {"git_runner", "dependency_runner", "python_executable", "node_executable", "npm_cli"}:
            _fail("CONTROL_INPUT_INVALID")
        self.issued_at = datetime.now(UTC).replace(microsecond=0)
        self.pending = {}
        self.publishing = {}
        self.diagnostics = {}

    def selection(self, args):
        snapshot = workspace.discover_workspaces(self.root, runner=self.options.get("git_runner"))
        selected = _listed(snapshot, self.root, getattr(args, "worktree", None))
        records = _registry(snapshot, self.home).read()
        if records.codes not in {(), ("REGISTRY_MISSING",)}:
            _fail(records.codes[0])
        existing = next(
            (entry.descriptor for entry in records.entries if entry.descriptor.worktree_id == selected.worktree_id),
            None,
        )
        return setup.Selection(
            selected.worktree_id,
            getattr(args, "mode", None) or (existing.mode if existing else None),
            getattr(args, "auth", None) or (existing.auth_mode if existing else None),
            getattr(args, "provider", None) or (existing.provider if existing else None),
            getattr(args, "generation", None)
            if getattr(args, "generation", None) is not None
            else (existing.generation if existing else 1),
            getattr(args, "family", None) or ("instance" if existing else None),
            getattr(args, "existing_family", None) or ("instance" if existing else None),
        )

    def observation(self, selection):
        observed = setup.observe_setup(self.root, selection, home=self.home, **self.options)
        source = Path(__file__).resolve(strict=True)
        public = [
            observed.controller_fingerprint,
            [
                (name, hashlib.sha256(dev_environment.bounded_read_bytes(source.parent / name, 1048576)).hexdigest())
                for name in (
                    source.name,
                    *certificates._CONTROLLERS,
                    "dev_workspace_runtime.py",
                    "dev_workspace_readiness.py",
                    "dev_workspace_bindings.py",
                    "dev_workspace_engine.py",
                )
            ],
        ]
        if selection.mode == "mock" and observed.worktree:
            style = observed.worktree.root / "frontend/src/app/globals.css"
            public.append(preview._proof(style, observed.worktree.root)[-1])
            public.append(
                preview._proof(observed.worktree.root / "scripts/dev_next_guard.cjs", observed.worktree.root)[-1]
            )
        return replace(observed, controller_fingerprint=_digest(public))

    def known(self, descriptor):
        active = self.publishing.get(descriptor.instance_id)
        if active is not None:
            # Only this synchronous source invocation may bridge the binding
            # writer's own staging file. Its actual writer still verifies all
            # history/root/lock identities before atomic publication.
            store, snapshot, expected = active
            if not _same_identity(expected, descriptor):
                _fail("CONTROL_BINDING_CHANGED")
            return store, snapshot
        store = bindings.BindingStore(home=self.home, instance_id=descriptor.instance_id)
        snapshot = store.read()
        if snapshot.code not in {"BINDING_OBSERVED", "BINDING_MISSING"}:
            _fail(snapshot.code)
        if snapshot.binding is not None and not _same_identity(snapshot.binding.descriptor, descriptor):
            _fail("CONTROL_BINDING_CHANGED")
        return store, snapshot

    def certificate_plan(self, plan):
        descriptor = plan.instance_plan.descriptor
        _store, known = self.known(descriptor)
        expected = known.binding.certificate_receipt if known.binding else None
        pending = self.pending.get(descriptor.instance_id)
        if pending is not None:
            expected = pending.receipt
        generation = (
            expected.generation if expected else str(uuid5(NAMESPACE_URL, "sbom-preview-tls:" + descriptor.instance_id))
        )
        source = certificates.inspect_source(plan.observation.worktree.root, worktree_id=descriptor.worktree_id)
        cert = certificates.plan_certificates(
            descriptor,
            source,
            anchor=workspace._identity(self.home),
            generation=generation,
            now=expected.issued_at if expected else self.issued_at,
            certificate_days=expected.certificate_days if expected else 30,
        )
        if expected:
            certificates._reuse(cert, expected)
        elif os.path.lexists(cert.parent):
            storage._verify(cert.parent, private=True)
            with os.scandir(cert.parent) as entries:
                if any(entry.name != ".prepare.lock" for entry in entries):
                    _fail("TLS_UNKNOWN_GENERATION_RETAINED")
        return cert, expected

    def preview_plan(self, plan):
        dep = plan.observation.dependency_plan
        if dep is None or dep.blockers or not all(dep.target_stamps.get(key) for key in ("python", "frontend")):
            _fail("CONTROL_DEPENDENCIES_REQUIRED")
        cert, expected = self.certificate_plan(plan)
        if expected is None:
            _fail("CONTROL_CERTIFICATE_PREPARATION_REQUIRED")
        tls = preview.PreviewTls(cert.directory / "s.pem", cert.directory / "s.key", cert.directory / "c.pem")
        return preview.plan_preview(
            plan.observation.repository,
            plan.observation.worktree,
            plan.instance_plan.descriptor,
            state_anchor=self.home,
            node_executable=Path(dep.tools["node"][0]),
            tls=tls,
        )

    def plan(self, selection):
        observed = self.observation(selection)
        base = setup.plan_setup(observed, selection)
        if base.instance_plan is None or selection.mode != "mock":
            return base
        descriptor = base.instance_plan.descriptor
        generation = str(uuid5(NAMESPACE_URL, "sbom-preview-tls:" + descriptor.instance_id))
        reference = _digest([descriptor.instance_id, generation, descriptor.origin, observed.controller_fingerprint])
        cert_status, preview_status = "MISSING", "MISSING"
        expected = None
        try:
            _cert, expected = self.certificate_plan(base)
            if expected is not None and descriptor.instance_id not in self.pending:
                cert_status = "READY"
        except Exception as error:
            self.diagnostics["certificates"] = _error_code(error)
            cert_status, preview_status = "BLOCKED", "BLOCKED"
        if expected is not None:
            try:
                planned = self.preview_plan(base)
                if os.path.lexists(planned.workspace.parent):
                    preview.require_preview(planned)
                    preview_status = "READY"
            except Exception as error:
                code = _error_code(error)
                self.diagnostics["dependencies" if code == "CONTROL_DEPENDENCIES_REQUIRED" else "preview"] = code
                if code != "CONTROL_DEPENDENCIES_REQUIRED":
                    preview_status = "BLOCKED"
        contexts = [setup.StageContext("certificates", cert_status, base.target_fingerprint, reference)]
        registered_categories = ["certificates"]
        if "preview" in setup._CATEGORIES:
            contexts.append(setup.StageContext("preview", preview_status, base.target_fingerprint, reference))
            registered_categories.append("preview")
        return setup.plan_setup(
            observed,
            selection,
            contexts=setup.Contexts(tuple(contexts)),
            registered_categories=tuple(registered_categories),
        )

    def authorize(self, plan, consent):
        if plan.selection.mode != "mock" or consent.category not in {"certificates", "preview"}:
            _fail("CONTROL_PROVIDER_ATTESTATION_REQUIRED")
        if consent.category == "certificates":
            cert, _expected = self.certificate_plan(plan)
            certificates._revalidate(cert)
        else:
            preview._revalidate(self.preview_plan(plan))
        return setup.StageAuthority(
            consent.category,
            plan.target_fingerprint,
            dict(plan.stage_bindings)[consent.category],
            setup._AUTHORITY[consent.category],
        )

    def prepare_certificates(self, plan, guard):
        cert, _expected = self.certificate_plan(plan)

        def authorize(candidate, category):
            guard("certificates")
            if candidate != cert or category != "certificates":
                _fail("CONTROL_BINDING_CHANGED")
            return certificates.CertificateConsent(cert.operation_binding, cert.generation, cert.not_after)

        outcome = certificates.prepare_certificates(cert, authorize=authorize)
        if outcome.exit_code == 130:
            raise KeyboardInterrupt
        if outcome.exit_code != 0 or outcome.receipt is None:
            raise ControlError(outcome.code)
        self.pending[cert.descriptor.instance_id] = outcome
        store, known = self.known(cert.descriptor)
        prepared = (
            replace(
                known.binding,
                descriptor=cert.descriptor,
                certificate_generation=cert.generation,
                certificate_receipt=outcome.receipt,
            )
            if known.binding
            else bindings.PreparedBinding(
                cert.descriptor, certificate_generation=cert.generation, certificate_receipt=outcome.receipt
            )
        )
        self.publishing[cert.descriptor.instance_id] = (store, known, cert.descriptor)
        try:
            store.publish(
                prepared,
                expected_revision=known.revision,
                authorize=lambda _binding, _revision: bool(guard("certificates")),
                completed=bindings.CompletedSources(certificate_plan=cert, certificate_outcome=outcome),
            )
        finally:
            self.publishing.pop(cert.descriptor.instance_id)
        self.pending.pop(cert.descriptor.instance_id)
        return setup.StageOutcome("certificates", "COMPLETED", "SETUP_STAGE_COMPLETED", ("certificates",), True)

    def prepare_preview(self, plan, guard):
        planned = self.preview_plan(plan)

        def authorize(candidate):
            current = guard("preview")
            if candidate != planned or self.preview_plan(current) != planned:
                _fail("CONTROL_SOURCE_CHANGED")
            return True

        preview.prepare_preview(planned, authorize=authorize)
        return setup.StageOutcome("preview", "COMPLETED", "SETUP_STAGE_COMPLETED", ("preview",), True)

    def adapters(self):
        result = [setup.StageAdapter("certificates", self.prepare_certificates, self.authorize)]
        if "preview" in setup._CATEGORIES:
            result.append(setup.StageAdapter("preview", self.prepare_preview, self.authorize))
        return tuple(result)


def _error_code(error):
    code = getattr(error, "code", None)
    return code if type(code) is str and code in _ALLOWED_ERRORS else "CONTROL_RUNTIME_UNCONFIRMED"


def _print(args, payload):
    if getattr(args, "json", False):
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"[{'PASS' if payload.get('exit_code') == 0 else 'BLOCKED'}] {payload.get('code', 'CONTROL_STATUS_OBSERVED')}; browser trust UNVERIFIED; application readiness not claimed."
        )
        for item in payload.get("services", ()):
            print(
                f"[INFO] {item['component']}: {item['process_status']}; pid={item['pid']}; log={json.dumps(item['log_path'])}"
            )
        for item in payload.get("readiness", ()):
            print(f"[{item['status']}] {item['component']}: {item['code']}")
        for item in payload.get("required_checks", {}).get("results", ()):
            print(f"[{item['status']}] {item['category']}: {item['code']}")
        if diagnostic := payload.get("diagnostic"):
            print(
                f"[BLOCKED] {diagnostic['component']}: {diagnostic['code']}; category={diagnostic['category']}; operation={diagnostic['operation']}; winerror={diagnostic['winerror']}"
            )
            print(diagnostic["guidance"])
        if inspection := payload.get("inspection"):
            print(f"[BLOCKED] {inspection['stage']}: {inspection['category']}; winerror={inspection['winerror']}")


def _error(args, error):
    cancelled = isinstance(error, (KeyboardInterrupt, EOFError))
    payload = {
        "code": "CONTROL_CANCELLED" if cancelled else _error_code(error),
        "exit_code": 130 if cancelled else 1,
        "application_ready": False,
        "browser_trust": "UNVERIFIED",
    }
    pid = (
        error.pid
        if type(error) is ControlError and error.code == "CONTROL_COMPILER_CLEANUP_UNCONFIRMED"
        else error.probe_pid
        if type(error) is readiness.ReadinessError and error.code == "LISTENER_PROBE_CLEANUP_UNCONFIRMED"
        else None
    )
    if type(pid) is int and 0 < pid <= 0xFFFFFFFF:
        payload["owned_probe_pid"] = pid
    diagnostic = error.diagnostic if type(error) is HomeAccessError else _storage_diagnostic(error, "private-state")
    if diagnostic is not None:
        payload["diagnostic"] = diagnostic
    if type(error) is ControlError and error.code == "CONTROL_PORT_UNAVAILABLE":
        payload.update(
            component="Frontend",
            process_status="UNVERIFIED",
            guidance="The instance frontend port cannot be reserved on 127.0.0.1. Inspect instance status and the existing listener; preserve its owner. No foreign process was contacted or terminated.",
        )
    if getattr(args, "command", None) == "setup":
        payload.update(plan=None, outcome={"code": payload["code"], "exit_code": payload["exit_code"]})
    _print(args, payload)
    return payload["exit_code"]


@contextmanager
def scoped_signals():
    """Handle only this controller; never broadcast console/process signals."""
    previous = []

    def cancelled(_signum, _frame):
        raise KeyboardInterrupt

    try:
        if threading.current_thread() is threading.main_thread():
            for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
                value = getattr(signal, name, None)
                if value is not None:
                    previous.append((value, signal.getsignal(value)))
                    signal.signal(value, cancelled)
        yield
    finally:
        for value, handler in reversed(previous):
            signal.signal(value, handler)


def run_setup(args, root, *, home=None, io=None, observe_options=None):
    with scoped_signals():
        return _run_setup(args, root, home=home, io=io, observe_options=observe_options)


def _run_setup(args, root, *, home=None, io=None, observe_options=None):
    try:
        session = SetupSession(root, home=home, observe_options=observe_options)
        selected = session.selection(args)
        terminal = io or setup.TerminalIO()
        captured, observation_error = {}, {}
        if getattr(args, "json", False):

            class ReadOnlyIO:
                def interactive(self):
                    return False

                def display(self, plan):
                    captured["plan"] = plan.to_dict()

            terminal = ReadOnlyIO()
        executor = setup.SetupExecutor(
            reobserve=session.plan,
            adapters=session.adapters(),
            dependency_runner=session.options.get("dependency_runner"),
        )

        def planner(selection):
            try:
                return session.plan(selection)
            except Exception as error:
                diagnostic = _storage_diagnostic(error, "setup-observation")
                if diagnostic is not None:
                    observation_error.update(diagnostic)
                raise setup.SetupError("SETUP_OBSERVATION_BLOCKED") from None

        result = setup.guided_session(
            selected, planner=planner, executor=executor, io=terminal, check=bool(getattr(args, "check", False))
        )
        _print(
            args,
            {
                **result.to_dict(),
                "plan": captured.get("plan"),
                "outcome": result.to_dict(),
                **({"diagnostic": observation_error} if observation_error else {}),
                "diagnostics": dict(session.diagnostics),
                "application_ready": False,
                "browser_trust": "UNVERIFIED",
            },
        )
        return result.exit_code
    except (Exception, KeyboardInterrupt, EOFError) as error:
        return _error(args, error)


def _launcher():
    if __package__:
        from . import dev
    else:
        import dev
    return dev


def _runtime(anchor, descriptor, launcher):
    location = runtime.RuntimeLocation(descriptor, anchor / ".sbom-dev/instances" / descriptor.instance_id, anchor)
    return runtime.WorkspaceRuntime(
        location,
        runtime_factory=launcher.Runtime,
        atomic_json=launcher.atomic_json,
        process_info=launcher.process_info,
        matches=launcher.matches,
    )


def compiler_probe(plan, argv, environment):
    """Original-handle bounded native binding probe; no Next loader/download."""
    try:
        raw = engine._owned_run(argv, cwd=plan.workspace, environment=environment, timeout=8)
        payload = json.loads(raw, object_pairs_hook=registry._json_object)
        if len(raw) > 128 or type(payload) is not dict or set(payload) != {"ready"} or payload["ready"] is not True:
            _fail("CONTROL_COMPILER_UNVERIFIED")
        return True
    except engine.EngineError as error:
        if error.code == "ENGINE_CHILD_CLEANUP_UNCONFIRMED":
            raise ControlError("CONTROL_COMPILER_CLEANUP_UNCONFIRMED", pid=error.child_pid) from None
        if error.code == "ENGINE_CHILD_CANCELLED":
            raise KeyboardInterrupt from None
        _fail("CONTROL_COMPILER_UNVERIFIED")
    except (ValueError, TypeError):
        _fail("CONTROL_COMPILER_UNVERIFIED")


def frontend_port_available(descriptor):
    """Startup-only bind/close observation, never foreign service contact.

    This is deliberately not a lease: a later rebind race remains possible and
    the runtime's independent listener/PID/TLS checks must still fail closed.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owned:
            owned.settimeout(0.5)
            if os.name == "nt":
                option = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if type(option) is not int:
                    _fail("CONTROL_PORT_UNAVAILABLE")
                owned.setsockopt(socket.SOL_SOCKET, option, 1)
            owned.bind(("127.0.0.1", descriptor.ports["frontend"]))
        return True
    except OSError:
        _fail("CONTROL_PORT_UNAVAILABLE")


def _mock_prepared(args, root, anchor, snapshot, selected, entry):
    if entry.descriptor.mode != "mock":
        _fail("CONTROL_PROVIDER_ATTESTATION_REQUIRED")
    if selected is None or selected.status != "PASS" or selected.head != entry.descriptor.commit:
        _fail("CONTROL_SOURCE_CHANGED")
    session = SetupSession(root, home=anchor)
    selection = setup.Selection(
        selected.worktree_id,
        "mock",
        entry.descriptor.auth_mode,
        entry.descriptor.provider,
        entry.descriptor.generation,
        "instance",
        "instance",
    )
    plan = session.plan(selection)
    if plan.instance_plan is None or plan.instance_plan.descriptor != entry.descriptor:
        _fail("CONTROL_SOURCE_CHANGED")
    planned = session.preview_plan(plan)
    preview.require_preview(planned)
    return session, plan, planned


def _runtime_payload(result, descriptor, anchor, reader=None):
    if type(result) is not runtime.RuntimeOutcome:
        _fail("CONTROL_RUNTIME_UNCONFIRMED")
    services = []
    for item in result.services:
        if item.component not in runtime._LOGS:
            continue
        services.append(
            {
                "component": item.component,
                "process_status": item.process_status
                if item.process_status in {"RUNNING", "STOPPED", "PARTIAL", "UNKNOWN", "UNOWNED"}
                else "UNKNOWN",
                "pid": item.pid if type(item.pid) is int and 0 < item.pid <= 0xFFFFFFFF else None,
                "log_path": str(
                    anchor
                    / ".sbom-dev/instances"
                    / descriptor.instance_id
                    / ".dev-logs"
                    / runtime._LOGS[item.component]
                ),
            }
        )
    payload = {
        "code": result.code if result.code in _RUNTIME_CODES else "CONTROL_RUNTIME_UNCONFIRMED",
        "exit_code": result.exit_code if type(result.exit_code) is int and result.exit_code in {0, 1, 130} else 1,
        "mode": descriptor.mode,
        "services": services,
        "records_retained": result.records_retained is True,
        "mock_preview_ready": descriptor.mode == "mock" and result.ready is True,
        "application_ready": False,
        "browser_trust": "UNVERIFIED",
        "readiness": [value.to_dict() for value in reader.results.values()] if reader else [],
    }
    payload["component"] = (
        result.component if type(result.component) is str and result.component in runtime._LOGS else None
    )
    payload["winerror"] = (
        result.winerror if type(result.winerror) is int and 0 <= result.winerror <= 0xFFFFFFFF else None
    )
    if type(result.inspection) is runtime.RuntimeInspection:
        payload["inspection"] = result.inspection.to_dict()
    if (
        result.code == "LISTENER_PROBE_CLEANUP_UNCONFIRMED"
        and type(result.probe_pid) is int
        and 0 < result.probe_pid <= 0xFFFFFFFF
    ):
        payload["owned_probe_pid"] = result.probe_pid
    return payload


def run_lifecycle(args, root, *, home=None):
    with scoped_signals():
        return _run_lifecycle(args, root, home=home)


def _run_lifecycle(args, root, *, home=None):
    supervisor = None
    try:
        action = getattr(args, "command", None)
        if action not in {"start", "stop", "restart"}:
            _fail("CONTROL_INPUT_INVALID")
        anchor, snapshot, selected, entry = registered(args, root, home=home)
        if action != "stop" and entry.descriptor.mode != "mock":
            _fail("CONTROL_PROVIDER_ATTESTATION_REQUIRED")
        prepared = _mock_prepared(args, root, anchor, snapshot, selected, entry) if action != "stop" else None
        if action == "start":
            frontend_port_available(entry.descriptor)
        launcher = _launcher()
        supervisor = _runtime(anchor, entry.descriptor, launcher)
        reader = None
        preflight_failure = None
        if action == "stop":
            result = supervisor.stop(timeout=45)
        else:
            session, plan, planned = prepared

            def verify_tls(candidate, _environment):
                readiness.validate_tls_material(candidate.tls, candidate.descriptor.hostname)
                return True

            launch = preview.validate_launch(
                planned, runtime.minimal_transport(), verify_tls=verify_tls, verify_compiler=compiler_probe
            )
            specs = runtime.preview_launch(supervisor.location, launch)
            environment = {
                **runtime.minimal_transport(),
                "SBOM_DEV_RESOURCE_ID": entry.descriptor.instance_id,
                "APP_ENVIRONMENT": "development",
                "PYTHON_DOTENV_DISABLED": "1",
            }
            context = readiness.ReadinessContext(
                entry.descriptor, environment, supervisor.location.root, selected.root, planned.tls, "not_applicable"
            )
            reader = readiness.WorkspaceReadiness(context, launcher, lambda: supervisor.runtime)
            probes = {"Frontend": reader.frontend}

            def preflight(candidates, _budget):
                nonlocal preflight_failure
                if tuple(candidates) != specs:
                    return False
                _store, known = session.known(entry.descriptor)
                if known.binding is None or known.binding.certificate_receipt is None:
                    return False
                preview.require_preview(planned)
                if not verify_tls(planned, launch.environment):
                    return False
                try:
                    return frontend_port_available(entry.descriptor)
                except ControlError as error:
                    if error.code == "CONTROL_PORT_UNAVAILABLE":
                        preflight_failure = error.code
                        return False
                    raise

            method = supervisor.restart if action == "restart" else supervisor.start
            result = method(specs, preflight=preflight, probes=probes, timeout=90)
            if result.ready:
                _print(args, _runtime_payload(result, entry.descriptor, anchor, reader))
                result = supervisor.supervise(probes)
        payload = _runtime_payload(result, entry.descriptor, anchor, reader)
        if preflight_failure is not None and result.exit_code:
            payload.update(code=preflight_failure, component="Frontend", process_status="UNVERIFIED")
        _print(args, payload)
        return result.exit_code
    except (Exception, KeyboardInterrupt, EOFError) as error:
        return _error(args, error)
    finally:
        if supervisor is not None and supervisor.runtime is not None:
            try:
                stopped = supervisor.stop(timeout=45)
                if stopped.exit_code:
                    _print(args, _runtime_payload(stopped, supervisor.location.descriptor, supervisor.location.anchor))
            except (Exception, KeyboardInterrupt, EOFError):
                _print(args, {"code": "CONTROL_RUNTIME_UNCONFIRMED", "exit_code": 1, "records_retained": True})
            finally:
                try:
                    supervisor.release()
                except (Exception, KeyboardInterrupt, EOFError):
                    _print(args, {"code": "CONTROL_RUNTIME_UNCONFIRMED", "exit_code": 1, "records_retained": True})


def run_status(args, root, *, home=None):
    try:
        anchor, _snapshot, selected, entry = registered(args, root, home=home)
        report = inspect.inspect_instance(
            entry.descriptor,
            root=anchor / ".sbom-dev/instances" / entry.descriptor.instance_id,
            anchor=anchor,
            launcher=_launcher(),
            current_head=selected.head if selected else None,
        )
        payload = {
            "code": "CONTROL_STATUS_OBSERVED",
            "exit_code": 1 if report.process_status in {"UNKNOWN", "PARTIAL"} else 0,
            **report.to_dict(),
            "application_ready": False,
            "browser_trust": "UNVERIFIED",
        }
        if getattr(args, "command", None) == "diagnose":
            required = observe.diagnose_instance(
                entry.descriptor, include_host=bool(getattr(args, "host", False)), home=anchor
            )
            payload["required_checks"] = required.to_dict()
            if any(status in {"FAIL", "BLOCKED"} for _category, status, _code in required.results):
                payload["exit_code"] = 1
        _print(args, payload)
        return payload["exit_code"]
    except Exception as error:
        return _error(args, error)
