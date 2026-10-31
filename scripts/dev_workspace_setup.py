"""Single-session development preparation, with independent approval scopes.

observe_setup uses bounded read-only Git/software observers. plan_setup is pure.
Only execute_selected may call mutators, after exact category/target/expiry/drift
checks. User consent never supplies company, database, OS-trust or Native account
authority. Sensitive adapters must independently verify their own boundaries.
Plans, check forms and non-TTY sessions never write a journal or prepare anything.
Existing Legacy/Greenfield settings are neither read as secrets nor converted.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

if __package__:
    from . import (
        dev_environment,
    )
    from . import (
        dev_instance_plan as instances,
    )
    from . import (
        dev_instance_registry as registry,
    )
    from . import (
        dev_instance_storage as storage,
    )
    from . import (
        dev_workspace as workspace,
    )
    from . import dev_workspace_dependencies as dependencies
    from . import dev_workspace_onboarding as onboarding
else:
    import dev_environment
    import dev_instance_plan as instances
    import dev_instance_registry as registry
    import dev_instance_storage as storage
    import dev_workspace as workspace
    import dev_workspace_dependencies as dependencies
    import dev_workspace_onboarding as onboarding

_CATEGORIES = (
    "selection",
    "registry",
    "dependencies",
    "provider-policy",
    "private-credentials",
    "certificates",
    "preview",
    "provider-resources",
    "database-init",
    "schema",
    "trust",
    "onboarding",
)
_SENSITIVE = frozenset(_CATEGORIES[3:-1])
_STATUSES = frozenset({"READY", "MISSING", "BLOCKED", "NEEDS_APPROVAL", "INCOMPATIBLE", "WARN", "SKIPPED"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PREREQUISITES = {
    "selection": (),
    "dependencies": (),
    "registry": ("selection",),
    "provider-policy": ("selection",),
    "private-credentials": ("registry", "provider-policy"),
    "certificates": ("registry", "provider-policy"),
    "preview": ("registry", "dependencies", "certificates", "provider-resources", "database-init", "schema"),
    "provider-resources": ("registry", "provider-policy", "private-credentials", "certificates"),
    "database-init": ("provider-resources",),
    "schema": ("database-init",),
    "trust": ("certificates",),
    "onboarding": ("schema",),
}
_MOCK_NOT_REQUIRED = frozenset(
    {"provider-policy", "private-credentials", "provider-resources", "database-init", "schema", "onboarding"}
)


def _prerequisites(mode, category):
    if mode == "mock" and category in _MOCK_NOT_REQUIRED:
        return ()
    if mode in {"mock", "shared-backend"} and category == "certificates":
        return ("registry",)
    if category == "preview" and mode == "mock":
        return ("registry", "dependencies", "certificates")
    if category == "preview" and mode == "shared-backend":
        return ("registry", "dependencies", "certificates", "private-credentials", "provider-resources")
    return _PREREQUISITES[category]


_AUTHORITY = {
    category: frozenset({"independent-authority", "exact-stage-inputs", "profile-preservation"})
    for category in _SENSITIVE
}
_AUTHORITY.update(
    {
        "provider-policy": _AUTHORITY["provider-policy"]
        | {"company-policy", "provenance-scan-registry", "platform-contract"},
        "provider-resources": _AUTHORITY["provider-resources"] | {"engine-and-creation-identities", "durable-journal"},
        "database-init": _AUTHORITY["database-init"] | {"exact-database-approval", "nonroot-volume", "durable-journal"},
        "schema": _AUTHORITY["schema"] | {"exact-database-approval", "reviewed-schema-action", "durable-journal"},
        "trust": _AUTHORITY["trust"] | {"explicit-os-trust-approval", "approved-certificate"},
        "preview": _AUTHORITY["preview"] | {"owned-source", "compiler-guard"},
    }
)
_CODES = frozenset(
    {
        "SETUP_INPUT_INVALID",
        "SETUP_OBSERVATION_BLOCKED",
        "SETUP_SELECTION_REQUIRED",
        "SETUP_SELECTION_READY",
        "SETUP_EXISTING_FAMILY_REVIEW_REQUIRED",
        "SETUP_FAMILY_CONVERSION_REFUSED",
        "SETUP_REGISTRY_UNKNOWN",
        "SETUP_REGISTRY_READY",
        "SETUP_REGISTRY_APPROVAL_REQUIRED",
        "SETUP_REGISTRY_SOURCE_REVIEW_REQUIRED",
        "SETUP_DEPENDENCIES_BLOCKED",
        "SETUP_DEPENDENCIES_READY",
        "SETUP_DEPENDENCIES_APPROVAL_REQUIRED",
        "SETUP_ADAPTER_REQUIRED",
        "SETUP_CONTEXT_REQUIRED",
        "SETUP_CONTEXT_INCOMPATIBLE",
        "SETUP_STAGE_READY",
        "SETUP_STAGE_APPROVAL_REQUIRED",
        "SETUP_PREREQUISITE_BLOCKED",
        "SETUP_NATIVE_ADMIN_EXISTS",
        "SETUP_NATIVE_ACTIVATION_PENDING",
        "SETUP_NATIVE_COMPLETED_RESERVATION_PRESERVED",
        "SETUP_NATIVE_ENROLLMENT_APPROVAL_REQUIRED",
        "SETUP_ONBOARDING_UNKNOWN",
        "SETUP_HCL_IDENTITY_EXISTS",
        "SETUP_HCL_PROVISIONING_APPROVAL_REQUIRED",
        "SETUP_READ_ONLY",
        "SETUP_CANCELLED",
        "SETUP_CONSENT_REQUIRED",
        "SETUP_CONSENT_EXPIRED",
        "SETUP_DRIFT_DETECTED",
        "SETUP_SCOPE_REFUSED",
        "SETUP_AUTHORITY_REQUIRED",
        "SETUP_STAGE_COMPLETED",
        "SETUP_STAGE_FAILED",
        "SETUP_PARTIAL_RETAINED",
        "SETUP_NOT_SELECTED",
        "SETUP_ALREADY_READY",
        "SETUP_NOT_REQUIRED",
        "SETUP_PRIVILEGED_ONBOARDING_GATED",
        "SETUP_JOURNAL_UNCONFIRMED",
    }
)


class SetupError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "SETUP_INPUT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise SetupError(code) from None


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("SETUP_INPUT_INVALID")


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class Selection:
    worktree_id: str | None = None
    mode: str | None = None
    auth_mode: str | None = None
    provider: str | None = None
    generation: int = 1
    family: str | None = None
    existing_family: str | None = None

    def __post_init__(self):
        families = {"legacy-managed", "legacy-env", "greenfield", "instance"}
        if (
            self.worktree_id is not None
            and (type(self.worktree_id) is not str or _HASH.fullmatch(self.worktree_id) is None)
            or self.mode is not None
            and (type(self.mode) is not str or self.mode not in {"isolated", "mock", "shared-backend"})
            or self.auth_mode is not None
            and (type(self.auth_mode) is not str or self.auth_mode not in {"native", "hcl"})
            or self.provider is not None
            and (type(self.provider) is not str or self.provider not in {"container", "local", "mock", "shared"})
            or type(self.generation) is not int
            or not 1 <= self.generation <= 2147483647
            or self.family is not None
            and (type(self.family) is not str or self.family not in families)
            or self.existing_family is not None
            and (type(self.existing_family) is not str or self.existing_family not in families)
        ):
            _fail("SETUP_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class StageContext:
    """Observation with a public policy/opaque-generation digest, never a secret hash."""

    category: str
    status: str
    target_fingerprint: str
    reference: str

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _SENSITIVE
            or type(self.status) is not str
            or self.status not in _STATUSES - {"SKIPPED"}
        ):
            _fail("SETUP_INPUT_INVALID")
        _hash(self.target_fingerprint)
        _hash(self.reference)


@dataclass(frozen=True, slots=True)
class ExistingIdentity:
    """Verified read-only external identity observation, never provisioning permission."""

    context: onboarding.OnboardingContext = field(repr=False)
    reference: str
    state: str

    def __post_init__(self):
        if (
            type(self.context) is not onboarding.OnboardingContext
            or self.context.auth_mode != "hcl"
            or type(self.state) is not str
            or self.state not in {"EXISTING_AUTHORIZED", "UNKNOWN", "REQUIRED"}
        ):
            _fail("SETUP_INPUT_INVALID")
        _hash(self.reference)


@dataclass(frozen=True, slots=True)
class Contexts:
    stages: tuple[StageContext, ...] = ()
    onboarding_plan: onboarding.OnboardingPlan | None = field(default=None, repr=False)
    external_identity: ExistingIdentity | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.stages) is not tuple
            or any(type(value) is not StageContext for value in self.stages)
            or len({value.category for value in self.stages}) != len(self.stages)
            or self.onboarding_plan is not None
            and type(self.onboarding_plan) is not onboarding.OnboardingPlan
            or self.external_identity is not None
            and type(self.external_identity) is not ExistingIdentity
        ):
            _fail("SETUP_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class Observation:
    repository: workspace.RepositorySnapshot = field(repr=False)
    worktree: workspace.WorktreeSnapshot | None = field(repr=False)
    dependency_plan: dependencies.DependencyPlan | None = field(repr=False)
    registry_store: registry.InstanceRegistry | None = field(repr=False)
    registry_snapshot: registry.RegistrySnapshot = field(repr=False)
    controller_fingerprint: str
    private_configuration_present: bool = False
    instance_manifest_hashes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if (
            type(self.repository) is not workspace.RepositorySnapshot
            or self.worktree is not None
            and type(self.worktree) is not workspace.WorktreeSnapshot
            or self.dependency_plan is not None
            and type(self.dependency_plan) is not dependencies.DependencyPlan
            or self.registry_store is not None
            and type(self.registry_store) is not registry.InstanceRegistry
            or type(self.registry_snapshot) is not registry.RegistrySnapshot
            or type(self.private_configuration_present) is not bool
            or type(self.instance_manifest_hashes) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or item[0] not in instances._MANIFESTS
                or type(item[1]) is not str
                or _HASH.fullmatch(item[1]) is None
                for item in self.instance_manifest_hashes
            )
            or len({name for name, _ in self.instance_manifest_hashes}) != len(self.instance_manifest_hashes)
        ):
            _fail("SETUP_INPUT_INVALID")
        _hash(self.controller_fingerprint)


def observe_setup(
    root,
    selection,
    *,
    home=None,
    git_runner=None,
    dependency_runner=None,
    python_executable=None,
    node_executable=None,
    npm_cli=None,
):
    """Bounded readonly public-source/software observations; no secret/config read."""
    if type(selection) is not Selection:
        _fail("SETUP_INPUT_INVALID")
    snapshot = workspace.discover_workspaces(root, runner=git_runner)
    matches = [
        item
        for item in snapshot.worktrees
        if (item.worktree_id == selection.worktree_id if selection.worktree_id else item.root == snapshot.root)
    ]
    selected = matches[0] if len(matches) == 1 else None
    dep, store, records, present = None, None, registry.RegistrySnapshot(codes=("REGISTRY_MISSING",)), False
    instance_manifests = ()
    controller = Path(__file__).resolve(strict=True).parent
    names = (
        "dev.py",
        "dev_workspace_cli.py",
        "dev_workspace_setup.py",
        "dev_workspace.py",
        "dev_workspace_dependencies.py",
        "dev_instance_plan.py",
        "dev_instance_registry.py",
        "dev_instance_storage.py",
        "dev_private.py",
        "dev_windows_acl.py",
        "dev_environment.py",
        "dev_workspace_onboarding.py",
    )
    source = _digest(
        [
            (name, hashlib.sha256(dev_environment.bounded_read_bytes(controller / name, 1048576)).hexdigest())
            for name in names
        ]
    )
    if (
        snapshot.status == "PASS"
        and selected is not None
        and selected.status == "PASS"
        and not any((selected.bare, selected.locked, selected.prunable))
        and selected.identity is not None
    ):
        # Reuse the public launcher's exact descriptor manifest contract. This
        # local import invokes no CLI dispatch, private config or preparation.
        if __package__:
            from . import dev_workspace_cli
        else:
            import dev_workspace_cli
        hashes = dev_workspace_cli._manifest_hashes(selected.root, selected.identity, snapshot.root, snapshot.identity)
        instance_manifests = tuple(sorted(hashes.items()))
        anchor = Path(home).resolve(strict=True) if home is not None else Path.home().resolve(strict=True)
        dep = dependencies.inspect_dependencies(
            snapshot,
            selected,
            manifest_hashes=hashes,
            runner=dependency_runner,
            state_anchor=anchor,
            python_executable=python_executable,
            node_executable=node_executable,
            npm_cli=npm_cli,
        )
        store = registry.InstanceRegistry(
            anchor / ".sbom-dev" / "repositories" / snapshot.repository_id / "instances",
            anchor=anchor,
            repository_id=snapshot.repository_id,
        )
        records = store.read()
        present = any(
            os.path.lexists(selected.root / name)
            for name in (".env", ".env.dev.local", "frontend/.env.local", ".windows/sbom.env.ps1")
        )
    return Observation(snapshot, selected, dep, store, records, source, present, instance_manifests)


@dataclass(frozen=True, slots=True)
class PlanRow:
    category: str
    status: str
    code: str
    prerequisites: tuple[str, ...]
    executable: bool = False

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _CATEGORIES
            or type(self.status) is not str
            or self.status not in _STATUSES
            or type(self.code) is not str
            or self.code not in _CODES
            or type(self.prerequisites) is not tuple
            or any(type(value) is not str or value not in _CATEGORIES for value in self.prerequisites)
            or len(set(self.prerequisites)) != len(self.prerequisites)
            or self.category in self.prerequisites
            or type(self.executable) is not bool
            or (self.status == "SKIPPED") != (self.code == "SETUP_NOT_REQUIRED")
            or self.status == "SKIPPED"
            and (self.executable or self.prerequisites)
        ):
            _fail("SETUP_INPUT_INVALID")

    def to_dict(self):
        guidance = "Review the explicit category plan and retain existing settings and artifacts."
        if self.code == "SETUP_NOT_REQUIRED":
            guidance = "This category does not apply to a mock preview. It provides no application, authentication or service readiness."
        elif self.code == "SETUP_NATIVE_ACTIVATION_PENDING":
            guidance = (
                "Complete the existing email activation and password-creation flow; preserve the pending reservation."
            )
        elif self.code == "SETUP_NATIVE_COMPLETED_RESERVATION_PRESERVED":
            guidance = (
                "Preserve the completed enrollment reservation. Completion does not establish a current Platform Admin grant. "
                "Request approved effective-administrator status and recovery review; setup cannot reopen enrollment or create another administrator."
            )
        elif self.category == "onboarding":
            guidance = "Reuse a verified existing account when available. New privileged enrollment needs separate approved authority; this setup cannot create it."
        elif self.category == "dependencies":
            guidance = "Software preparation is independent of private configuration; existing unmanaged artifacts require review."
        return {
            "category": self.category,
            "status": self.status,
            "code": self.code,
            "prerequisites": list(self.prerequisites),
            "executable_after_consent": self.executable,
            "guidance": guidance,
        }


@dataclass(frozen=True, slots=True)
class SetupPlan:
    selection: Selection
    observation: Observation = field(repr=False)
    instance_plan: instances.InstancePlan | None = field(repr=False)
    contexts: Contexts = field(repr=False)
    rows: tuple[PlanRow, ...]
    stage_bindings: tuple[tuple[str, str], ...] = field(repr=False)
    target_fingerprint: str
    fingerprint: str

    def __post_init__(self):
        if (
            type(self.selection) is not Selection
            or type(self.observation) is not Observation
            or self.instance_plan is not None
            and type(self.instance_plan) is not instances.InstancePlan
            or type(self.contexts) is not Contexts
            or type(self.rows) is not tuple
            or any(type(value) is not PlanRow for value in self.rows)
            or tuple(value.category for value in self.rows) != _CATEGORIES
            or any(
                value.prerequisites != _prerequisites(self.selection.mode, value.category)
                or (value.status == "SKIPPED")
                != (self.selection.mode == "mock" and value.category in _MOCK_NOT_REQUIRED)
                for value in self.rows
            )
            or type(self.stage_bindings) is not tuple
            or len(self.stage_bindings) != len(_CATEGORIES)
        ):
            _fail("SETUP_INPUT_INVALID")
        for index, value in enumerate(self.stage_bindings):
            if type(value) is not tuple or len(value) != 2 or value[0] != _CATEGORIES[index]:
                _fail("SETUP_INPUT_INVALID")
            _hash(value[1])
        _hash(self.target_fingerprint)
        _hash(self.fingerprint)

    def to_dict(self):
        selected = self.observation.worktree
        return {
            "version": 1,
            "worktree_id": selected.worktree_id if selected else None,
            "commit": selected.head if selected else None,
            "instance_id": self.instance_plan.descriptor.instance_id if self.instance_plan else None,
            "family": self.selection.family,
            "existing_family_preserved": self.selection.existing_family,
            "mode": self.selection.mode,
            "auth_mode": self.selection.auth_mode,
            "rows": [row.to_dict() for row in self.rows],
            "fingerprint": self.fingerprint,
            "private_values_included": False,
            "privileged_onboarding_authorized": False,
            "application_ready": False,
            "authentication_ready": False,
        }


def _context_matches(context, descriptor):
    basic = (
        context.repository_id,
        context.worktree_id,
        context.instance_id,
        context.commit,
        context.generation,
        context.config_generation,
        context.auth_mode,
    ) == (
        descriptor.repository_id,
        descriptor.worktree_id,
        descriptor.instance_id,
        descriptor.commit,
        descriptor.generation,
        descriptor.config_generation,
        descriptor.auth_mode,
    )
    return basic and (
        descriptor.mode != "isolated"
        or (context.database_name, context.database_port)
        == (descriptor.resources["database"], descriptor.ports["postgres"])
    )


def plan_setup(observation, selection, *, contexts=None, registered_categories=()):
    """Pure immutable consolidated plan, independent of private config for deps."""
    if (
        type(observation) is not Observation
        or type(selection) is not Selection
        or type(registered_categories) is not tuple
        or any(type(value) is not str or value not in _SENSITIVE for value in registered_categories)
    ):
        _fail("SETUP_INPUT_INVALID")
    contexts = contexts or Contexts()
    if type(contexts) is not Contexts:
        _fail("SETUP_INPUT_INVALID")
    selected, dep = observation.worktree, observation.dependency_plan
    valid = (
        observation.repository.status == "PASS"
        and selected is not None
        and selected in observation.repository.worktrees
        and (selection.worktree_id is None or selection.worktree_id == selected.worktree_id)
        and selected.status == "PASS"
        and selected.identity is not None
        and selected.head is not None
        and not any((selected.bare, selected.locked, selected.prunable))
    )
    existing = next(
        (
            entry
            for entry in observation.registry_snapshot.entries
            if selected and entry.descriptor.worktree_id == selected.worktree_id
        ),
        None,
    )
    instance = None
    if valid and selection.mode is not None and selection.auth_mode is not None:
        claims = tuple(
            port
            for entry in observation.registry_snapshot.entries
            if entry is not existing
            for port in entry.descriptor.ports.values()
        )
        instance = instances.plan_instance(
            repository_id=observation.repository.repository_id,
            worktree_id=selected.worktree_id,
            commit=selected.head,
            generation=selection.generation,
            mode=selection.mode,
            auth_mode=selection.auth_mode,
            provider=selection.provider,
            manifest_hashes=dict(observation.instance_manifest_hashes) or (dict(dep.manifest_hashes) if dep else {}),
            claimed_ports=claims,
            config_generation=existing.descriptor.config_generation if existing else None,
            config_present=existing.descriptor.configuration_present if existing else False,
        )
    basis = [
        observation.repository.repository_id,
        selected.worktree_id if selected else None,
        selected.head if selected else None,
        [selected.identity.device, selected.identity.inode] if selected and selected.identity else None,
        observation.controller_fingerprint,
        dict(observation.instance_manifest_hashes) or (dict(dep.manifest_hashes) if dep else {}),
        selection.__dict__
        if hasattr(selection, "__dict__")
        else [getattr(selection, name) for name in selection.__dataclass_fields__],
        instance.fingerprint if instance else None,
    ]
    target = _digest(basis)
    rows = []

    def add(category, status, code, executable=False):
        rows.append(PlanRow(category, status, code, _prerequisites(selection.mode, category), executable))

    family_conflict = selection.existing_family is not None and selection.family != selection.existing_family
    if family_conflict:
        add("selection", "INCOMPATIBLE", "SETUP_FAMILY_CONVERSION_REFUSED")
    elif observation.private_configuration_present and selection.existing_family is None:
        add("selection", "BLOCKED", "SETUP_EXISTING_FAMILY_REVIEW_REQUIRED")
    elif not valid or instance is None or selection.family is None:
        add("selection", "MISSING", "SETUP_SELECTION_REQUIRED")
    else:
        add("selection", "READY", "SETUP_SELECTION_READY")
    registry_unknown = observation.registry_snapshot.codes not in {(), ("REGISTRY_MISSING",)}
    if registry_unknown or not valid:
        add("registry", "BLOCKED", "SETUP_REGISTRY_UNKNOWN")
    elif rows[0].status != "READY":
        add("registry", "BLOCKED", "SETUP_PREREQUISITE_BLOCKED")
    elif existing and existing.descriptor != instance.descriptor:
        metadata_only = (
            replace(
                existing.descriptor,
                commit=instance.descriptor.commit,
                manifest_hashes=instance.descriptor.manifest_hashes,
            )
            == instance.descriptor
        )
        if metadata_only and existing.state in {"PLANNED", "PREPARED", "STOPPED"}:
            add("registry", "NEEDS_APPROVAL", "SETUP_REGISTRY_SOURCE_REVIEW_REQUIRED", True)
        else:
            add("registry", "INCOMPATIBLE", "SETUP_CONTEXT_INCOMPATIBLE")
    elif existing:
        add("registry", "READY", "SETUP_REGISTRY_READY")
    else:
        add("registry", "NEEDS_APPROVAL", "SETUP_REGISTRY_APPROVAL_REQUIRED", True)
    if not valid or dep is None or dep.blockers:
        add("dependencies", "BLOCKED", "SETUP_DEPENDENCIES_BLOCKED")
    elif all(dep.target_stamps.get(name) for name in ("python", "frontend")):
        add("dependencies", "READY", "SETUP_DEPENDENCIES_READY")
    else:
        add("dependencies", "NEEDS_APPROVAL", "SETUP_DEPENDENCIES_APPROVAL_REQUIRED", True)
    supplied = {value.category: value for value in contexts.stages}

    def prerequisite_status(parent):
        previous = next((value for value in rows if value.category == parent), None)
        if previous is not None:
            return previous.status
        future = supplied.get(parent)
        return future.status if future and future.target_fingerprint == target else "BLOCKED"

    for category in _CATEGORIES[3:-1]:
        if selection.mode == "mock" and category in _MOCK_NOT_REQUIRED:
            add(category, "SKIPPED", "SETUP_NOT_REQUIRED")
            continue
        context = supplied.get(category)
        if context is None:
            add(
                category,
                "MISSING" if category in {"private-credentials", "certificates"} else "BLOCKED",
                "SETUP_CONTEXT_REQUIRED",
            )
        elif context.target_fingerprint != target:
            add(category, "INCOMPATIBLE", "SETUP_CONTEXT_INCOMPATIBLE")
        elif context.status == "READY":
            add(category, "READY", "SETUP_STAGE_READY")
        elif context.status in {"BLOCKED", "INCOMPATIBLE", "WARN"}:
            add(
                category,
                context.status,
                "SETUP_CONTEXT_INCOMPATIBLE" if context.status == "INCOMPATIBLE" else "SETUP_CONTEXT_REQUIRED",
            )
        elif category not in registered_categories:
            add(category, "BLOCKED", "SETUP_ADAPTER_REQUIRED")
        elif any(
            prerequisite_status(parent) not in {"READY", "NEEDS_APPROVAL"}
            for parent in _prerequisites(selection.mode, category)
        ):
            add(category, "BLOCKED", "SETUP_PREREQUISITE_BLOCKED")
        else:
            add(category, "NEEDS_APPROVAL", "SETUP_STAGE_APPROVAL_REQUIRED", True)
    onboard = contexts.onboarding_plan
    if selection.mode == "mock":
        add("onboarding", "SKIPPED", "SETUP_NOT_REQUIRED")
    elif (
        instance
        and onboard
        and onboard.context.auth_mode == "native"
        and _context_matches(onboard.context, instance.descriptor)
    ):
        states = {
            "EXISTING_ADMIN": ("READY", "SETUP_NATIVE_ADMIN_EXISTS"),
            "ENROLLMENT_COMPLETED": ("WARN", "SETUP_NATIVE_COMPLETED_RESERVATION_PRESERVED"),
            "ENROLLMENT_PENDING": ("WARN", "SETUP_NATIVE_ACTIVATION_PENDING"),
            "ENROLLMENT_REQUIRED": ("NEEDS_APPROVAL", "SETUP_NATIVE_ENROLLMENT_APPROVAL_REQUIRED"),
        }
        add("onboarding", *states.get(onboard.state, ("BLOCKED", "SETUP_ONBOARDING_UNKNOWN")))
    elif (
        instance
        and contexts.external_identity
        and _context_matches(contexts.external_identity.context, instance.descriptor)
        and contexts.external_identity.state == "EXISTING_AUTHORIZED"
    ):
        add("onboarding", "READY", "SETUP_HCL_IDENTITY_EXISTS")
    else:
        add(
            "onboarding",
            "BLOCKED",
            "SETUP_HCL_PROVISIONING_APPROVAL_REQUIRED" if selection.auth_mode == "hcl" else "SETUP_ONBOARDING_UNKNOWN",
        )
    # Preview is displayed near certificates but can depend on later provider
    # or schema rows. Resolve forward prerequisite failures before publication.
    for _ in _CATEGORIES:
        statuses = {value.category: value.status for value in rows}
        updated = [
            replace(value, status="BLOCKED", code="SETUP_PREREQUISITE_BLOCKED", executable=False)
            if value.status == "NEEDS_APPROVAL"
            and value.executable
            and any(statuses[parent] not in {"READY", "NEEDS_APPROVAL"} for parent in value.prerequisites)
            else value
            for value in rows
        ]
        if updated == rows:
            break
        rows = updated
    bindings = []
    for row in rows:
        if row.category == "dependencies":
            value = dep.fingerprint if dep else None
        elif row.category == "registry":
            value = [
                existing.to_dict() if existing else None,
                [(entry.descriptor.instance_id, entry.revision) for entry in observation.registry_snapshot.entries],
                registry_unknown,
            ]
        else:
            context = supplied.get(row.category)
            value = (
                [context.status, context.reference, context.target_fingerprint]
                if context and row.status != "SKIPPED"
                else [row.status, row.code]
            )
        bindings.append((row.category, _digest([target, value])))
    fingerprint = _digest([target, [row.to_dict() for row in rows], bindings])
    return SetupPlan(selection, observation, instance, contexts, tuple(rows), tuple(bindings), target, fingerprint)


@dataclass(frozen=True, slots=True)
class StageConsent:
    category: str
    plan_fingerprint: str
    target_fingerprint: str
    issued_at: float
    expires_at: float

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _CATEGORIES
            or any(
                type(value) not in {int, float} or not math.isfinite(value)
                for value in (self.issued_at, self.expires_at)
            )
            or not self.issued_at < self.expires_at <= self.issued_at + 120
        ):
            _fail("SETUP_CONSENT_REQUIRED")
        _hash(self.plan_fingerprint)
        _hash(self.target_fingerprint)


@dataclass(frozen=True, slots=True)
class StageAuthority:
    category: str
    target_fingerprint: str
    stage_binding: str
    checks: frozenset[str]

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _SENSITIVE
            or type(self.checks) is not frozenset
            or any(type(value) is not str or value not in _AUTHORITY[self.category] for value in self.checks)
        ):
            _fail("SETUP_AUTHORITY_REQUIRED")
        _hash(self.target_fingerprint)
        _hash(self.stage_binding)


@dataclass(frozen=True, slots=True)
class StageOutcome:
    category: str
    status: str
    code: str
    completed_categories: tuple[str, ...] = ()
    artifacts_retained: bool = False

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _CATEGORIES
            or type(self.status) is not str
            or self.status not in {"COMPLETED", "SKIPPED", "BLOCKED", "FAILED"}
            or type(self.code) is not str
            or self.code not in _CODES
            or type(self.completed_categories) is not tuple
            or any(value not in _CATEGORIES for value in self.completed_categories)
            or type(self.artifacts_retained) is not bool
        ):
            _fail("SETUP_INPUT_INVALID")
        if (
            self.status == "COMPLETED"
            and self.category not in self.completed_categories
            or self.status != "COMPLETED"
            and self.completed_categories
        ):
            _fail("SETUP_INPUT_INVALID")

    def to_dict(self):
        return {
            "category": self.category,
            "status": self.status,
            "code": self.code,
            "completed_categories": list(self.completed_categories),
            "artifacts_retained": self.artifacts_retained,
        }


@dataclass(frozen=True, slots=True)
class StageAdapter:
    category: str
    execute: object = field(repr=False)
    authorize: object = field(repr=False)
    required_categories: tuple[str, ...] = ()

    def __post_init__(self):
        if (
            type(self.category) is not str
            or self.category not in _SENSITIVE
            or not callable(self.execute)
            or not callable(self.authorize)
            or type(self.required_categories) is not tuple
            or any(type(value) is not str or value not in _SENSITIVE for value in self.required_categories)
        ):
            _fail("SETUP_INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class SetupOutcome:
    code: str
    exit_code: int
    stages: tuple[StageOutcome, ...] = ()

    def __post_init__(self):
        if (
            type(self.code) is not str
            or self.code not in _CODES
            or type(self.exit_code) is not int
            or self.exit_code not in {0, 1, 130}
            or type(self.stages) is not tuple
            or any(type(value) is not StageOutcome for value in self.stages)
        ):
            _fail("SETUP_INPUT_INVALID")

    def to_dict(self):
        return {
            "code": self.code,
            "exit_code": self.exit_code,
            "stages": [value.to_dict() for value in self.stages],
            "automatic_rollback": False,
            "automatic_retry": False,
            "privileged_onboarding_authorized": False,
            "application_ready": False,
            "authentication_ready": False,
        }


class SetupExecutor:
    def __init__(self, *, reobserve, adapters=(), clock=time.monotonic, journal=None, dependency_runner=None):
        if (
            not callable(reobserve)
            or not callable(clock)
            or type(adapters) is not tuple
            or any(type(value) is not StageAdapter for value in adapters)
            or len({value.category for value in adapters}) != len(adapters)
            or journal is not None
            and not callable(getattr(journal, "record", None))
        ):
            _fail("SETUP_INPUT_INVALID")
        self.reobserve, self.adapters, self.clock, self.journal = (
            reobserve,
            {value.category: value for value in adapters},
            clock,
            journal,
        )
        self.dependency_runner, self.used = dependency_runner, set()

    def execute_selected(self, plan, selected, consents, *, check=False, interactive=False):
        if (
            type(plan) is not SetupPlan
            or type(selected) is not tuple
            or any(type(value) is not str or value not in _CATEGORIES for value in selected)
            or len(set(selected)) != len(selected)
            or type(consents) is not tuple
            or any(type(value) is not StageConsent for value in consents)
            or len({value.category for value in consents}) != len(consents)
        ):
            _fail("SETUP_INPUT_INVALID")
        if type(check) is not bool or type(interactive) is not bool:
            _fail("SETUP_INPUT_INVALID")
        if check or not interactive:
            return SetupOutcome(
                "SETUP_READ_ONLY",
                1 if any(row.status not in {"READY", "SKIPPED"} for row in plan.rows) else 0,
                tuple(
                    StageOutcome(
                        row.category, "SKIPPED", "SETUP_NOT_REQUIRED" if row.status == "SKIPPED" else "SETUP_READ_ONLY"
                    )
                    for row in plan.rows
                ),
            )
        if not selected:
            return SetupOutcome(
                "SETUP_READ_ONLY", 1 if any(row.status not in {"READY", "SKIPPED"} for row in plan.rows) else 0
            )
        approvals, results, completed = {value.category: value for value in consents}, [], set()
        initial = dict(plan.stage_bindings)
        active_adapter = None

        def prerequisites_valid(current, category):
            for parent in next(value for value in current.rows if value.category == category).prerequisites:
                fresh = next(value for value in current.rows if value.category == parent)
                if (
                    fresh.status not in {"READY", "NEEDS_APPROVAL"}
                    or fresh.status != "READY"
                    and parent not in completed
                ):
                    _fail("SETUP_PREREQUISITE_BLOCKED")
                if parent in _SENSITIVE:
                    before = next((value for value in plan.contexts.stages if value.category == parent), None)
                    after = next((value for value in current.contexts.stages if value.category == parent), None)
                    if (
                        before is None
                        or after is None
                        or (before.reference, before.target_fingerprint) != (after.reference, after.target_fingerprint)
                    ):
                        _fail("SETUP_DRIFT_DETECTED")

        def guard(category):
            consent = approvals.get(category)
            if consent is None or (consent.plan_fingerprint, consent.target_fingerprint) != (
                plan.fingerprint,
                plan.target_fingerprint,
            ):
                _fail("SETUP_CONSENT_REQUIRED")
            now = self.clock()
            if not consent.issued_at <= now <= consent.expires_at:
                _fail("SETUP_CONSENT_EXPIRED")
            current = self.reobserve(plan.selection)
            if (
                type(current) is not SetupPlan
                or current.target_fingerprint != plan.target_fingerprint
                or dict(current.stage_bindings).get(category) != initial.get(category)
            ):
                _fail("SETUP_DRIFT_DETECTED")
            fresh_row = next(value for value in current.rows if value.category == category)
            if fresh_row.status not in {"READY", "NEEDS_APPROVAL"}:
                _fail("SETUP_DRIFT_DETECTED")
            prerequisites_valid(current, category)
            if not consent.issued_at <= self.clock() <= consent.expires_at:
                _fail("SETUP_CONSENT_EXPIRED")
            if category in _SENSITIVE:
                adapter = (
                    active_adapter
                    if active_adapter is not None
                    and category in {active_adapter.category, *active_adapter.required_categories}
                    else self.adapters.get(category)
                )
                if adapter is None:
                    _fail("SETUP_ADAPTER_REQUIRED")
                proof = adapter.authorize(current, consent)
                if (
                    type(proof) is not StageAuthority
                    or proof.category != category
                    or proof.target_fingerprint != plan.target_fingerprint
                    or proof.stage_binding != initial[category]
                    or not _AUTHORITY[category] <= proof.checks
                ):
                    _fail("SETUP_AUTHORITY_REQUIRED")
            if not consent.issued_at <= self.clock() <= consent.expires_at:
                _fail("SETUP_CONSENT_EXPIRED")
            return current

        remaining, execution_order = list(plan.rows), []
        while remaining:
            value = next((value for value in remaining if set(value.prerequisites) <= set(execution_order)), None)
            if value is None:
                _fail("SETUP_INPUT_INVALID")
            execution_order.append(value.category)
            remaining.remove(value)
        for category in execution_order:
            row = next(value for value in plan.rows if value.category == category)
            if row.status == "SKIPPED":
                results.append(StageOutcome(category, "SKIPPED", "SETUP_NOT_REQUIRED"))
                continue
            if category not in selected:
                results.append(StageOutcome(category, "SKIPPED", "SETUP_NOT_SELECTED"))
                continue
            if category in completed:
                results.append(StageOutcome(category, "SKIPPED", "SETUP_ALREADY_READY"))
                continue
            if row.status == "READY":
                results.append(StageOutcome(category, "SKIPPED", "SETUP_ALREADY_READY"))
                completed.add(category)
                continue
            if category == "onboarding":
                results.append(StageOutcome(category, "BLOCKED", "SETUP_PRIVILEGED_ONBOARDING_GATED"))
                continue
            attempted = False
            try:
                if not row.executable or row.status != "NEEDS_APPROVAL":
                    _fail("SETUP_SCOPE_REFUSED")
                if any(
                    next(item for item in plan.rows if item.category == parent).status != "READY"
                    and parent not in completed
                    for parent in row.prerequisites
                ):
                    _fail("SETUP_PREREQUISITE_BLOCKED")
                consent = approvals.get(category)
                active_adapter = self.adapters.get(category)
                required = tuple(
                    dict.fromkeys((category, *(active_adapter.required_categories if active_adapter else ())))
                )
                if any(scope not in selected for scope in required):
                    _fail("SETUP_SCOPE_REFUSED")
                if any(approvals.get(scope) in self.used for scope in required):
                    _fail("SETUP_CONSENT_REQUIRED")
                for scope in required:
                    current = guard(scope)
                self.used.update(approvals[scope] for scope in required)
                if category == "dependencies":
                    attempted = True
                    dependency_refusal = None

                    def dependency_command(command, _consent=consent, **options):
                        # The existing dependency adapter revalidates its source,
                        # tools and owned paths internally. Re-observing while
                        # its private pending record exists would reject its own
                        # operation, so check expiry here before each owned child.
                        nonlocal dependency_refusal
                        if not _consent.issued_at <= self.clock() <= _consent.expires_at:
                            dependency_refusal = "SETUP_CONSENT_EXPIRED"
                            _fail("SETUP_CONSENT_EXPIRED")
                        return (self.dependency_runner or workspace._run_git)(command, **options)

                    outcome = dependencies.prepare_dependencies(
                        current.observation.dependency_plan,
                        authorize=lambda _plan, category=category: bool(guard(category)),
                        runner=dependency_command,
                    )
                    if outcome.exit_code == 130:
                        result = StageOutcome(
                            category,
                            "FAILED",
                            "SETUP_PARTIAL_RETAINED" if outcome.artifacts_retained else "SETUP_CANCELLED",
                            artifacts_retained=outcome.artifacts_retained,
                        )
                        results.append(result)
                        if self.journal is not None:
                            try:
                                self.journal.record(plan, result)
                            except Exception:
                                results.append(
                                    StageOutcome(
                                        category,
                                        "FAILED",
                                        "SETUP_JOURNAL_UNCONFIRMED",
                                        artifacts_retained=outcome.artifacts_retained,
                                    )
                                )
                        return SetupOutcome(result.code, 130, tuple(results))
                    result = StageOutcome(
                        category,
                        "COMPLETED" if outcome.exit_code == 0 else "FAILED",
                        "SETUP_STAGE_COMPLETED"
                        if outcome.exit_code == 0
                        else dependency_refusal or "SETUP_STAGE_FAILED",
                        (category,) if outcome.exit_code == 0 else (),
                        outcome.artifacts_retained,
                    )
                elif category == "registry":
                    store = current.observation.registry_store
                    if store is None or current.instance_plan is None:
                        _fail("SETUP_SCOPE_REFUSED")
                    previous = next(
                        (
                            entry
                            for entry in current.observation.registry_snapshot.entries
                            if entry.descriptor.worktree_id == current.instance_plan.descriptor.worktree_id
                        ),
                        None,
                    )
                    guard(category)
                    attempted = True
                    storage.initialize_private_directory(store.root, anchor=store.anchor)
                    guard(category)
                    revision = previous.revision if previous else 0
                    store.publish(
                        registry.RegistryEntry(
                            current.instance_plan.descriptor,
                            revision=revision + 1,
                            state=previous.state if previous else "PLANNED",
                            last_code=previous.last_code if previous else None,
                            plan_fingerprint=current.instance_plan.fingerprint,
                            operations=(*(previous.operations if previous else ()), "REGISTRY_PREPARED"),
                        ),
                        expected_revision=revision,
                    )
                    result = StageOutcome(category, "COMPLETED", "SETUP_STAGE_COMPLETED", (category,), True)
                else:
                    adapter = self.adapters.get(category)
                    if adapter is None:
                        _fail("SETUP_ADAPTER_REQUIRED")
                    attempted = True
                    result = adapter.execute(current, guard)
                    if (
                        type(result) is not StageOutcome
                        or result.category != category
                        or not set(result.completed_categories) <= set(required)
                    ):
                        _fail("SETUP_SCOPE_REFUSED")
                results.append(result)
                completed.update(result.completed_categories)
                if self.journal is not None:
                    self.journal.record(plan, result)
            except (KeyboardInterrupt, EOFError):
                results.append(
                    StageOutcome(
                        category,
                        "FAILED",
                        "SETUP_PARTIAL_RETAINED" if attempted else "SETUP_CANCELLED",
                        artifacts_retained=attempted,
                    )
                )
                return SetupOutcome("SETUP_PARTIAL_RETAINED" if attempted else "SETUP_CANCELLED", 130, tuple(results))
            except Exception as error:
                code = (
                    "SETUP_PARTIAL_RETAINED"
                    if attempted
                    else error.code
                    if isinstance(error, SetupError)
                    else "SETUP_OBSERVATION_BLOCKED"
                )
                results.append(
                    StageOutcome(category, "FAILED" if attempted else "BLOCKED", code, artifacts_retained=attempted)
                )
        failed = any(value.status in {"FAILED", "BLOCKED"} for value in results)
        return SetupOutcome(
            "SETUP_PARTIAL_RETAINED"
            if failed and completed
            else "SETUP_STAGE_FAILED"
            if failed
            else "SETUP_STAGE_COMPLETED",
            1 if failed else 0,
            tuple(results),
        )


class TerminalIO:
    def interactive(self):
        return sys.stdin.isatty() and sys.stdout.isatty()

    def choose_selection(self, selection):
        options = (
            ("isolated", "native"),
            ("isolated", "hcl"),
            ("mock", "native"),
            ("mock", "hcl"),
            ("shared-backend", "native"),
            ("shared-backend", "hcl"),
        )
        answer = input(
            "Select 1 isolated Native, 2 isolated HCL, 3 mock Native, 4 mock HCL, 5 shared Native, 6 shared HCL (blank cancels): "
        )
        if answer not in {str(index) for index in range(1, 7)}:
            _fail("SETUP_CANCELLED")
        mode, auth = options[int(answer) - 1]
        return replace(
            selection, mode=mode, auth_mode=auth, family=selection.existing_family or selection.family or "instance"
        )

    def display(self, plan):
        print(json.dumps(plan.to_dict(), sort_keys=True, indent=2))

    def approve_categories(self, choices):
        answer = input("Approve only these categories, comma-separated; blank means none: " + ", ".join(choices) + ": ")
        values = tuple(value.strip() for value in answer.split(",") if value.strip())
        if len(set(values)) != len(values) or any(value not in choices for value in values):
            _fail("SETUP_CONSENT_REQUIRED")
        return values


def guided_session(selection, *, planner, executor, io=None, check=False, clock=time.monotonic):
    io = io or TerminalIO()
    try:
        plan = planner(selection)
        interactive = not check and io.interactive()
        if interactive and (selection.mode is None or selection.auth_mode is None or selection.family is None):
            selection = io.choose_selection(selection)
            plan = planner(selection)
        io.display(plan)
        if not interactive:
            return executor.execute_selected(plan, (), (), check=True, interactive=False)
        choices = tuple(row.category for row in plan.rows if row.executable and row.status == "NEEDS_APPROVAL")
        selected = io.approve_categories(choices)
        now = clock()
        consents = tuple(
            StageConsent(category, plan.fingerprint, plan.target_fingerprint, now, now + 120) for category in selected
        )
        return executor.execute_selected(plan, selected, consents, interactive=True)
    except (KeyboardInterrupt, EOFError):
        return SetupOutcome("SETUP_CANCELLED", 130)
    except SetupError as error:
        return SetupOutcome(error.code, 130 if error.code == "SETUP_CANCELLED" else 1)
    except Exception:
        return SetupOutcome("SETUP_OBSERVATION_BLOCKED", 1)
