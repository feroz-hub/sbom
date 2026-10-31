"""Pure public proposals for future development instances, never live resources.

Inputs are caller-supplied public metadata. This module never discovers a checkout,
reads configuration, allocates ports, authorizes an action or imports the app.
Deterministic identifiers and registry port claims are proposals, not ownership.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MANIFESTS = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/next.config.js",
        "frontend/next.config.mjs",
        "frontend/next.config.ts",
        "frontend/tsconfig.json",
        "controller/scripts/dev.py",
        "controller/scripts/dev_workspace.py",
        "controller/scripts/dev_workspace_cli.py",
        "controller/scripts/dev_instance_plan.py",
        "controller/scripts/dev_instance_registry.py",
        "controller/scripts/dev_instance_storage.py",
    }
)
_RESERVED_PORTS = frozenset({1025, 1026, 3000, 5432, 6379, 8000, 8025, 8026, 13000, 18000, 55439, 56044, 56379, 56381})
_PORTS = {
    "isolated": ("api", "frontend", "postgres", "redis", "smtp", "mailpit_ui"),
    "mock": ("frontend",),
    "shared-backend": ("frontend",),
}
_PROVIDERS = {"isolated": {"container", "local"}, "mock": {"mock"}, "shared-backend": {"shared"}}
_DEFAULT_PROVIDER = {"isolated": "container", "mock": "mock", "shared-backend": "shared"}
_ACTION_CATEGORIES = {
    "prepare-dependencies": "software-dependencies",
    "review-private-configuration": "private-configuration",
    "review-provider-policy": "providers",
    "prepare-isolated-providers": "providers",
    "review-database-preparation": "database",
    "review-native-enrollment": "administrator",
    "review-shared-backend-registration": "shared-backend",
    "review-hcl-registration": "identity-provider",
    "review-certificate-material": "certificates",
    "review-certificate-trust": "trust",
}
_BLOCKER_CATEGORIES = {
    "SOFTWARE_PREPARATION_APPROVAL_REQUIRED": "software-dependencies",
    "PRIVATE_CONFIGURATION_REVIEW_REQUIRED": "private-configuration",
    "PRIVATE_CONFIGURATION_MISSING": "private-configuration",
    "CONFIGURATION_GENERATION_REQUIRED": "private-configuration",
    "CONTAINER_ENGINE_APPROVAL_REQUIRED": "providers",
    "LOCAL_ISOLATION_POLICY_REQUIRED": "providers",
    "PROVIDER_PREPARATION_APPROVAL_REQUIRED": "providers",
    "DATABASE_PREPARATION_APPROVAL_REQUIRED": "database",
    "NATIVE_ENROLLMENT_GATED": "administrator",
    "SHARED_BACKEND_REGISTRATION_REQUIRED": "shared-backend",
    "HCL_REGISTRATION_APPROVAL_REQUIRED": "identity-provider",
    "CERTIFICATE_PREPARATION_APPROVAL_REQUIRED": "certificates",
    "CERTIFICATE_TRUST_APPROVAL_REQUIRED": "trust",
    "INSTANCE_LIVE_OPERATIONS_GATED": "authorization",
}
_NAMESPACE = uuid.UUID("e115a24a-39ba-5688-9e73-920e13ed0577")
_DESCRIPTOR_FIELDS = frozenset(
    {
        "version",
        "instance_id",
        "repository_id",
        "worktree_id",
        "commit",
        "generation",
        "config_generation",
        "configuration_present",
        "mode",
        "auth_mode",
        "provider",
        "hostname",
        "origin",
        "ports",
        "resources",
        "manifest_hashes",
        "proposal_only",
        "ownership_verified",
        "live_operations_authorized",
    }
)


class InstancePlanError(ValueError):
    """A fixed safe category; never interpolate caller values or exceptions."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _refuse(code):
    raise InstancePlanError(code) from None


def _integer(value, low, high, code):
    if type(value) is not int or not low <= value <= high:
        _refuse(code)
    return value


def _public_id(value):
    if type(value) is not str:
        _refuse("INSTANCE_PUBLIC_ID_INVALID")
    if _SHA256.fullmatch(value):
        return value
    try:
        if str(uuid.UUID(value)) == value:
            return value
    except (ValueError, AttributeError):
        pass
    _refuse("INSTANCE_PUBLIC_ID_INVALID")


def _configuration_generation(value):
    if value is None:
        return None
    if type(value) is int:
        return _integer(value, 1, 2147483647, "INSTANCE_CONFIG_GENERATION_INVALID")
    return _public_id(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _instance_id(repository_id, worktree_id, generation):
    return str(uuid.uuid5(_NAMESPACE, _canonical([1, repository_id, worktree_id, generation]).decode("ascii")))


def _manifests(values):
    if not isinstance(values, Mapping) or len(values) > len(_MANIFESTS):
        _refuse("INSTANCE_MANIFESTS_INVALID")
    snapshot = dict(values)
    if any(
        type(key) is not str or key not in _MANIFESTS or type(value) is not str or not _SHA256.fullmatch(value)
        for key, value in snapshot.items()
    ):
        _refuse("INSTANCE_MANIFESTS_INVALID")
    return MappingProxyType(dict(sorted(snapshot.items())))


def _resources(instance_id, mode):
    token = uuid.UUID(instance_id).hex
    resources = {
        "frontend": "sbom-dev-" + token + "-frontend",
        "artifacts": "sbom-dev-" + token + "-artifacts",
        "logs": "sbom-dev-" + token + "-logs",
        "venv": "sbom-dev-" + token + "-venv",
        "frontend_dependencies": "sbom-dev-" + token + "-node-modules",
        "frontend_workspace": "sbom-dev-" + token + "-frontend-workspace",
        "tls_leaf": "sbom-dev-" + token + "-leaf",
    }
    if mode != "mock":
        # Proposed BFF key domain only; this selects no Redis target or key.
        resources["session_namespace"] = "sbom:bff:" + token + ":"
    if mode == "isolated":
        resources.update(
            database="sbom_dev_" + token,
            restricted_database_role="sbom_dev_" + token + "_runtime",
            network="sbom-dev-" + token + "-network",
            postgres="sbom-dev-" + token + "-postgres",
            postgres_volume="sbom-dev-" + token + "-postgres-data",
            redis="sbom-dev-" + token + "-redis",
            redis_volume="sbom-dev-" + token + "-redis-data",
            mailpit="sbom-dev-" + token + "-mailpit",
            worker_default="sbom-dev-" + token + "-worker",
            worker_reports="sbom-dev-" + token + "-reports",
            beat="sbom-dev-" + token + "-beat",
            beat_schedule="sbom-dev-" + token + "-beat-schedule",
            queue_default="sbom.dev." + token + ".default",
            queue_reports="sbom.dev." + token + ".reports",
            beat_namespace="sbom:dev:" + token + ":beat",
            rate_limit_namespace="sbom:iam:" + token + ":",
        )
    return MappingProxyType(resources)


def _port_set(values):
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes, Mapping)):
        _refuse("INSTANCE_PORT_CLAIMS_INVALID")
    result = set()
    for index, value in enumerate(values):
        if index >= 65535:
            _refuse("INSTANCE_PORT_CLAIMS_INVALID")
        result.add(_integer(value, 1, 65535, "INSTANCE_PORT_CLAIMS_INVALID"))
    return tuple(sorted(result))


def _action_codes(values, *, empty=True):
    if type(values) not in {list, tuple} or len(values) > len(_ACTION_CATEGORIES):
        _refuse("INSTANCE_ACTIONS_INVALID")
    if any(type(value) is not str or value not in _ACTION_CATEGORIES for value in values):
        _refuse("INSTANCE_ACTIONS_INVALID")
    if len(set(values)) != len(values) or (not empty and not values):
        _refuse("INSTANCE_ACTIONS_INVALID")
    return tuple(values)


def _propose_ports(instance_id, names, port_range, unavailable):
    if type(port_range) not in {tuple, list} or len(port_range) != 2:
        _refuse("INSTANCE_PORT_RANGE_INVALID")
    low, high = (_integer(value, 1024, 65535, "INSTANCE_PORT_RANGE_INVALID") for value in port_range)
    if low > high:
        _refuse("INSTANCE_PORT_RANGE_INVALID")
    width = high - low + 1
    start = int(hashlib.sha256(instance_id.encode("ascii")).hexdigest(), 16) % width
    available = []
    for offset in range(width):
        port = low + (start + offset) % width
        if port not in unavailable:
            available.append(port)
        if len(available) == len(names):
            return MappingProxyType(dict(zip(names, available, strict=True)))
    _refuse("INSTANCE_PORT_RANGE_EXHAUSTED")


@dataclass(frozen=True, slots=True)
class InstanceDescriptor:
    version: int
    instance_id: str
    repository_id: str
    worktree_id: str
    commit: str
    generation: int
    config_generation: str | int | None
    configuration_present: bool
    mode: str
    auth_mode: str
    provider: str
    hostname: str
    origin: str
    ports: Mapping[str, int]
    resources: Mapping[str, str]
    manifest_hashes: Mapping[str, str]
    proposal_only: bool = True
    ownership_verified: bool = False
    live_operations_authorized: bool = False

    def __post_init__(self):
        if type(self.version) is not int or self.version != 1:
            _refuse("INSTANCE_DESCRIPTOR_VERSION_INVALID")
        _public_id(self.repository_id)
        _public_id(self.worktree_id)
        _integer(self.generation, 1, 2147483647, "INSTANCE_GENERATION_INVALID")
        _configuration_generation(self.config_generation)
        if type(self.commit) is not str or not _COMMIT.fullmatch(self.commit):
            _refuse("INSTANCE_COMMIT_INVALID")
        if type(self.configuration_present) is not bool:
            _refuse("INSTANCE_CONFIGURATION_STATUS_INVALID")
        if type(self.mode) is not str or self.mode not in _PORTS:
            _refuse("INSTANCE_MODE_INVALID")
        if type(self.auth_mode) is not str or self.auth_mode not in {"native", "hcl"}:
            _refuse("INSTANCE_AUTH_MODE_INVALID")
        if type(self.provider) is not str or self.provider not in _PROVIDERS[self.mode]:
            _refuse("INSTANCE_PROVIDER_INVALID")
        if type(self.instance_id) is not str or self.instance_id != _instance_id(
            self.repository_id, self.worktree_id, self.generation
        ):
            _refuse("INSTANCE_ID_MISMATCH")
        expected_host = "sbom-" + uuid.UUID(self.instance_id).hex + ".localhost"
        if type(self.hostname) is not str or self.hostname != expected_host:
            _refuse("INSTANCE_ORIGIN_INVALID")
        if (
            not isinstance(self.ports, Mapping)
            or any(type(key) is not str for key in self.ports)
            or set(self.ports) != set(_PORTS[self.mode])
        ):
            _refuse("INSTANCE_PORTS_INVALID")
        ports = dict(self.ports)
        for value in ports.values():
            _integer(value, 1024, 65535, "INSTANCE_PORTS_INVALID")
        if len(set(ports.values())) != len(ports) or set(ports.values()) & _RESERVED_PORTS:
            _refuse("INSTANCE_PORTS_INVALID")
        if type(self.origin) is not str or self.origin != "https://" + expected_host + ":" + str(ports["frontend"]):
            _refuse("INSTANCE_ORIGIN_INVALID")
        if not isinstance(self.resources, Mapping) or dict(self.resources) != dict(
            _resources(self.instance_id, self.mode)
        ):
            _refuse("INSTANCE_RESOURCES_INVALID")
        if (
            self.proposal_only is not True
            or self.ownership_verified is not False
            or self.live_operations_authorized is not False
        ):
            _refuse("INSTANCE_AUTHORIZATION_FLAGS_INVALID")
        object.__setattr__(self, "ports", MappingProxyType(ports))
        object.__setattr__(self, "resources", _resources(self.instance_id, self.mode))
        object.__setattr__(self, "manifest_hashes", _manifests(self.manifest_hashes))

    def to_dict(self):
        return {
            name: dict(value) if isinstance(value, Mapping) else value
            for name in sorted(_DESCRIPTOR_FIELDS)
            for value in (getattr(self, name),)
        }

    @classmethod
    def from_dict(cls, raw):
        if type(raw) is not dict or set(raw) != _DESCRIPTOR_FIELDS:
            _refuse("INSTANCE_DESCRIPTOR_FIELDS_INVALID")
        if any(type(raw[name]) is not dict for name in ("ports", "resources", "manifest_hashes")):
            _refuse("INSTANCE_DESCRIPTOR_FIELDS_INVALID")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class PlanAction:
    code: str
    category: str
    prerequisites: tuple[str, ...] = ()
    requires_configuration: bool = False
    requires_approval: bool = True
    executable: bool = False

    def __post_init__(self):
        if type(self.code) is not str or self.code not in _ACTION_CATEGORIES:
            _refuse("INSTANCE_ACTIONS_INVALID")
        if (
            type(self.category) is not str
            or self.category != _ACTION_CATEGORIES[self.code]
            or type(self.requires_configuration) is not bool
        ):
            _refuse("INSTANCE_ACTIONS_INVALID")
        if self.requires_approval is not True or self.executable is not False:
            _refuse("INSTANCE_AUTHORIZATION_FLAGS_INVALID")
        prerequisites = _action_codes(self.prerequisites)
        if self.code in prerequisites:
            _refuse("INSTANCE_ACTIONS_INVALID")
        object.__setattr__(self, "prerequisites", prerequisites)

    def to_dict(self):
        return {
            "code": self.code,
            "category": self.category,
            "prerequisites": list(self.prerequisites),
            "requires_configuration": self.requires_configuration,
            "requires_approval": self.requires_approval,
            "executable": self.executable,
        }


@dataclass(frozen=True, slots=True)
class PlanBlocker:
    code: str
    category: str
    actions: tuple[str, ...]

    def __post_init__(self):
        if type(self.code) is not str or self.code not in _BLOCKER_CATEGORIES:
            _refuse("INSTANCE_BLOCKERS_INVALID")
        if type(self.category) is not str or self.category != _BLOCKER_CATEGORIES[self.code]:
            _refuse("INSTANCE_BLOCKERS_INVALID")
        object.__setattr__(self, "actions", _action_codes(self.actions, empty=False))

    def to_dict(self):
        return {"code": self.code, "category": self.category, "actions": list(self.actions)}


@dataclass(frozen=True, slots=True)
class InstancePlan:
    descriptor: InstanceDescriptor
    actions: tuple[PlanAction, ...]
    blockers: tuple[PlanBlocker, ...]
    port_range: tuple[int, int]
    claimed_ports: tuple[int, ...]
    excluded_ports: tuple[int, ...]

    def __post_init__(self):
        if type(self.descriptor) is not InstanceDescriptor or type(self.actions) not in {list, tuple}:
            _refuse("INSTANCE_PLAN_INVALID")
        if type(self.blockers) not in {list, tuple}:
            _refuse("INSTANCE_PLAN_INVALID")
        if any(type(item) is not PlanAction for item in self.actions) or any(
            type(item) is not PlanBlocker for item in self.blockers
        ):
            _refuse("INSTANCE_PLAN_INVALID")
        descriptor = self.descriptor
        actions, blockers = _actions_and_blockers(
            descriptor.mode,
            descriptor.auth_mode,
            descriptor.provider,
            descriptor.configuration_present,
            descriptor.config_generation,
        )
        if tuple(self.actions) != actions or tuple(self.blockers) != blockers:
            _refuse("INSTANCE_PLAN_INVALID")
        claimed = _port_set(self.claimed_ports)
        excluded = tuple(sorted(set(_port_set(self.excluded_ports)) | _RESERVED_PORTS))
        proposed = _propose_ports(
            descriptor.instance_id, _PORTS[descriptor.mode], self.port_range, set(claimed) | set(excluded)
        )
        if dict(descriptor.ports) != dict(proposed):
            _refuse("INSTANCE_PORTS_INVALID")
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "blockers", blockers)
        object.__setattr__(self, "port_range", tuple(self.port_range))
        object.__setattr__(self, "claimed_ports", claimed)
        object.__setattr__(self, "excluded_ports", excluded)

    @property
    def fingerprint(self):
        return hashlib.sha256(_canonical(self._public_plan())).hexdigest()

    def _public_plan(self):
        return {
            "version": 1,
            "descriptor": self.descriptor.to_dict(),
            "actions": [item.to_dict() for item in self.actions],
            "blockers": [item.to_dict() for item in self.blockers],
            "port_range": list(self.port_range),
            "claimed_ports": list(self.claimed_ports),
            "excluded_ports": list(self.excluded_ports),
        }

    def to_dict(self):
        return {**self._public_plan(), "fingerprint": self.fingerprint}


def _actions_and_blockers(mode, auth_mode, provider, configured, config_generation):
    actions = [PlanAction("prepare-dependencies", "software-dependencies")]
    blockers = [
        PlanBlocker("SOFTWARE_PREPARATION_APPROVAL_REQUIRED", "software-dependencies", ("prepare-dependencies",))
    ]

    def add(code, category, blocker, *, configuration=False, prerequisites=("prepare-dependencies",)):
        actions.append(PlanAction(code, category, prerequisites, configuration))
        blockers.append(PlanBlocker(blocker, category, (code,)))

    if mode != "mock":
        add("review-private-configuration", "private-configuration", "PRIVATE_CONFIGURATION_REVIEW_REQUIRED")
        if not configured:
            blockers.append(
                PlanBlocker("PRIVATE_CONFIGURATION_MISSING", "private-configuration", ("review-private-configuration",))
            )
        if config_generation is None:
            blockers.append(
                PlanBlocker(
                    "CONFIGURATION_GENERATION_REQUIRED", "private-configuration", ("review-private-configuration",)
                )
            )
    if mode == "isolated":
        add(
            "review-provider-policy",
            "providers",
            "CONTAINER_ENGINE_APPROVAL_REQUIRED" if provider == "container" else "LOCAL_ISOLATION_POLICY_REQUIRED",
            configuration=True,
        )
        add("prepare-isolated-providers", "providers", "PROVIDER_PREPARATION_APPROVAL_REQUIRED", configuration=True)
        add("review-database-preparation", "database", "DATABASE_PREPARATION_APPROVAL_REQUIRED", configuration=True)
        if auth_mode == "native":
            add("review-native-enrollment", "administrator", "NATIVE_ENROLLMENT_GATED", configuration=True)
    elif mode == "shared-backend":
        add(
            "review-shared-backend-registration",
            "shared-backend",
            "SHARED_BACKEND_REGISTRATION_REQUIRED",
            configuration=True,
        )
    if mode != "mock" and auth_mode == "hcl":
        add("review-hcl-registration", "identity-provider", "HCL_REGISTRATION_APPROVAL_REQUIRED", configuration=True)
    add("review-certificate-material", "certificates", "CERTIFICATE_PREPARATION_APPROVAL_REQUIRED")
    add("review-certificate-trust", "trust", "CERTIFICATE_TRUST_APPROVAL_REQUIRED")
    gated = tuple(action.code for action in actions if action.code != "prepare-dependencies")
    blockers.append(PlanBlocker("INSTANCE_LIVE_OPERATIONS_GATED", "authorization", gated))
    return tuple(actions), tuple(blockers)


def plan_instance(
    *,
    repository_id: str,
    worktree_id: str,
    commit: str,
    generation: int,
    mode: str,
    auth_mode: str,
    provider: str | None = None,
    manifest_hashes: Mapping[str, str] | None = None,
    config_generation: str | int | None = None,
    config_present: bool = False,
    port_range: tuple[int, int] = (20000, 29999),
    claimed_ports: Iterable[int] = (),
    excluded_ports: Iterable[int] = (),
) -> InstancePlan:
    """Propose public identifiers, unallocated ports and separately gated actions.

    Claims are supplied registry observations, never a substitute for a later
    ownership-safe reservation. Missing configuration never blocks dependency
    preparation; approval is still required for that separate mutable phase.
    """
    repository_id, worktree_id = _public_id(repository_id), _public_id(worktree_id)
    _integer(generation, 1, 2147483647, "INSTANCE_GENERATION_INVALID")
    _configuration_generation(config_generation)
    if type(mode) is not str or mode not in _PORTS:
        _refuse("INSTANCE_MODE_INVALID")
    if type(auth_mode) is not str or auth_mode not in {"native", "hcl"}:
        _refuse("INSTANCE_AUTH_MODE_INVALID")
    if type(config_present) is not bool:
        _refuse("INSTANCE_CONFIGURATION_STATUS_INVALID")
    provider = _DEFAULT_PROVIDER[mode] if provider is None else provider
    if type(provider) is not str or provider not in _PROVIDERS[mode]:
        _refuse("INSTANCE_PROVIDER_INVALID")
    manifests = _manifests({} if manifest_hashes is None else manifest_hashes)
    claimed = _port_set(claimed_ports)
    excluded = tuple(sorted(set(_port_set(excluded_ports)) | _RESERVED_PORTS))
    instance_id = _instance_id(repository_id, worktree_id, generation)
    ports = _propose_ports(instance_id, _PORTS[mode], port_range, set(claimed) | set(excluded))
    hostname = "sbom-" + uuid.UUID(instance_id).hex + ".localhost"
    descriptor = InstanceDescriptor(
        1,
        instance_id,
        repository_id,
        worktree_id,
        commit,
        generation,
        config_generation,
        config_present,
        mode,
        auth_mode,
        provider,
        hostname,
        "https://" + hostname + ":" + str(ports["frontend"]),
        ports,
        _resources(instance_id, mode),
        manifests,
    )
    actions, blockers = _actions_and_blockers(mode, auth_mode, provider, config_present, config_generation)
    return InstancePlan(descriptor, actions, blockers, tuple(port_range), claimed, excluded)
