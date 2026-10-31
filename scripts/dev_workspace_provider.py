"""Pure container proposals and consistency checks of normalized supplied data.

This module never invokes an engine, reads credentials, provisions resources,
connects to a database or grants authority. A caller-supplied policy ID is a
reference, not approval. A future adapter must independently verify/pin the engine
and resource identities and normalize its inspect output to this strict schema.
CONSISTENT means supplied data matches the proposal and supplied pinned records;
it never means ownership, readiness or a mutation was independently authorized.

Fresh PostgreSQL containers can initialize their data on first boot. Provider
creation therefore requires target-specific database/credential approval too.
Pinned company images must be validated for their nonroot UID/data/port contract
in separately approved disposable acceptance before any real executor use.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from uuid import UUID

if __package__:
    from .dev_instance_plan import InstanceDescriptor
else:
    from dev_instance_plan import InstanceDescriptor

_COMPONENTS = frozenset({"postgres", "redis", "mailpit"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"(?:[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/)?[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z")
_USER = re.compile(r"[1-9][0-9]{0,9}(?::[1-9][0-9]{0,9})?\Z")
_LABEL = "io.sbom.dev."
_CONTAINER_KEYS = frozenset(
    {
        "name",
        "component",
        "id",
        "image",
        "user",
        "pid",
        "started_at",
        "state",
        "health",
        "labels",
        "privileged",
        "host_network",
        "read_only",
        "cap_drop",
        "cap_add",
        "devices",
        "pid_mode",
        "ipc_mode",
        "no_new_privileges",
        "ports",
        "networks",
        "mounts",
        "credential_refs",
    }
)
_RESOURCE_KEYS = frozenset({"id", "name", "labels", "driver", "options"})


class ProviderPlanError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ProviderPlanError(code) from None


def _public_id(value):
    if type(value) is not str:
        _fail("PROVIDER_POLICY_ID_INVALID")
    if _HASH.fullmatch(value):
        return
    try:
        if str(UUID(value)) == value:
            return
    except ValueError:
        pass
    _fail("PROVIDER_POLICY_ID_INVALID")


def _strict(value, keys):
    if type(value) is not dict or set(value) != keys:
        _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    return value


def _pinned_id(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("PROVIDER_IDENTITY_UNVERIFIED")
    return value


def _birth(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value) is None
    ):
        _fail("PROVIDER_PROCESS_IDENTITY_UNVERIFIED")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("PROVIDER_PROCESS_IDENTITY_UNVERIFIED")
    return value


def _pid(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        _fail("PROVIDER_PROCESS_IDENTITY_UNVERIFIED")
    return value


def _image(value):
    if type(value) is not str or len(value) > 512 or _IMAGE.fullmatch(value) is None:
        _fail("PROVIDER_PINNED_IMAGES_REQUIRED")
    body = value.split("@", 1)[0]
    if any(part in {"", ".", ".."} for part in body.split("/")):
        _fail("PROVIDER_PINNED_IMAGES_REQUIRED")
    authority = body.split("/", 1)[0]
    if ":" in authority and not 1 <= int(authority.rsplit(":", 1)[1]) <= 65535:
        _fail("PROVIDER_PINNED_IMAGES_REQUIRED")


@dataclass(frozen=True, slots=True)
class ContainerPolicy:
    engine: str
    policy_id: str
    engine_identity: str
    images: Mapping[str, str]
    users: Mapping[str, str]

    def __post_init__(self):
        if type(self.engine) is not str or self.engine not in {"docker", "podman"}:
            _fail("PROVIDER_ENGINE_POLICY_REQUIRED")
        _public_id(self.policy_id)
        _pinned_id(self.engine_identity)
        if not isinstance(self.images, Mapping) or set(self.images) != _COMPONENTS:
            _fail("PROVIDER_PINNED_IMAGES_REQUIRED")
        images = dict(self.images)
        for image in images.values():
            _image(image)
        if not isinstance(self.users, Mapping) or set(self.users) != _COMPONENTS:
            _fail("PROVIDER_NONROOT_USERS_REQUIRED")
        users = dict(self.users)
        if any(
            type(user) is not str
            or _USER.fullmatch(user) is None
            or any(int(part) > 2147483647 for part in user.split(":"))
            for user in users.values()
        ):
            _fail("PROVIDER_NONROOT_USERS_REQUIRED")
        object.__setattr__(self, "images", MappingProxyType(dict(sorted(images.items()))))
        object.__setattr__(self, "users", MappingProxyType(dict(sorted(users.items()))))

    def to_dict(self):
        return {
            "engine": self.engine,
            "policy_id": self.policy_id,
            "engine_identity": self.engine_identity,
            "images": dict(self.images),
            "users": dict(self.users),
        }

    @classmethod
    def from_dict(cls, value):
        _strict(value, {"engine", "policy_id", "engine_identity", "images", "users"})
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PortBinding:
    container_port: int
    host_port: int

    def __post_init__(self):
        if (
            type(self.container_port) is not int
            or type(self.host_port) is not int
            or not 1 <= self.container_port <= 65535
            or not 1024 <= self.host_port <= 65535
        ):
            _fail("PROVIDER_PORT_BINDING_INVALID")

    def to_dict(self):
        return {
            "container_port": self.container_port,
            "host_ip": "127.0.0.1",
            "host_port": self.host_port,
            "protocol": "tcp",
        }


@dataclass(frozen=True, slots=True)
class VolumeMount:
    name: str
    target: str

    def __post_init__(self):
        if (
            type(self.name) is not str
            or re.fullmatch(r"sbom-dev-[0-9a-f]{32}-(?:postgres|redis)-data", self.name) is None
            or self.target not in {"/var/lib/postgresql/data", "/data"}
        ):
            _fail("PROVIDER_VOLUME_MOUNT_INVALID")

    def to_dict(self):
        return {"kind": "volume", "name": self.name, "target": self.target, "read_only": False}


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    component: str
    name: str
    image: str
    user: str
    ports: tuple[PortBinding, ...]
    mounts: tuple[VolumeMount, ...]
    credential_refs: tuple[str, ...]

    def __post_init__(self):
        if type(self.component) is not str or self.component not in _COMPONENTS:
            _fail("PROVIDER_COMPONENT_INVALID")
        if type(self.name) is not str or re.fullmatch(r"sbom-dev-[0-9a-f]{32}-" + self.component, self.name) is None:
            _fail("PROVIDER_COMPONENT_INVALID")
        if (
            type(self.image) is not str
            or _IMAGE.fullmatch(self.image) is None
            or type(self.user) is not str
            or _USER.fullmatch(self.user) is None
        ):
            _fail("PROVIDER_IMAGE_OR_USER_INVALID")
        if type(self.ports) is not tuple or any(type(item) is not PortBinding for item in self.ports):
            _fail("PROVIDER_PORT_BINDING_INVALID")
        if type(self.mounts) is not tuple or any(type(item) is not VolumeMount for item in self.mounts):
            _fail("PROVIDER_VOLUME_MOUNT_INVALID")
        if type(self.credential_refs) is not tuple or any(
            type(item) is not str
            or re.fullmatch(
                r"sbom-dev-[0-9a-f]{32}-(?:postgres-(?:bootstrap-password|runtime-password|tls)|redis-(?:credential|tls)|mailpit-(?:credential|tls))",
                item,
            )
            is None
            for item in self.credential_refs
        ):
            _fail("PROVIDER_CREDENTIAL_REFERENCES_INVALID")

    def to_dict(self):
        return {
            "component": self.component,
            "name": self.name,
            "image": self.image,
            "user": self.user,
            "ports": [port.to_dict() for port in self.ports],
            "mounts": [mount.to_dict() for mount in self.mounts],
            "credential_refs": list(self.credential_refs),
            "privileged": False,
            "host_network": False,
            "read_only": True,
            "cap_drop": ["ALL"],
            "cap_add": [],
            "devices": [],
            "pid_mode": "private",
            "ipc_mode": "private",
            "no_new_privileges": True,
        }


@dataclass(frozen=True, slots=True)
class ContainerProviderPlan:
    descriptor: InstanceDescriptor = field(repr=False)
    policy: ContainerPolicy
    labels: Mapping[str, str]
    network: str
    volumes: tuple[str, ...]
    containers: tuple[ContainerSpec, ...]
    database_owner_role: str
    database_runtime_role: str
    fingerprint: str

    def __post_init__(self):
        if type(self.descriptor) is not InstanceDescriptor or type(self.policy) is not ContainerPolicy:
            _fail("PROVIDER_PLAN_REQUIRED")
        if self.descriptor.mode != "isolated" or self.descriptor.provider != "container":
            _fail("PROVIDER_FULL_ISOLATION_REQUIRED")
        if not isinstance(self.labels, Mapping) or dict(self.labels) != _labels(self.descriptor, self.policy):
            _fail("PROVIDER_LABEL_MISMATCH")
        if (
            self.network != self.descriptor.resources["network"]
            or type(self.volumes) is not tuple
            or self.volumes != (self.descriptor.resources["postgres_volume"], self.descriptor.resources["redis_volume"])
        ):
            _fail("PROVIDER_RESOURCE_NAMES_INVALID")
        if type(self.containers) is not tuple or self.containers != _specs(self.descriptor, self.policy):
            _fail("PROVIDER_SPECIFICATION_DRIFT")
        if (
            self.database_owner_role != "sbom_dev_" + UUID(self.descriptor.instance_id).hex + "_bootstrap"
            or self.database_runtime_role != self.descriptor.resources["restricted_database_role"]
        ):
            _fail("PROVIDER_DATABASE_ROLE_SEPARATION_REQUIRED")
        if type(self.fingerprint) is not str or self.fingerprint != _fingerprint(
            self.descriptor,
            self.policy,
            self.labels,
            self.containers,
            self.database_owner_role,
            self.database_runtime_role,
        ):
            _fail("PROVIDER_PLAN_FINGERPRINT_INVALID")
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))

    def to_dict(self):
        return {
            "version": 1,
            "engine": self.policy.engine,
            "policy_id": self.policy.policy_id,
            "engine_identity": self.policy.engine_identity,
            "instance_id": self.descriptor.instance_id,
            "labels": dict(self.labels),
            "network": {"name": self.network, "driver": "bridge", "internal": True, "options": {}},
            "volumes": [{"name": name, "driver": "local", "options": {}} for name in self.volumes],
            "containers": [item.to_dict() for item in self.containers],
            "database": {
                "name": self.descriptor.resources["database"],
                "bootstrap_owner_role": self.database_owner_role,
                "restricted_runtime_role": self.database_runtime_role,
                "role_separation_requires_database_acceptance": True,
            },
            "fingerprint": self.fingerprint,
            "source_context": {
                "commit": self.descriptor.commit,
                "manifest_hashes": dict(self.descriptor.manifest_hashes),
                "config_generation": self.descriptor.config_generation,
                "reported_configuration_present": self.descriptor.configuration_present,
            },
            "approval_required": True,
            "required_approvals": [
                "company-container-policy",
                "pinned-image-contract-acceptance",
                "provider-resources",
                "database-initialization",
                "credentials-and-tls-material",
            ],
            "ownership_verified": False,
            "live_authorized": False,
            "executable": False,
            "image_contract_acceptance_required": True,
        }


def _labels(descriptor, policy):
    return {
        _LABEL + "repository": descriptor.repository_id,
        _LABEL + "worktree": descriptor.worktree_id,
        _LABEL + "instance": descriptor.instance_id,
        _LABEL + "generation": str(descriptor.generation),
        _LABEL + "policy": policy.policy_id,
    }


def _specs(descriptor, policy):
    token = UUID(descriptor.instance_id).hex
    references = "sbom-dev-" + token
    return (
        ContainerSpec(
            "postgres",
            descriptor.resources["postgres"],
            policy.images["postgres"],
            policy.users["postgres"],
            (PortBinding(5432, descriptor.ports["postgres"]),),
            (VolumeMount(descriptor.resources["postgres_volume"], "/var/lib/postgresql/data"),),
            (
                references + "-postgres-bootstrap-password",
                references + "-postgres-runtime-password",
                references + "-postgres-tls",
            ),
        ),
        ContainerSpec(
            "redis",
            descriptor.resources["redis"],
            policy.images["redis"],
            policy.users["redis"],
            (PortBinding(6379, descriptor.ports["redis"]),),
            (VolumeMount(descriptor.resources["redis_volume"], "/data"),),
            (references + "-redis-credential", references + "-redis-tls"),
        ),
        ContainerSpec(
            "mailpit",
            descriptor.resources["mailpit"],
            policy.images["mailpit"],
            policy.users["mailpit"],
            (PortBinding(1025, descriptor.ports["smtp"]), PortBinding(8025, descriptor.ports["mailpit_ui"])),
            (),
            (references + "-mailpit-credential", references + "-mailpit-tls"),
        ),
    )


def _fingerprint(descriptor, policy, labels, specs, owner, runtime):
    # Resource receipts survive ordinary source commits and preparation metadata
    # updates. Mutation consent separately binds the complete source descriptor.
    identity = {key: value for key, value in descriptor.to_dict().items()
                if key not in {"commit", "manifest_hashes", "config_generation", "configuration_present"}}
    public = [identity, policy.to_dict(), dict(labels), [item.to_dict() for item in specs], owner, runtime]
    return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def plan_provider(descriptor, policy):
    """Build public proposals only; a pinned image is not approval or readiness."""
    if type(descriptor) is not InstanceDescriptor:
        _fail("PROVIDER_INSTANCE_DESCRIPTOR_REQUIRED")
    if descriptor.mode != "isolated" or descriptor.provider != "container":
        _fail("PROVIDER_FULL_ISOLATION_REQUIRED")
    if type(policy) is not ContainerPolicy:
        _fail("PROVIDER_COMPANY_POLICY_REQUIRED")
    labels = MappingProxyType(_labels(descriptor, policy))
    specs = _specs(descriptor, policy)
    owner = "sbom_dev_" + UUID(descriptor.instance_id).hex + "_bootstrap"
    runtime = descriptor.resources["restricted_database_role"]
    fingerprint = _fingerprint(descriptor, policy, labels, specs, owner, runtime)
    return ContainerProviderPlan(
        descriptor,
        policy,
        labels,
        descriptor.resources["network"],
        (descriptor.resources["postgres_volume"], descriptor.resources["redis_volume"]),
        specs,
        owner,
        runtime,
        fingerprint,
    )


@dataclass(frozen=True, slots=True)
class ProviderInspection:
    status: str
    codes: tuple[str, ...]
    instance_id: str
    ownership_verified: bool = False
    live_authorized: bool = False

    def __post_init__(self):
        if self.ownership_verified is not False or self.live_authorized is not False:
            _fail("PROVIDER_AUTHORIZATION_NOT_ESTABLISHED")

    def to_dict(self):
        return {
            "status": self.status,
            "codes": list(self.codes),
            "instance_id": self.instance_id,
            "ownership_verified": False,
            "live_authorized": False,
        }


def _named(values, keys):
    if type(values) is not list or len(values) > 8:
        _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    result = {}
    for value in values:
        _strict(value, keys)
        if type(value["name"]) is not str or value["name"] in result:
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
        result[value["name"]] = value
    return result


def _container_shapes(value):
    for field_name in ("labels", "networks"):
        if type(value[field_name]) is not dict or any(
            type(key) is not str or type(item) is not str for key, item in value[field_name].items()
        ):
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    for field_name, limit in (("ports", 4), ("mounts", 2), ("credential_refs", 4)):
        if type(value[field_name]) is not list or len(value[field_name]) > limit:
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    for binding in value["ports"]:
        _strict(binding, {"container_port", "host_ip", "host_port", "protocol"})
        if (
            type(binding["container_port"]) is not int
            or type(binding["host_port"]) is not int
            or type(binding["host_ip"]) is not str
            or type(binding["protocol"]) is not str
        ):
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    for mount in value["mounts"]:
        _strict(mount, {"kind", "name", "target", "read_only"})
        if (
            any(type(mount[key]) is not str for key in ("kind", "name", "target"))
            or type(mount["read_only"]) is not bool
        ):
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    if any(type(reference) is not str for reference in value["credential_refs"]):
        _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")


def _verify(plan, inventory, pinned):
    _strict(inventory, {"version", "engine", "containers", "networks", "volumes", "absent"})
    if type(inventory["version"]) is not int or inventory["version"] != 1:
        _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
    engine = _strict(inventory["engine"], {"kind", "id", "state"})
    if engine["kind"] != plan.policy.engine or _pinned_id(engine["id"]) != plan.policy.engine_identity:
        _fail("PROVIDER_ENGINE_IDENTITY_MISMATCH")
    if engine["state"] != "ready":
        return "UNKNOWN", "PROVIDER_ENGINE_UNAVAILABLE"
    containers = _named(inventory["containers"], _CONTAINER_KEYS)
    networks = _named(inventory["networks"], _RESOURCE_KEYS | {"internal"})
    volumes = _named(inventory["volumes"], _RESOURCE_KEYS)
    expected = {
        "containers": {item.name for item in plan.containers},
        "networks": {plan.network},
        "volumes": set(plan.volumes),
    }
    actual = {"containers": set(containers), "networks": set(networks), "volumes": set(volumes)}
    absent = _strict(inventory["absent"], {"containers", "networks", "volumes"})
    for kind, names in expected.items():
        if type(absent[kind]) is not list or any(type(name) is not str for name in absent[kind]):
            _fail("PROVIDER_INSPECTION_SCHEMA_INVALID")
        reported = set(absent[kind])
        if len(reported) != len(absent[kind]) or actual[kind] - names or reported - names or actual[kind] & reported:
            _fail("PROVIDER_UNEXPECTED_RESOURCE")
        if actual[kind] | reported != names:
            return "UNKNOWN", "PROVIDER_INVENTORY_INCOMPLETE"
    if not any(actual.values()):
        return "ABSENT", "PROVIDER_REPORTED_ABSENT"
    if any(absent.values()):
        return "BLOCKED", "PROVIDER_PARTIAL_STATE_REVIEW_REQUIRED"
    if pinned is None:
        return "UNKNOWN", "PROVIDER_PINNED_IDENTITIES_REQUIRED"
    _strict(pinned, {"version", "engine_id", "containers", "networks", "volumes"})
    if (
        type(pinned["version"]) is not int
        or pinned["version"] != 1
        or pinned["engine_id"] != plan.policy.engine_identity
    ):
        _fail("PROVIDER_PINNED_IDENTITIES_INVALID")
    for kind in expected:
        if type(pinned[kind]) is not dict or set(pinned[kind]) != expected[kind]:
            _fail("PROVIDER_PINNED_IDENTITIES_INVALID")
    for kind, objects in (("networks", networks), ("volumes", volumes)):
        for name, item in objects.items():
            if _pinned_id(item["id"]) != _pinned_id(pinned[kind][name]):
                _fail("PROVIDER_RESOURCE_IDENTITY_MISMATCH")
            if item["labels"] != dict(plan.labels):
                _fail("PROVIDER_LABEL_MISMATCH")
            if item["driver"] != ("bridge" if kind == "networks" else "local") or item["options"] != {}:
                _fail("PROVIDER_HOST_MOUNT_OR_NETWORK_REFUSED")
            if kind == "networks" and item["internal"] is not True:
                _fail("PROVIDER_HOST_MOUNT_OR_NETWORK_REFUSED")
    for spec in plan.containers:
        value = containers[spec.name]
        _container_shapes(value)
        record = _strict(pinned["containers"][spec.name], {"id", "pid", "started_at"})
        if (_pinned_id(value["id"]), _pid(value["pid"]), _birth(value["started_at"])) != (
            _pinned_id(record["id"]),
            _pid(record["pid"]),
            _birth(record["started_at"]),
        ):
            _fail("PROVIDER_PROCESS_IDENTITY_MISMATCH")
        if value["state"] != "running" or value["health"] != "healthy":
            _fail("PROVIDER_STATE_UNREADY")
        if value["labels"] != dict(plan.labels):
            _fail("PROVIDER_LABEL_MISMATCH")
        wanted = spec.to_dict()
        for name in ("component", "name", "image", "user", "ports", "mounts", "credential_refs"):
            if value[name] != wanted[name]:
                _fail("PROVIDER_SPECIFICATION_DRIFT")
        if value["networks"] != {plan.network: networks[plan.network]["id"]}:
            _fail("PROVIDER_NETWORK_MISMATCH")
        if (
            any(value[name] is not False for name in ("privileged", "host_network"))
            or value["read_only"] is not True
            or value["no_new_privileges"] is not True
            or value["cap_drop"] != ["ALL"]
            or value["cap_add"] != []
            or value["devices"] != []
            or value["pid_mode"] != "private"
            or value["ipc_mode"] != "private"
        ):
            _fail("PROVIDER_UNSAFE_CONTAINER_SECURITY")
    return "CONSISTENT", "PROVIDER_SUPPLIED_RECORDS_CONSISTENT"


def verify_inventory(plan, inventory, *, pinned=None):
    """Compare supplied normalized records; never inspect or authorize a service.

    Root schema: version1, engine(kind/id/state), containers, networks, volumes,
    absent(containers/networks/volumes). IDs are lowercase SHA256-like normalized
    opaque IDs. Containers additionally bind PID/started_at, exact spec, labels,
    dedicated network and safe security flags. Network/volume options must be
    empty: local volume-driver bind options can otherwise conceal host mounts.
    `pinned` separately supplies engine/container/process/network/volume identities.
    Neither payload is trusted authority merely because this comparison matches.
    """
    if type(plan) is not ContainerProviderPlan:
        _fail("PROVIDER_PLAN_REQUIRED")
    if inventory is None:
        return ProviderInspection("UNKNOWN", ("PROVIDER_INVENTORY_REQUIRED",), plan.descriptor.instance_id)
    try:
        state, code = _verify(plan, inventory, pinned)
    except ProviderPlanError as error:
        state, code = "BLOCKED", error.code
    except Exception:
        state, code = "BLOCKED", "PROVIDER_INSPECTION_SCHEMA_INVALID"
    return ProviderInspection(state, (code,), plan.descriptor.instance_id)


if __name__ == "__main__":
    raise SystemExit(
        "PROVIDER_PLANNING_ONLY: use the unified developer launcher; live provider operations require separate approval."
    )
