"""Pure Compose JSON/YAML-subset generation; no provider or filesystem activity.

Known upstream profiles use password/config files, never credential values in
argv or environment. Reference images are not approved or asserted available.
Policy reviews are supplied by a separately trusted verifier, not authenticated
by this generator. Matching supplied reviews permit a source manifest to reach
resource review; they never authorize an engine, volume, DB or trust operation.

Private file paths and their binding digest are deliberately absent from public
JSON/fingerprints. Only render_private_manifest exposes paths for a future private
no-replace writer. That adapter must independently pin canonical file identity,
ownership/ACL and nonroot readability immediately before use. File-backed Compose
secrets do not remap uid/gid/mode; those options would give false assurances:
https://compose-spec.github.io/compose-spec/container_spec.html#secrets

Compose ignores x-* gates and can reuse colliding resources. A live adapter must
enforce fresh approval/ownership checks; this document cannot enforce them itself.
No root init container or automatic chown is generated. PGDATA and Redis volumes
must already meet the explicit nonroot ownership contract before approved use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType
from uuid import UUID

if __package__:
    from . import dev_workspace_provider as provider
else:
    import dev_workspace_provider as provider

_COMPONENTS = frozenset({"postgres", "redis", "mailpit"})
_PROFILES = {"postgres": "postgres-file-tls-v1", "redis": "redis-config-tls-v1", "mailpit": "mailpit-file-tls-v1"}
_CHECKS = frozenset(
    {
        "company_policy",
        "image_availability",
        "image_provenance",
        "image_scanning",
        "platform_compatibility",
        "external_health_adapters",
        "nonroot_postgres_initialization",
        "nonroot_volume_contract",
        "volume_population_contract",
        "private_secret_access_contract",
        "postgres_tls_hba",
        "redis_config_tls_acl",
        "mailpit_auth_tls",
        "compose_implementation",
    }
)
_LIVE_GATES = (
    "COMPANY_PROVIDER_POLICY_AUTHORITY_REQUIRED",
    "PROVIDER_ENGINE_IDENTITY_AND_OWNERSHIP_REQUIRED",
    "PROVIDER_RESOURCE_AUTHORIZATION_REQUIRED",
    "DISPOSABLE_DATABASE_PREPARATION_AUTHORIZATION_REQUIRED",
    "PRIVATE_BUNDLE_FRESH_IDENTITY_REQUIRED",
    "NONROOT_VOLUME_FRESH_OWNERSHIP_REQUIRED",
    "TLS_TARGET_ACCEPTANCE_REQUIRED",
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ComposePlanError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ComposePlanError(code) from None


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _public_id(value):
    if type(value) is str:
        if _HASH.fullmatch(value):
            return
        try:
            if str(UUID(value)) == value:
                return
        except ValueError:
            pass
    _fail("COMPOSE_PUBLIC_REFERENCE_INVALID")


def _mapping(value, keys, kind, code):
    try:
        result = dict(value) if isinstance(value, Mapping) else None
        if (
            result is None
            or set(result) != keys
            or any(type(key) is not str for key in result)
            or any(type(item) is not kind for item in result.values())
        ):
            _fail(code)
        return MappingProxyType(dict(sorted(result.items())))
    except Exception:
        _fail(code)


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail("COMPOSE_LIMITS_INVALID")


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    cpus: str
    memory_bytes: int
    pids: int
    tmpfs_bytes: int
    shm_bytes: int

    def __post_init__(self):
        if (
            type(self.cpus) is not str
            or re.fullmatch(r"[0-9]{1,2}(?:\.[0-9]{1,2})?", self.cpus) is None
            or not Decimal("0.1") <= Decimal(self.cpus) <= Decimal("64")
        ):
            _fail("COMPOSE_LIMITS_INVALID")
        _integer(self.memory_bytes, 64 * 1048576, 32 * 1073741824)
        _integer(self.pids, 16, 4096)
        _integer(self.tmpfs_bytes, 1048576, self.memory_bytes)
        _integer(self.shm_bytes, 1048576, self.memory_bytes)

    def to_dict(self):
        return {
            "cpus": self.cpus,
            "memory_bytes": self.memory_bytes,
            "pids": self.pids,
            "tmpfs_bytes": self.tmpfs_bytes,
            "shm_bytes": self.shm_bytes,
        }


@dataclass(frozen=True, slots=True)
class DataOwnership:
    uid: int
    gid: int
    mode: int

    def __post_init__(self):
        _integer(self.uid, 1, 2147483647)
        _integer(self.gid, 1, 2147483647)
        if type(self.mode) is not int or self.mode != 0o700:
            _fail("COMPOSE_PRIVATE_DATA_OWNERSHIP_REQUIRED")

    def to_dict(self):
        return {"uid": self.uid, "gid": self.gid, "mode": "0700", "preowned_volume_required": True}


@dataclass(frozen=True, slots=True)
class HealthPolicy:
    interval_seconds: int
    timeout_seconds: int
    retries: int
    start_period_seconds: int
    stop_grace_seconds: int

    def __post_init__(self):
        for value, low, high in (
            (self.interval_seconds, 2, 60),
            (self.timeout_seconds, 1, 30),
            (self.retries, 1, 60),
            (self.start_period_seconds, 0, 300),
            (self.stop_grace_seconds, 1, 120),
        ):
            _integer(value, low, high)
        if self.timeout_seconds > self.interval_seconds:
            _fail("COMPOSE_HEALTH_POLICY_INVALID")

    def to_dict(self):
        return {
            "interval_seconds": self.interval_seconds,
            "timeout_seconds": self.timeout_seconds,
            "retries": self.retries,
            "start_period_seconds": self.start_period_seconds,
            "stop_grace_seconds": self.stop_grace_seconds,
        }


@dataclass(frozen=True, slots=True)
class SecretFile:
    reference: str
    source: str = field(repr=False)
    host_platform: str

    def __post_init__(self):
        if (
            type(self.reference) is not str
            or re.fullmatch(r"sbom-dev-[0-9a-f]{32}-(?:postgres|redis|mailpit)-[a-z0-9-]{1,64}", self.reference) is None
        ):
            _fail("COMPOSE_SECRET_REFERENCE_INVALID")
        if type(self.host_platform) is not str or self.host_platform not in {"win32", "linux", "darwin"}:
            _fail("COMPOSE_HOST_PLATFORM_INVALID")
        if (
            type(self.source) is not str
            or not self.source
            or len(self.source) > 4096
            or "$" in self.source
            or any(ord(char) < 32 or ord(char) == 127 for char in self.source)
        ):
            _fail("COMPOSE_PRIVATE_FILE_PATH_INVALID")
        path = PureWindowsPath(self.source) if self.host_platform == "win32" else PurePosixPath(self.source)
        if (
            not path.is_absolute()
            or not path.name
            or any(part in {".", ".."} for part in self.source.replace("\\", "/").split("/"))
        ):
            _fail("COMPOSE_PRIVATE_FILE_PATH_INVALID")
        if self.host_platform == "win32":
            if (
                not re.fullmatch(r"[A-Za-z]:", path.drive)
                or ":" in self.source[2:]
                or any(char in self.source[2:] for char in '<>"|?*')
                or any(part.endswith((" ", ".")) for part in path.parts[1:])
            ):
                _fail("COMPOSE_PRIVATE_FILE_PATH_INVALID")
            for part in path.parts[1:]:
                if part.split(".")[0].upper() in {
                    "CON",
                    "PRN",
                    "AUX",
                    "NUL",
                    "CLOCK$",
                    "CONIN$",
                    "CONOUT$",
                    *(f"COM{i}" for i in (*range(1, 10), "¹", "²", "³")),
                    *(f"LPT{i}" for i in (*range(1, 10), "¹", "²", "³")),
                }:
                    _fail("COMPOSE_PRIVATE_FILE_PATH_INVALID")
        elif "\\" in self.source or self.source.startswith("//"):
            _fail("COMPOSE_PRIVATE_FILE_PATH_INVALID")
        object.__setattr__(self, "source", str(path))


@dataclass(frozen=True, slots=True)
class ComposePolicy:
    reference: str
    bundle_generation: str
    host_platform: str
    platforms: Mapping[str, str]
    profiles: Mapping[str, str]
    limits: Mapping[str, ResourceLimits]
    data_ownership: Mapping[str, DataOwnership]
    volume_population: Mapping[str, str]
    health: HealthPolicy
    secret_files: tuple[SecretFile, ...] = field(repr=False)

    def __post_init__(self):
        _public_id(self.reference)
        _public_id(self.bundle_generation)
        if type(self.host_platform) is not str or self.host_platform not in {"win32", "linux", "darwin"}:
            _fail("COMPOSE_HOST_PLATFORM_INVALID")
        platforms = _mapping(self.platforms, _COMPONENTS, str, "COMPOSE_IMAGE_PLATFORM_REQUIRED")
        if any(item not in {"linux/amd64", "linux/arm64", "linux/arm64/v8"} for item in platforms.values()):
            _fail("COMPOSE_IMAGE_PLATFORM_REQUIRED")
        profiles = _mapping(self.profiles, _COMPONENTS, str, "COMPOSE_RUNTIME_PROFILE_REQUIRED")
        if dict(profiles) != _PROFILES:
            _fail("COMPOSE_RUNTIME_PROFILE_REQUIRED")
        limits = _mapping(self.limits, _COMPONENTS, ResourceLimits, "COMPOSE_LIMITS_REQUIRED")
        ownership = _mapping(
            self.data_ownership, {"postgres", "redis"}, DataOwnership, "COMPOSE_DATA_OWNERSHIP_REQUIRED"
        )
        population = _mapping(self.volume_population, {"postgres", "redis"}, str, "COMPOSE_VOLUME_POPULATION_REQUIRED")
        if any(item not in {"copy-empty-image-directory", "preowned-empty-volume"} for item in population.values()):
            _fail("COMPOSE_VOLUME_POPULATION_REQUIRED")
        if type(self.health) is not HealthPolicy:
            _fail("COMPOSE_HEALTH_POLICY_REQUIRED")
        if (
            type(self.secret_files) is not tuple
            or not 1 <= len(self.secret_files) <= 24
            or any(
                type(item) is not SecretFile or item.host_platform != self.host_platform for item in self.secret_files
            )
            or len({item.reference for item in self.secret_files}) != len(self.secret_files)
        ):
            _fail("COMPOSE_SECRET_LAYOUT_INVALID")
        paths = [
            str(PureWindowsPath(item.source)).lower() if self.host_platform == "win32" else item.source
            for item in self.secret_files
        ]
        if len(set(paths)) != len(paths):
            _fail("COMPOSE_SHARED_SECRET_FILE_REFUSED")
        for name, value in (
            ("platforms", platforms),
            ("profiles", profiles),
            ("limits", limits),
            ("data_ownership", ownership),
            ("volume_population", population),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "secret_files", tuple(sorted(self.secret_files, key=lambda item: item.reference)))

    def to_dict(self):
        return {
            "reference": self.reference,
            "bundle_generation": self.bundle_generation,
            "host_platform": self.host_platform,
            "platforms": dict(self.platforms),
            "profiles": dict(self.profiles),
            "limits": {name: item.to_dict() for name, item in self.limits.items()},
            "data_ownership": {name: item.to_dict() for name, item in self.data_ownership.items()},
            "volume_population": dict(self.volume_population),
            "health": self.health.to_dict(),
            "secret_references": [item.reference for item in self.secret_files],
        }

    def private_binding(self):
        """Private verifier channel only; never publish path-derived hashes."""
        return hashlib.sha256(
            _json([self.bundle_generation, [(item.reference, item.source) for item in self.secret_files]]).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ComposeContractReview:
    """Trusted-verifier supplied review, not independently authenticated here."""

    reference: str
    provider_fingerprint: str
    policy_fingerprint: str
    private_binding: str = field(repr=False)
    checks: Mapping[str, str]

    def __post_init__(self):
        _public_id(self.reference)
        if any(
            type(item) is not str or _HASH.fullmatch(item) is None
            for item in (self.provider_fingerprint, self.policy_fingerprint, self.private_binding)
        ):
            _fail("COMPOSE_REVIEW_BINDING_INVALID")
        checks = _mapping(self.checks, _CHECKS, str, "COMPOSE_REVIEW_CHECKS_INVALID")
        if any(item not in {"VERIFIED", "NOT_VERIFIED", "FAILED"} for item in checks.values()):
            _fail("COMPOSE_REVIEW_CHECKS_INVALID")
        object.__setattr__(self, "checks", checks)

    def to_dict(self):
        return {
            "reference": self.reference,
            "provider_fingerprint": self.provider_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "supplied_checks": dict(self.checks),
            "independently_authenticated_by_generator": False,
        }


def secret_layout(plan):
    """Public fixed bundle layout for a future separately authorized writer."""
    if type(plan) is not provider.ContainerProviderPlan:
        _fail("COMPOSE_PROVIDER_PLAN_REQUIRED")
    prefix = "sbom-dev-" + UUID(plan.descriptor.instance_id).hex
    return {
        "postgres": {
            "bootstrap": prefix + "-postgres-bootstrap-password",
            "runtime": prefix + "-postgres-runtime-password",
            **{role: prefix + "-postgres-tls-" + role for role in ("cert", "key", "ca", "hba")},
        },
        "redis": {
            "config": prefix + "-redis-credential",
            **{role: prefix + "-redis-tls-" + role for role in ("cert", "key", "ca")},
        },
        "mailpit": {
            "auth": prefix + "-mailpit-credential",
            **{role: prefix + "-mailpit-tls-" + role for role in ("cert", "key", "ca")},
        },
    }


def policy_fingerprint(policy):
    if type(policy) is not ComposePolicy:
        _fail("COMPOSE_POLICY_REQUIRED")
    return hashlib.sha256(_json(policy.to_dict()).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ComposePlan:
    provider_plan: provider.ContainerProviderPlan = field(repr=False)
    policy: ComposePolicy = field(repr=False)
    review: ComposeContractReview | None = field(repr=False)
    fingerprint: str
    blockers: tuple[str, ...]

    def __post_init__(self):
        blockers, fingerprint = _plan_state(self.provider_plan, self.policy, self.review)
        if (
            type(self.blockers) is not tuple
            or self.blockers != blockers
            or type(self.fingerprint) is not str
            or self.fingerprint != fingerprint
        ):
            _fail("COMPOSE_PLAN_BINDING_INVALID")

    def to_dict(self):
        return {
            "version": 1,
            "status": "BLOCKED" if self.blockers else "READY_FOR_RESOURCE_REVIEW",
            "instance_id": self.provider_plan.descriptor.instance_id,
            "provider_fingerprint": self.provider_plan.fingerprint,
            "policy": self.policy.to_dict(),
            "policy_fingerprint": policy_fingerprint(self.policy),
            "supplied_review": self.review.to_dict() if self.review else None,
            "verification_source": "supplied-review-not-authenticated-by-generator"
            if self.review
            else "no-reviewed-contract",
            "verification": dict(self.review.checks)
            if self.review
            else {name: "NOT_VERIFIED" for name in sorted(_CHECKS)},
            "blockers": list(self.blockers),
            "live_execution_gates": list(_LIVE_GATES),
            "fingerprint": self.fingerprint,
            "live_authorized": False,
            "ownership_verified": False,
            "database_authorized": False,
            "private_paths_in_public_plan": False,
            "private_bundle_independently_verified": False,
            "manifest_format": "Compose JSON (YAML subset)",
            "provider": self.provider_plan.to_dict(),
        }

    def render_private_manifest(self, *, allocations=None):
        """Sensitive paths: return only to a separately approved private writer."""
        return json.dumps(_document(self, allocations=allocations), sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _plan_state(plan, policy, review):
    if type(plan) is not provider.ContainerProviderPlan:
        _fail("COMPOSE_PROVIDER_PLAN_REQUIRED")
    if type(policy) is not ComposePolicy:
        _fail("COMPOSE_POLICY_REQUIRED")
    if provider.plan_provider(plan.descriptor, plan.policy) != plan:
        _fail("COMPOSE_PROVIDER_PLAN_DRIFT")
    if policy.reference != plan.policy.policy_id:
        _fail("COMPOSE_POLICY_REFERENCE_DRIFT")
    layout = secret_layout(plan)
    if {item.reference for item in policy.secret_files} != {
        item for values in layout.values() for item in values.values()
    }:
        _fail("COMPOSE_SECRET_LAYOUT_DRIFT")
    for item in plan.containers:
        if re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", item.user) is None:
            _fail("COMPOSE_EXPLICIT_UID_GID_REQUIRED")
        if item.component in policy.data_ownership:
            ownership = policy.data_ownership[item.component]
            if item.user != f"{ownership.uid}:{ownership.gid}":
                _fail("COMPOSE_DATA_OWNER_DRIFT")
    if review is not None and type(review) is not ComposeContractReview:
        _fail("COMPOSE_CONTRACT_REVIEW_REQUIRED")
    blockers = []
    if review is None:
        blockers.append("COMPOSE_RUNTIME_CONTRACT_REVIEW_REQUIRED")
    elif (
        review.provider_fingerprint != plan.fingerprint
        or review.policy_fingerprint != policy_fingerprint(policy)
        or not hmac.compare_digest(review.private_binding, policy.private_binding())
    ):
        blockers.append("COMPOSE_CONTRACT_REVIEW_DRIFT")
    elif any(value != "VERIFIED" for value in review.checks.values()):
        blockers.append("COMPOSE_RUNTIME_CONTRACT_UNVERIFIED")
    public = [plan.fingerprint, policy.to_dict(), review.to_dict() if review else None, blockers]
    fingerprint = hashlib.sha256(_json(public).encode()).hexdigest()
    return tuple(blockers), fingerprint


def plan_compose(plan, policy, *, review=None):
    """Generate even reference/unverified source; only real operations stay gated."""
    blockers, fingerprint = _plan_state(plan, policy, review)
    return ComposePlan(plan, policy, review, fingerprint, blockers)


def revalidate_compose(plan, *, provider_plan, policy, review=None):
    if type(plan) is not ComposePlan:
        _fail("COMPOSE_PLAN_REQUIRED")
    current = plan_compose(provider_plan, policy, review=review)
    if current != plan:
        _fail("COMPOSE_PLAN_CHANGED")
    return current


def _runtime(plan, component, names):
    paths = {role: "/run/secrets/" + name for role, name in names.items()}
    original = plan.provider_plan
    if component == "postgres":
        environment = {
            "POSTGRES_DB": original.descriptor.resources["database"],
            "POSTGRES_USER": original.database_owner_role,
            "POSTGRES_PASSWORD_FILE": paths["bootstrap"],
            "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=scram-sha-256",
            "PGDATA": "/var/lib/postgresql/data",
            "PGSSLMODE": "verify-full",
            "PGSSLROOTCERT": paths["ca"],
        }
        entrypoint = ["postgres"]  # Never invoke upstream automatic initdb during ordinary runtime startup.
        command = [
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=" + paths["cert"],
            "-c",
            "ssl_key_file=" + paths["key"],
            "-c",
            "ssl_ca_file=" + paths["ca"],
            "-c",
            "hba_file=" + paths["hba"],
            "-c",
            "unix_socket_directories=/tmp",
        ]
    elif component == "redis":
        environment = {}
        entrypoint, command = ["redis-server"], [paths["config"]]
        # The protected config must enforce TLS-only + password/ACL auth and
        # name these mounted certificate files. No payload is read or assumed.
    else:
        environment = {
            "MP_DATABASE": "/tmp/mailpit.db",
            "MP_UI_AUTH_FILE": paths["auth"],
            "MP_SMTP_AUTH_FILE": paths["auth"],
            "MP_UI_TLS_CERT": paths["cert"],
            "MP_UI_TLS_KEY": paths["key"],
            "MP_SMTP_TLS_CERT": paths["cert"],
            "MP_SMTP_TLS_KEY": paths["key"],
            "MP_SMTP_REQUIRE_STARTTLS": "true",
            "MP_SMTP_AUTH_ALLOW_INSECURE": "false",
            "MP_SMTP_AUTH_ACCEPT_ANY": "false",
            "MP_ALLOW_UNTRUSTED_TLS": "false",
            "MP_DISABLE_VERSION_CHECK": "true",
            "MP_ALLOW_INTERNAL_HTTP_REQUESTS": "false",
            "MP_BLOCK_REMOTE_CSS_AND_FONTS": "true",
        }
        entrypoint, command = ["/mailpit"], []
    return environment, entrypoint, command


def _external_health(plan):
    original, timing = plan.provider_plan, plan.policy.health
    prefix = "sbom-dev-" + UUID(original.descriptor.instance_id).hex
    common = {
        "host": "127.0.0.1",
        "verify_certificate_and_hostname": True,
        "timeout_seconds": timing.timeout_seconds,
        "interval_seconds": timing.interval_seconds,
        "retries": timing.retries,
        "start_period_seconds": timing.start_period_seconds,
        "adapter_required": True,
        "observed": False,
    }
    return {
        "postgres": {
            **common,
            "protocol": "postgresql-verify-full-readonly",
            "port": original.descriptor.ports["postgres"],
            "database": original.descriptor.resources["database"],
            "role": original.database_runtime_role,
            "credential_reference": prefix + "-postgres-runtime-password",
            "ca_reference": prefix + "-postgres-tls-ca",
        },
        "redis": {
            **common,
            "protocol": "rediss-authenticated-ping",
            "port": original.descriptor.ports["redis"],
            "credential_reference": prefix + "-redis-credential",
            "ca_reference": prefix + "-redis-tls-ca",
        },
        "mailpit": {
            **common,
            "protocol": "https-authenticated-and-smtp-starttls",
            "port": original.descriptor.ports["mailpit_ui"],
            "smtp_port": original.descriptor.ports["smtp"],
            "https_path": "/readyz",
            "credential_reference": prefix + "-mailpit-credential",
            "ca_reference": prefix + "-mailpit-tls-ca",
        },
    }


def _document(plan, *, allocations=None):
    original, policy = plan.provider_plan, plan.policy
    if allocations is not None:
        try:
            allocations = dict(allocations) if isinstance(allocations, Mapping) else None
            if (
                allocations is None
                or set(allocations) != set(original.volumes)
                or any(type(name) is not str for name in allocations)
                or any(type(item) is not str or _HASH.fullmatch(item) is None for item in allocations.values())
                or len(set(allocations.values())) != len(allocations)
            ):
                _fail("COMPOSE_VOLUME_ALLOCATION_INVALID")
        except Exception:
            _fail("COMPOSE_VOLUME_ALLOCATION_INVALID")
    layout, labels = secret_layout(original), dict(original.labels)
    services = {}
    for item in original.containers:
        limits, health = policy.limits[item.component], policy.health
        environment, entrypoint, command = _runtime(plan, item.component, layout[item.component])
        uid, gid = item.user.split(":")
        value = {
            "image": item.image,
            "platform": policy.platforms[item.component],
            "pull_policy": "never",
            "container_name": item.name,
            "user": item.user,
            "labels": labels.copy(),
            "restart": "no",
            "read_only": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": [],
            "security_opt": ["no-new-privileges:true"],
            "ipc": "private",
            "networks": [original.network],
            "ports": [
                {
                    "target": port.container_port,
                    "published": str(port.host_port),
                    "host_ip": "127.0.0.1",
                    "protocol": "tcp",
                }
                for port in item.ports
            ],
            "volumes": [
                {
                    "type": "volume",
                    **({"source": mount.name} if allocations is not None else {}),
                    "target": mount.target,
                    "read_only": False,
                    "volume": {"nocopy": policy.volume_population[item.component] == "preowned-empty-volume"},
                }
                for mount in item.mounts
            ],
            "secrets": [{"source": name, "target": name} for name in layout[item.component].values()],
            "cpus": limits.cpus,
            "mem_limit": str(limits.memory_bytes),
            "pids_limit": limits.pids,
            "shm_size": str(limits.shm_bytes),
            "tmpfs": [f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_bytes},uid={uid},gid={gid},mode=0700"],
            "stop_grace_period": f"{health.stop_grace_seconds}s",
            "environment": environment,
            "entrypoint": entrypoint,
            "command": command,
            "healthcheck": {"disable": True},
        }
        services[item.component] = value
    return {
        "name": "sbom-dev-" + UUID(original.descriptor.instance_id).hex,
        "services": services,
        "networks": {
            original.network: {
                "name": original.network,
                "driver": "bridge",
                "internal": True,
                "labels": labels.copy(),
                "driver_opts": {},
            }
        },
        "volumes": {name: {"name": actual, "external": True} for name, actual in allocations.items()}
        if allocations is not None
        else {},
        "secrets": {item.reference: {"file": item.source} for item in policy.secret_files},
        "x-sbom-development": {
            "policy_reference": policy.reference,
            "plan_fingerprint": plan.fingerprint,
            "blockers": list(plan.blockers),
            "live_execution_gates": list(_LIVE_GATES),
            "logical_volume_claims": [
                {
                    "logical_name": mount.name,
                    "component": item.component,
                    "target": mount.target,
                    "ownership": policy.data_ownership[item.component].to_dict(),
                }
                for item in original.containers
                for mount in item.mounts
            ],
            "supplied_volume_allocations": dict(allocations) if allocations is not None else None,
            "allocation_ownership_verified": False,
            "external_health": _external_health(plan),
            "postgres_initialization": {
                "required_before_first_runtime": True,
                "ordinary_runtime_initializes_database": False,
                "authorized": False,
                "bootstrap_role": original.database_owner_role,
                "runtime_role": original.database_runtime_role,
            },
            "live_authorized": False,
            "ownership_verified": False,
        },
    }


if __name__ == "__main__":
    raise SystemExit(
        "COMPOSE_GENERATION_ONLY: use the unified launcher; live provider operations require separate review."
    )
