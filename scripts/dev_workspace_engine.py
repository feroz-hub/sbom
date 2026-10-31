"""Explicit container-engine boundary; discovery and supplied JSON grant no authority.

Docker is accessed only through an absolute, pinned executable, an empty private
CLI configuration directory and an explicit local IPC endpoint. The caller must
provide an independently implemented company-policy authority and exact action
consent. These trusted Python interfaces are not a sandbox against the same user.
Creation records the returned network/container IDs in a durable caller journal.
Container create allocates fresh anonymous data volumes; a name/label lookup is
never a substitute for a creation receipt. PostgreSQL is never started by create.
Docker volumes have no native immutable ID. Their creation fingerprint is checked
but this adapter never deletes, reconfigures or otherwise mutates an existing volume.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from uuid import UUID

if __package__:
    from . import dev_environment, dev_instance_storage, dev_workspace_compose, dev_workspace_provider
else:
    import dev_environment
    import dev_instance_storage
    import dev_workspace_compose
    import dev_workspace_provider

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LIMIT = 1048576
_ACTIONS = frozenset({"create", "start", "stop"})
_CONTROLLER_NAMES = (
    "dev_workspace_engine.py",
    "dev_workspace_compose.py",
    "dev_workspace_provider.py",
    "dev_workspace_provider_input.py",
    "dev_environment.py",
    "dev_instance_storage.py",
    "dev_private.py",
    "dev_windows_acl.py",
)
_CHECKS = frozenset(
    {
        "company-policy",
        "image-contract",
        "provenance",
        "vulnerability-scan",
        "registry",
        "nonroot-platform",
        "provider-resources",
        "operator-action",
        "private-bundle",
    }
)
_CREATE_CHECKS = frozenset({"credentials-files", "exclusive-creation-reservation"})
_DATABASE_CHECKS = frozenset(
    {"target-database-initialization", "database-prepared", "data-volume-ownership", "host-health-contract"}
)
_CODES = frozenset(
    {
        "ENGINE_INPUT_INVALID",
        "ENGINE_MISSING",
        "ENGINE_UNSUPPORTED",
        "ENGINE_TOOL_UNVERIFIED",
        "ENGINE_CONFIG_REQUIRED",
        "ENGINE_LOCAL_ENDPOINT_REQUIRED",
        "ENGINE_DISCOVERY_BLOCKED",
        "ENGINE_COMMAND_FAILED",
        "ENGINE_OUTPUT_INVALID",
        "ENGINE_CHILD_TIMEOUT",
        "ENGINE_CHILD_CANCELLED",
        "ENGINE_CHILD_CLEANUP_UNCONFIRMED",
        "ENGINE_IDENTITY_CHANGED",
        "ENGINE_POLICY_REQUIRED",
        "ENGINE_CONSENT_REQUIRED",
        "ENGINE_RESOURCES_UNVERIFIED",
        "ENGINE_RESOURCE_DRIFT",
        "ENGINE_SECRET_FILE_UNVERIFIED",
        "ENGINE_COMPOSE_ARTIFACT_UNVERIFIED",
        "ENGINE_CREATION_RECEIPT_REQUIRED",
        "ENGINE_ACTION_COMPLETED",
        "ENGINE_CAPABILITY_OBSERVED",
        "ENGINE_ACTION_UNCONFIRMED",
        "ENGINE_CREATION_UNCONFIRMED",
    }
)


class EngineError(ValueError):
    def __init__(self, code, *, child_pid=None):
        self.code = code if type(code) is str and code in _CODES else "ENGINE_INPUT_INVALID"
        self.child_pid = child_pid if type(child_pid) is int and 0 < child_pid <= 0xFFFFFFFF else None
        super().__init__(self.code)


def _fail(code):
    raise EngineError(code) from None


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail("ENGINE_INPUT_INVALID")
    return value


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


def _proof_valid(value):
    return (
        type(value) is tuple
        and len(value) == 6
        and all(type(item) is int and item >= 0 for item in value[:5])
        and type(value[-1]) is str
        and _HASH.fullmatch(value[-1]) is not None
    )


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("ENGINE_OUTPUT_INVALID")
            result[key] = value
        return result

    if type(raw) is not bytes or len(raw) > _LIMIT:
        _fail("ENGINE_OUTPUT_INVALID")
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except EngineError:
        raise
    except Exception:
        _fail("ENGINE_OUTPUT_INVALID")


def _file(path, *, private=False):
    if type(path) is not Path and not isinstance(path, Path):
        _fail("ENGINE_TOOL_UNVERIFIED")
    if not path.is_absolute() or path.resolve(strict=True) != path:
        _fail("ENGINE_TOOL_UNVERIFIED")
    if os.name == "nt" and (re.fullmatch(r"[A-Za-z]:", path.drive) is None or ":" in str(path)[2:]):
        _fail("ENGINE_TOOL_UNVERIFIED")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not before.st_ino
        or getattr(before, "st_file_attributes", 0) & 1024
    ):
        _fail("ENGINE_TOOL_UNVERIFIED")
    if private:
        dev_instance_storage._verify(path.parent, private=True)
        if os.name == "nt":
            if __package__:
                from .dev_windows_acl import verify_access
            else:
                from dev_windows_acl import verify_access
            verify_access(path, private=True)
        elif before.st_uid != os.getuid() or before.st_mode & 0o077:
            _fail("ENGINE_SECRET_FILE_UNVERIFIED")
    return (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)


def _tool(path):
    stamp = _file(path)
    if stamp[2] > 268435456:
        _fail("ENGINE_TOOL_UNVERIFIED")
    raw = dev_environment.bounded_read_bytes(path, 268435456)
    if _file(path) != stamp:
        _fail("ENGINE_TOOL_UNVERIFIED")
    return (*stamp, hashlib.sha256(raw).hexdigest())


def _config(path):
    if not isinstance(path, Path) or not path.is_absolute() or path.resolve(strict=True) != path:
        _fail("ENGINE_CONFIG_REQUIRED")
    value = dev_instance_storage._verify(path, private=True)
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            _fail("ENGINE_CONFIG_REQUIRED")
    return value.st_dev, value.st_ino


def _environment(config):
    values = {
        key.upper(): value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}
    }
    values.update(
        PATH="",
        HOME=str(config),
        USERPROFILE=str(config),
        APPDATA=str(config),
        LOCALAPPDATA=str(config),
        DOCKER_CONFIG=str(config),
        DOCKER_CLI_HINTS="false",
        DOCKER_CLI_EXPERIMENTAL="disabled",
        COMPOSE_DISABLE_ENV_FILE="1",
        COMPOSE_ANSI="never",
        COMPOSE_INTERACTIVE_NO_CLI="1",
    )
    return values


def _owned_run(argv, *, cwd, environment, timeout):
    """Bound output and waits; cleanup touches only the original Popen handle."""
    process, threads, output, overflow = None, [], [bytearray(), bytearray()], threading.Event()

    def read(stream, target):
        try:
            while chunk := stream.read(65536):
                target.extend(chunk[: max(0, _LIMIT - len(target))])
                if len(target) >= _LIMIT:
                    overflow.set()
                    return
        except Exception:
            overflow.set()

    reason, code, cleanup = None, None, False
    try:
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            bufsize=0,
            **flags,
        )
        for stream, target in zip((process.stdout, process.stderr), output, strict=True):
            thread = threading.Thread(target=read, args=(stream, target), daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                reason = "ENGINE_OUTPUT_INVALID" if overflow.is_set() else "ENGINE_CHILD_TIMEOUT"
                break
            time.sleep(0.01)
    except (KeyboardInterrupt, EOFError):
        reason = "ENGINE_CHILD_CANCELLED"
    except Exception:
        reason = "ENGINE_COMMAND_FAILED"
    finally:
        # Repeated cancellation is bounded too; uncertainty retains the known PID.
        for _ in range(2):
            try:
                if process is None:
                    break
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                cleanup, code = True, process.returncode
                break
            except (KeyboardInterrupt, EOFError):
                reason = reason or "ENGINE_CHILD_CANCELLED"
            except Exception:
                reason = reason or "ENGINE_COMMAND_FAILED"
        for thread in threads:
            try:
                thread.join(timeout=1)
            except (KeyboardInterrupt, EOFError):
                reason = reason or "ENGINE_CHILD_CANCELLED"
        if process is not None and not any(thread.is_alive() for thread in threads):
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except (Exception, KeyboardInterrupt, EOFError):
                    reason = reason or "ENGINE_OUTPUT_INVALID"
    if process is not None and not cleanup:
        raise EngineError("ENGINE_CHILD_CLEANUP_UNCONFIRMED", child_pid=process.pid) from None
    if reason or overflow.is_set() or any(thread.is_alive() for thread in threads) or code != 0:
        raise EngineError(reason or "ENGINE_COMMAND_FAILED") from None
    return bytes(output[0])


@dataclass(frozen=True, slots=True)
class EngineCapability:
    status: str
    code: str
    executable: Path | None = field(default=None, repr=False)
    config_root: Path | None = field(default=None, repr=False)
    endpoint: str | None = field(default=None, repr=False)
    tool_proof: tuple = field(default=(), repr=False)
    config_identity: tuple = field(default=(), repr=False)
    engine_identity: str | None = None
    platform: str | None = None
    cli_version: str | None = None
    compose_version: str | None = None
    compose_proof: tuple = field(default=(), repr=False)
    kind: str = "docker"
    probe_pid: int | None = None

    def __post_init__(self):
        if (
            type(self.kind) is not str
            or self.kind not in {"docker", "podman"}
            or type(self.status) is not str
            or self.status not in {"MISSING", "BLOCKED", "AVAILABLE", "UNSUPPORTED"}
            or type(self.code) is not str
            or self.code not in _CODES
        ):
            _fail("ENGINE_INPUT_INVALID")
        if self.probe_pid is not None and (type(self.probe_pid) is not int or not 0 < self.probe_pid <= 0xFFFFFFFF):
            _fail("ENGINE_INPUT_INVALID")
        if self.status == "AVAILABLE":
            if (
                not isinstance(self.executable, Path)
                or not isinstance(self.config_root, Path)
                or not self.executable.is_absolute()
                or not self.config_root.is_absolute()
                or type(self.tool_proof) is not tuple
                or len(self.tool_proof) != 6
                or type(self.config_identity) is not tuple
                or len(self.config_identity) != 2
                or any(type(value) is not int or value < 0 for value in (*self.tool_proof[:5], *self.config_identity))
                or type(self.platform) is not str
                or self.platform not in {"linux/amd64", "linux/arm64"}
                or type(self.cli_version) is not str
                or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?", self.cli_version) is None
                or type(self.compose_proof) is not tuple
            ):
                _fail("ENGINE_INPUT_INVALID")
            _hash(self.tool_proof[-1])
            _hash(self.engine_identity)
            _endpoint(self.endpoint)
            if self.compose_version is not None and (
                type(self.compose_version) is not str
                or re.fullmatch(r"v?2\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?", self.compose_version) is None
                or len(self.compose_proof) != 7
            ):
                _fail("ENGINE_INPUT_INVALID")
        elif (
            any(
                value is not None
                for value in (
                    self.executable,
                    self.config_root,
                    self.endpoint,
                    self.engine_identity,
                    self.platform,
                    self.cli_version,
                    self.compose_version,
                )
            )
            or self.tool_proof
            or self.config_identity
            or self.compose_proof
        ):
            _fail("ENGINE_INPUT_INVALID")

    def to_dict(self):
        return {
            "engine": self.kind,
            "status": self.status,
            "code": self.code,
            "engine_identity": self.engine_identity,
            "platform": self.platform,
            "cli_version": self.cli_version,
            "compose_version": self.compose_version,
            "compose_plugin_identity_verified": bool(self.compose_proof),
            "probe_pid": self.probe_pid,
            "ownership_verified": False,
            "live_authorized": False,
        }


def _endpoint(value):
    if type(value) is not str or len(value) > 512 or any(char in value for char in "\r\n\0"):
        _fail("ENGINE_LOCAL_ENDPOINT_REQUIRED")
    if os.name == "nt":
        if value != "npipe:////./pipe/docker_engine":
            _fail("ENGINE_LOCAL_ENDPOINT_REQUIRED")
    elif not value.startswith("unix:///") or any(part in {".", "..", ""} for part in value[8:].split("/")):
        _fail("ENGINE_LOCAL_ENDPOINT_REQUIRED")
    return value


def discover_engine(*, executable=None, config_root=None, endpoint=None, runner=None):
    """Read-only probes; never read user Docker config, install, pull or adopt."""
    found = executable if executable is not None else shutil.which("docker")
    if found is None:
        return EngineCapability("MISSING", "ENGINE_MISSING")
    try:
        path = Path(found)
        if not path.is_absolute():
            _fail("ENGINE_TOOL_UNVERIFIED")
        path = path.resolve(strict=True)
        proof = _tool(path)
        root = Path(config_root) if config_root is not None else None
        identity = _config(root)
        endpoint = _endpoint(endpoint)
        run = runner or _owned_run
        base = (str(path), "--config", str(root), "--host", endpoint)
        env = _environment(root)

        def call(*args):
            raw = run((*base, *args), cwd=root, environment=env, timeout=5)
            if type(raw) is not bytes or len(raw) > _LIMIT:
                _fail("ENGINE_OUTPUT_INVALID")
            return raw

        version = _json(call("version", "--format", "{{json .}}"))
        info = _json(call("info", "--format", "{{json .}}"))
        compose, compose_proof = None, ()
        plugins = info.get("ClientInfo", {}).get("Plugins", [])
        if type(plugins) is not list or len(plugins) > 32:
            _fail("ENGINE_OUTPUT_INVALID")
        selected = [item for item in plugins if type(item) is dict and item.get("Name") == "compose"]
        if len(selected) > 1:
            _fail("ENGINE_OUTPUT_INVALID")
        if selected:
            plugin_locator = Path(selected[0]["Path"])
            if not plugin_locator.is_absolute():
                _fail("ENGINE_TOOL_UNVERIFIED")
            plugin = plugin_locator.resolve(strict=True)
            plugin_proof = _tool(plugin)
            compose = call("compose", "version", "--short").decode("ascii").strip()
            if _tool(plugin) != plugin_proof or plugin_locator.resolve(strict=True) != plugin:
                _fail("ENGINE_IDENTITY_CHANGED")
            compose_proof = (str(plugin), *plugin_proof)
        cli = version["Client"]["Version"]
        platform = (
            info["OSType"]
            + "/"
            + {"x86_64": "amd64", "aarch64": "arm64"}.get(info["Architecture"], info["Architecture"])
        )
        if (
            type(cli) is not str
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?", cli) is None
            or compose is not None
            and re.fullmatch(r"v?2\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?", compose) is None
            or platform not in {"linux/amd64", "linux/arm64"}
            or type(info["ID"]) is not str
            or not info["ID"]
        ):
            _fail("ENGINE_UNSUPPORTED")
        engine = _digest(["docker", endpoint, info["ID"], platform])
        if _tool(path) != proof or _config(root) != identity:
            _fail("ENGINE_IDENTITY_CHANGED")
        return EngineCapability(
            "AVAILABLE",
            "ENGINE_CAPABILITY_OBSERVED",
            path,
            root,
            endpoint,
            proof,
            identity,
            engine,
            platform,
            cli,
            compose,
            compose_proof,
        )
    except EngineError as error:
        return EngineCapability("BLOCKED", error.code, probe_pid=error.child_pid)
    except Exception:
        return EngineCapability("BLOCKED", "ENGINE_DISCOVERY_BLOCKED")


@dataclass(frozen=True, slots=True)
class ActionConsent:
    action: str
    operation_id: str
    provider_fingerprint: str
    engine_identity: str
    policy_id: str
    targets_fingerprint: str

    def __post_init__(self):
        try:
            if (
                type(self.action) is not str
                or self.action not in _ACTIONS
                or type(self.operation_id) is not str
                or str(UUID(self.operation_id)) != self.operation_id
            ):
                _fail("ENGINE_CONSENT_REQUIRED")
            _hash(self.provider_fingerprint)
            _hash(self.engine_identity)
            _hash(self.targets_fingerprint)
            dev_workspace_provider._public_id(self.policy_id)
        except Exception:
            _fail("ENGINE_CONSENT_REQUIRED")


@dataclass(frozen=True, slots=True)
class PolicyAuthorization:
    request_fingerprint: str
    checks: frozenset[str]

    def __post_init__(self):
        _hash(self.request_fingerprint)
        if type(self.checks) is not frozenset or not self.checks <= _CHECKS | _CREATE_CHECKS | _DATABASE_CHECKS:
            _fail("ENGINE_POLICY_REQUIRED")


class PolicyAuthority(Protocol):
    """Trusted approved-policy adapter, not a deserialized caller claim.

    Implementations must independently reload approved policy and verify the
    exact operator action/targets, pinned tool/image provenance and scan/registry
    evidence, supported nonroot runtime contract, and current private bundle.
    Start additionally needs independently observed prepared DB/volume ownership
    and a TLS/authenticated host-health contract. Supplied Compose review flags
    alone cannot satisfy any of these decisions.
    """

    def verify(self, request: EngineActionPlan) -> PolicyAuthorization: ...


@dataclass(frozen=True, slots=True)
class SecretFile:
    reference: str
    path: Path = field(repr=False)
    identity: tuple = field(repr=False)

    def __post_init__(self):
        if (
            type(self.reference) is not str
            or re.fullmatch(r"sbom-dev-[0-9a-f]{32}-[a-z-]+", self.reference) is None
            or not isinstance(self.path, Path)
            or not self.path.is_absolute()
            or type(self.identity) is not tuple
            or len(self.identity) != 5
            or any(type(value) is not int or value < 0 for value in self.identity)
            or not 0 < self.identity[2] <= _LIMIT
        ):
            _fail("ENGINE_SECRET_FILE_UNVERIFIED")

    @classmethod
    def inspect(cls, reference, path):
        try:
            if type(reference) is not str or re.fullmatch(r"sbom-dev-[0-9a-f]{32}-[a-z-]+", reference) is None:
                _fail("ENGINE_SECRET_FILE_UNVERIFIED")
            path = Path(path)
            stamp = _file(path, private=True)
            if not 0 < stamp[2] <= _LIMIT:
                _fail("ENGINE_SECRET_FILE_UNVERIFIED")
            return cls(reference, path, stamp)
        except Exception:
            _fail("ENGINE_SECRET_FILE_UNVERIFIED")


@dataclass(frozen=True, slots=True)
class ContainerRecord:
    component: str
    object_id: str
    started_at: str

    def __post_init__(self):
        if type(self.component) is not str or self.component not in {"postgres", "redis", "mailpit"}:
            _fail("ENGINE_RESOURCES_UNVERIFIED")
        _hash(self.object_id)
        dev_workspace_provider._birth(self.started_at)


@dataclass(frozen=True, slots=True)
class ResourceRecords:
    """Only an approved creation journal may initially publish these records."""

    engine_identity: str
    provider_fingerprint: str
    containers: tuple[ContainerRecord, ...]
    network_id: str
    volume_births: tuple[tuple[str, str, str], ...]
    secrets: tuple[SecretFile, ...] = field(repr=False)

    def __post_init__(self):
        for value in (self.engine_identity, self.provider_fingerprint, self.network_id):
            _hash(value)
        if (
            type(self.containers) is not tuple
            or len(self.containers) != 3
            or any(type(item) is not ContainerRecord for item in self.containers)
            or {item.component for item in self.containers} != {"postgres", "redis", "mailpit"}
            or len({item.object_id for item in self.containers}) != 3
            or type(self.volume_births) is not tuple
            or len(self.volume_births) != 2
            or any(
                type(item) is not tuple
                or len(item) != 3
                or type(item[0]) is not str
                or any(type(value) is not str or _HASH.fullmatch(value) is None for value in item[1:])
                for item in self.volume_births
            )
            or len({item[0] for item in self.volume_births}) != 2
            or len({item[1] for item in self.volume_births}) != 2
            or type(self.secrets) is not tuple
            or any(type(item) is not SecretFile for item in self.secrets)
            or len({item.reference for item in self.secrets}) != len(self.secrets)
        ):
            _fail("ENGINE_RESOURCES_UNVERIFIED")


@dataclass(frozen=True, slots=True)
class EngineActionPlan:
    provider: dev_workspace_provider.ContainerProviderPlan = field(repr=False)
    capability: EngineCapability = field(repr=False)
    consent: ActionConsent
    compose: dev_workspace_compose.ComposePlan = field(repr=False)
    recorded: ResourceRecords | None = field(default=None, repr=False)
    secrets: tuple[SecretFile, ...] = field(default=(), repr=False)
    controller_proofs: tuple = field(default=(), repr=False)
    fingerprint: str = ""

    def __post_init__(self):
        if (
            type(self.provider) is not dev_workspace_provider.ContainerProviderPlan
            or type(self.capability) is not EngineCapability
            or type(self.consent) is not ActionConsent
            or type(self.compose) is not dev_workspace_compose.ComposePlan
            or self.recorded is not None
            and type(self.recorded) is not ResourceRecords
            or type(self.secrets) is not tuple
            or any(type(item) is not SecretFile for item in self.secrets)
            or type(self.controller_proofs) is not tuple
            or len(self.controller_proofs) != len(_CONTROLLER_NAMES)
            or any(
                type(item) is not tuple or len(item) != 2 or type(item[0]) is not str or not _proof_valid(item[1])
                for item in self.controller_proofs
            )
            or tuple(item[0] for item in self.controller_proofs) != _CONTROLLER_NAMES
        ):
            _fail("ENGINE_INPUT_INVALID")
        _hash(self.fingerprint)


@dataclass(frozen=True, slots=True)
class EngineOutcome:
    code: str
    completed_ids: tuple[str, ...] = ()
    records: ResourceRecords | None = field(default=None, repr=False)
    child_pid: int | None = None
    created_network_id: str | None = None

    def __post_init__(self):
        if (
            type(self.code) is not str
            or self.code not in _CODES
            or type(self.completed_ids) is not tuple
            or len(self.completed_ids) > 3
            or any(type(value) is not str for value in self.completed_ids)
            or len(set(self.completed_ids)) != len(self.completed_ids)
            or self.records is not None
            and type(self.records) is not ResourceRecords
            or self.child_pid is not None
            and (type(self.child_pid) is not int or not 0 < self.child_pid <= 0xFFFFFFFF)
        ):
            _fail("ENGINE_INPUT_INVALID")
        for value in self.completed_ids:
            _hash(value)
        if self.created_network_id is not None:
            _hash(self.created_network_id)

    def to_dict(self):
        return {
            "code": self.code,
            "completed_container_ids": list(self.completed_ids),
            "child_pid": self.child_pid,
            "created_network_id": self.created_network_id,
            "unknown_resources_preserved": self.code != "ENGINE_ACTION_COMPLETED",
            "application_ready": False,
            "volume_deletion_permitted": False,
        }


class CreationJournal(Protocol):
    """Durable creation-intent/receipt sink; failure preserves partial resources."""

    def verify_reservation(self, request: EngineActionPlan) -> None: ...
    def record_intent(self, request: EngineActionPlan) -> None: ...
    def record_receipt(self, request: EngineActionPlan, kind: str, logical_name: str, object_id: str) -> None: ...
    def record_outcome(self, request: EngineActionPlan, outcome: EngineOutcome) -> None: ...


def action_targets(provider, compose, *, recorded=None, secrets=()):
    """Pure exact-target review binding; never a policy or ownership proof."""
    try:
        if (
            type(provider) is not dev_workspace_provider.ContainerProviderPlan
            or type(compose) is not dev_workspace_compose.ComposePlan
        ):
            _fail("ENGINE_INPUT_INVALID")
        files = recorded.secrets if recorded is not None else secrets
        targets = [
            provider.fingerprint,
            compose.fingerprint,
            compose.policy.private_binding(),
            [(item.reference, str(item.path), item.identity) for item in files],
        ]
        if recorded is not None:
            targets.extend(
                [
                    recorded.engine_identity,
                    recorded.network_id,
                    recorded.volume_births,
                    sorted((item.component, item.object_id) for item in recorded.containers),
                ]
            )
        return _digest(targets)
    except Exception:
        _fail("ENGINE_INPUT_INVALID")


def _controllers():
    root = Path(__file__).resolve(strict=True).parent
    return tuple((name, _tool(root / name)) for name in _CONTROLLER_NAMES)


def plan_action(provider, capability, consent, *, compose, recorded=None, secrets=()):
    try:
        if (
            type(provider) is not dev_workspace_provider.ContainerProviderPlan
            or type(capability) is not EngineCapability
            or capability.status != "AVAILABLE"
            or type(consent) is not ActionConsent
        ):
            _fail("ENGINE_INPUT_INVALID")
        if provider.policy.engine != "docker" or provider.policy.engine_identity != capability.engine_identity:
            _fail("ENGINE_IDENTITY_CHANGED")
        if type(compose) is not dev_workspace_compose.ComposePlan or compose.provider_plan != provider:
            _fail("ENGINE_COMPOSE_ARTIFACT_UNVERIFIED")
        dev_workspace_compose.revalidate_compose(
            compose, provider_plan=provider, policy=compose.policy, review=compose.review
        )
        if compose.blockers or any(value != capability.platform for value in compose.policy.platforms.values()):
            _fail("ENGINE_COMPOSE_ARTIFACT_UNVERIFIED")
        if (consent.provider_fingerprint, consent.engine_identity, consent.policy_id) != (
            provider.fingerprint,
            capability.engine_identity,
            provider.policy.policy_id,
        ):
            _fail("ENGINE_CONSENT_REQUIRED")
        if consent.action == "create":
            if recorded is not None:
                _fail("ENGINE_CREATION_RECEIPT_REQUIRED")
            expected = {item.reference for item in compose.policy.secret_files}
            if (
                type(secrets) is not tuple
                or any(type(item) is not SecretFile for item in secrets)
                or {item.reference for item in secrets} != expected
                or len(secrets) != len(expected)
            ):
                _fail("ENGINE_SECRET_FILE_UNVERIFIED")
            for item in secrets:
                configured = next(
                    value.source for value in compose.policy.secret_files if value.reference == item.reference
                )
                if (
                    _file(item.path, private=True) != item.identity
                    or any(char in str(item.path) for char in ',"\r\n\0')
                    or str(item.path) != configured
                ):
                    _fail("ENGINE_SECRET_FILE_UNVERIFIED")
        elif type(recorded) is not ResourceRecords or (recorded.engine_identity, recorded.provider_fingerprint) != (
            capability.engine_identity,
            provider.fingerprint,
        ):
            _fail("ENGINE_RESOURCES_UNVERIFIED")
        elif secrets:
            _fail("ENGINE_INPUT_INVALID")
        if action_targets(provider, compose, recorded=recorded, secrets=secrets) != consent.targets_fingerprint:
            _fail("ENGINE_CONSENT_REQUIRED")
        controllers = _controllers()
        binding = [
            provider.fingerprint,
            compose.fingerprint,
            compose.policy.private_binding(),
            capability.engine_identity,
            capability.platform,
            capability.tool_proof,
            consent.action,
            consent.operation_id,
            [(item.reference, str(item.path), item.identity) for item in secrets],
            [(item.component, item.object_id, item.started_at) for item in recorded.containers] if recorded else None,
            [
                recorded.network_id,
                recorded.volume_births,
                [(item.reference, str(item.path), item.identity) for item in recorded.secrets],
            ]
            if recorded
            else None,
            controllers,
        ]
        return EngineActionPlan(
            provider, capability, consent, compose, recorded, secrets, controllers, _digest(binding)
        )
    except EngineError:
        raise
    except Exception:
        _fail("ENGINE_INPUT_INVALID")


class DockerComposeClient:
    def __init__(self, capability, *, authority, runner=None):
        if (
            type(capability) is not EngineCapability
            or capability.status != "AVAILABLE"
            or capability.kind != "docker"
            or not callable(getattr(authority, "verify", None))
        ):
            _fail("ENGINE_POLICY_REQUIRED")
        self.capability, self.authority, self.runner = capability, authority, runner or _owned_run

    def _call(self, *args, timeout=5):
        cap = self.capability
        if _tool(cap.executable) != cap.tool_proof or _config(cap.config_root) != cap.config_identity:
            _fail("ENGINE_IDENTITY_CHANGED")
        raw = self.runner(
            (str(cap.executable), "--config", str(cap.config_root), "--host", cap.endpoint, *args),
            cwd=cap.config_root,
            environment=_environment(cap.config_root),
            timeout=timeout,
        )
        if type(raw) is not bytes or len(raw) > _LIMIT:
            _fail("ENGINE_OUTPUT_INVALID")
        return raw

    def _engine(self):
        info = _json(self._call("info", "--format", "{{json .}}"))
        platform = (
            info["OSType"]
            + "/"
            + {"x86_64": "amd64", "aarch64": "arm64"}.get(info["Architecture"], info["Architecture"])
        )
        if (
            platform != self.capability.platform
            or _digest(["docker", self.capability.endpoint, info["ID"], platform]) != self.capability.engine_identity
        ):
            _fail("ENGINE_IDENTITY_CHANGED")

    def _current(self, request):
        if type(request) is not EngineActionPlan or request.capability != self.capability:
            _fail("ENGINE_INPUT_INVALID")
        fresh = plan_action(
            request.provider,
            request.capability,
            request.consent,
            compose=request.compose,
            recorded=request.recorded,
            secrets=request.secrets,
        )
        if fresh != request:
            _fail("ENGINE_CONSENT_REQUIRED")

    def _authorize(self, request):
        self._current(request)
        self._engine()
        try:
            authorization = self.authority.verify(request)
        except EngineError:
            raise
        except Exception:
            _fail("ENGINE_POLICY_REQUIRED")
        required = _CHECKS | (_CREATE_CHECKS if request.consent.action == "create" else frozenset())
        if request.consent.action == "start":
            required |= _DATABASE_CHECKS
        if (
            type(authorization) is not PolicyAuthorization
            or authorization.request_fingerprint != request.fingerprint
            or not required <= authorization.checks
        ):
            _fail("ENGINE_POLICY_REQUIRED")

    def _inspect(self, kind, object_id):
        value = _json(self._call(kind, "inspect", object_id))
        if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
            _fail("ENGINE_OUTPUT_INVALID")
        return value[0]

    def _resources(self, request, *, records=None, refresh=False, expected_states=None):
        records, plan = request.recorded if records is None else records, request.provider
        if type(records) is not ResourceRecords or (records.engine_identity, records.provider_fingerprint) != (
            self.capability.engine_identity,
            plan.fingerprint,
        ):
            _fail("ENGINE_RESOURCES_UNVERIFIED")
        network = self._inspect("network", records.network_id)
        labels = dict(plan.labels)

        def own_labels(value):
            actual = value.get("Labels") or {}
            return type(actual) is dict and all(actual.get(key) == item for key, item in labels.items())

        if (
            network.get("Id") != records.network_id
            or network.get("Name") != plan.network
            or not own_labels(network)
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("Options") not in ({}, None)
        ):
            _fail("ENGINE_RESOURCE_DRIFT")
        births = {logical: (actual, birth) for logical, actual, birth in records.volume_births}
        if set(births) != set(plan.volumes):
            _fail("ENGINE_RESOURCE_DRIFT")
        for name in plan.volumes:
            actual, birth = births[name]
            volume = self._inspect("volume", actual)  # Validation only; no volume mutation exists.
            identity = _digest(
                [volume.get(key) for key in ("Name", "CreatedAt", "Driver", "Mountpoint", "Scope", "Options")]
            )
            if (
                volume.get("Name") != actual
                or volume.get("Driver") != "local"
                or volume.get("Options") not in ({}, None)
                or type(volume.get("CreatedAt")) is not str
                or identity != birth
            ):
                _fail("ENGINE_RESOURCE_DRIFT")
        secrets = {item.reference: item for item in records.secrets}
        document = _json(request.compose.render_private_manifest().encode("utf-8"))
        expected_refs = set(document["secrets"])
        if set(secrets) != expected_refs:
            _fail("ENGINE_SECRET_FILE_UNVERIFIED")
        for item in records.secrets:
            configured = document["secrets"][item.reference]["file"]
            if _file(item.path, private=True) != item.identity or str(item.path) != configured:
                _fail("ENGINE_SECRET_FILE_UNVERIFIED")
        updated = []
        for record in records.containers:
            spec = next(item for item in plan.containers if item.component == record.component)
            service = document["services"][record.component]
            value = self._inspect("container", record.object_id)
            config, host, state = value.get("Config", {}), value.get("HostConfig", {}), value.get("State", {})
            image = self._inspect("image", spec.image)
            image_platform = image.get("Os", "") + "/" + image.get("Architecture", "")
            ports = {
                f"{port.container_port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port.host_port)}]
                for port in spec.ports
            }
            mounts = [("volume", births[mount.name][0], mount.target, True) for mount in spec.mounts]
            mounts += [
                ("bind", str(secrets[item["source"]].path), "/run/secrets/" + item["target"], False)
                for item in service["secrets"]
            ]
            actual_mounts = [
                (
                    item.get("Type"),
                    item.get("Name") if item.get("Type") == "volume" else item.get("Source"),
                    item.get("Destination"),
                    item.get("RW"),
                )
                for item in value.get("Mounts", [])
            ]
            actual_mounts = [item for item in actual_mounts if item[0] != "tmpfs"]
            networks = value.get("NetworkSettings", {}).get("Networks", {})
            network_matches = (
                set(networks) == {plan.network} and networks[plan.network].get("NetworkID") == records.network_id
            )
            never_started = (
                state.get("Status") == "created"
                and type(state.get("StartedAt")) is str
                and re.fullmatch(r"0001-01-01T00:00:00(?:\.0+)?Z", state["StartedAt"]) is not None
            )
            if never_started and host.get("NetworkMode") == records.network_id:
                # Docker may not attach the operational endpoint until start.
                # The exact create-receipted network ID and independent network
                # inspection remain required; no name-based adoption occurs.
                network_matches = (
                    not networks
                    or len(networks) == 1
                    and set(networks) <= {plan.network, records.network_id}
                    and next(iter(networks.values())).get("NetworkID") in {"", records.network_id}
                )
            expected_environment = dict(item.split("=", 1) for item in image.get("Config", {}).get("Env", []))
            expected_environment.update(service["environment"])
            actual_environment = config.get("Env", [])
            if type(actual_environment) is not list or len(actual_environment) != len(expected_environment):
                _fail("ENGINE_RESOURCE_DRIFT")
            actual_environment = dict(item.split("=", 1) for item in actual_environment)
            expected_entrypoint = service.get("entrypoint", image.get("Config", {}).get("Entrypoint"))
            expected_command = service.get("command", image.get("Config", {}).get("Cmd"))
            actual_command = config.get("Cmd")
            # Docker represents no command after an explicit entrypoint as null.
            # Only that exact empty-command case is equivalent; inherited or
            # nonempty commands remain a specification drift.
            if expected_command == [] and actual_command is None and config.get("Entrypoint") == expected_entrypoint:
                actual_command = []
            if (
                value.get("Id") != record.object_id
                or value.get("Name") != "/" + spec.name
                or config.get("Image") != spec.image
                or config.get("User") != spec.user
                or not own_labels(config)
                or value.get("Image") != image.get("Id")
                or spec.image not in (image.get("RepoDigests") or [])
                or image_platform != self.capability.platform
                or not refresh
                and state.get("StartedAt") != record.started_at
                or state.get("Status") not in {"running", "exited", "created"}
                or expected_states is not None
                and record.component in expected_states
                and state.get("Status") not in expected_states[record.component]
                or config.get("Healthcheck", {}).get("Test") != ["NONE"]
                or host.get("Privileged") is not False
                or host.get("ReadonlyRootfs") is not True
                or host.get("CapDrop") != ["ALL"]
                or host.get("CapAdd") not in ([], None)
                or host.get("Devices") not in ([], None)
                or host.get("DeviceRequests") not in ([], None)
                or host.get("NetworkMode") not in {records.network_id, plan.network}
                or host.get("AutoRemove", False) is not False
                or host.get("RestartPolicy", {"Name": "no", "MaximumRetryCount": 0})
                != {"Name": "no", "MaximumRetryCount": 0}
                or host.get("PidMode") not in ("", "private")
                or host.get("IpcMode") != "private"
                or host.get("SecurityOpt") != ["no-new-privileges:true"]
                or host.get("PortBindings") != ports
                or len(actual_mounts) != len(mounts)
                or set(actual_mounts) != set(mounts)
                or actual_environment != expected_environment
                or config.get("Entrypoint") != expected_entrypoint
                or actual_command != expected_command
                or host.get("Memory") != int(service["mem_limit"])
                or host.get("PidsLimit") != service["pids_limit"]
                or host.get("NanoCpus") != int(float(service["cpus"]) * 1000000000)
                or host.get("ShmSize") != int(service["shm_size"])
                or host.get("Tmpfs") != dict(item.split(":", 1) for item in service["tmpfs"])
                or not network_matches
            ):
                _fail("ENGINE_RESOURCE_DRIFT")
            updated.append(ContainerRecord(record.component, record.object_id, state["StartedAt"]))
        return ResourceRecords(
            records.engine_identity,
            records.provider_fingerprint,
            tuple(updated),
            records.network_id,
            records.volume_births,
            records.secrets,
        )

    def _create_args(self, request, spec, network_id):
        """Fresh anonymous data volumes: deliberately no source/name is supplied."""
        document = _json(request.compose.render_private_manifest().encode("utf-8"))
        service = document["services"][spec.component]
        args = [
            "container",
            "create",
            "--name",
            spec.name,
            "--network",
            network_id,
            "--platform",
            self.capability.platform,
            "--user",
            spec.user,
            "--pull",
            "never",
            "--read-only",
            "--restart",
            "no",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--ipc",
            "private",
            "--pids-limit",
            str(service["pids_limit"]),
            "--memory",
            service["mem_limit"],
            "--cpus",
            str(service["cpus"]),
            "--shm-size",
            service["shm_size"],
            "--stop-timeout",
            service["stop_grace_period"][:-1],
        ]
        for key, value in request.provider.labels.items():
            args.extend(("--label", key + "=" + value))
        for port in spec.ports:
            args.extend(("--publish", f"127.0.0.1:{port.host_port}:{port.container_port}/tcp"))
        for mount in spec.mounts:
            configured = next(item for item in service["volumes"] if item["target"] == mount.target)
            options = ",volume-nocopy" if configured.get("volume", {}).get("nocopy") is True else ""
            args.extend(("--mount", "type=volume,target=" + mount.target + ",volume-driver=local" + options))
        secrets = {item.reference: item for item in request.secrets}
        for item in service["secrets"]:
            args.extend(
                (
                    "--mount",
                    "type=bind,source="
                    + str(secrets[item["source"]].path)
                    + ",target=/run/secrets/"
                    + item["target"]
                    + ",readonly",
                )
            )
        for value in service["tmpfs"]:
            args.extend(("--tmpfs", value))
        for key, value in service["environment"].items():
            args.extend(("--env", key + "=" + value))
        health = service["healthcheck"]
        if health.get("disable") is True or health.get("test") == ["NONE"]:
            args.append("--no-healthcheck")
        elif health["test"][0] != "CMD":
            _fail("ENGINE_COMPOSE_ARTIFACT_UNVERIFIED")
        else:
            args.extend(
                (
                    "--health-cmd",
                    shlex.join(health["test"][1:]),
                    "--health-interval",
                    health["interval"],
                    "--health-timeout",
                    health["timeout"],
                    "--health-retries",
                    str(health["retries"]),
                    "--health-start-period",
                    health["start_period"],
                )
            )
        entrypoint = service.get("entrypoint")
        if entrypoint is not None:
            if type(entrypoint) is not list or len(entrypoint) != 1 or type(entrypoint[0]) is not str:
                _fail("ENGINE_COMPOSE_ARTIFACT_UNVERIFIED")
            args.extend(("--entrypoint", entrypoint[0]))
        return (*args, spec.image, *service.get("command", []))

    def _created_records(self, request, network_id, container_ids, journal):
        containers, volumes = [], []
        for spec, object_id in zip(request.provider.containers, container_ids, strict=True):
            value = self._inspect("container", object_id)
            if value.get("Id") != object_id:
                _fail("ENGINE_RESOURCE_DRIFT")
            containers.append(ContainerRecord(spec.component, object_id, value.get("State", {}).get("StartedAt")))
            for mount in spec.mounts:
                matches = [
                    item
                    for item in value.get("Mounts", [])
                    if item.get("Type") == "volume" and item.get("Destination") == mount.target
                ]
                if len(matches) != 1:
                    _fail("ENGINE_RESOURCE_DRIFT")
                # The opaque volume name comes only from our new CID's mount,
                # never from lookup by a proposed logical name or label.
                actual = _hash(matches[0].get("Name"))
                volume = self._inspect("volume", actual)
                if volume.get("Name") != actual or not volume.get("CreatedAt"):
                    _fail("ENGINE_RESOURCE_DRIFT")
                birth = _digest(
                    [volume.get(key) for key in ("Name", "CreatedAt", "Driver", "Mountpoint", "Scope", "Options")]
                )
                journal.record_receipt(request, "volume", mount.name, actual)
                volumes.append((mount.name, actual, birth))
        if len({actual for _, actual, _ in volumes}) != len(volumes):
            _fail("ENGINE_RESOURCE_DRIFT")
        return ResourceRecords(
            self.capability.engine_identity,
            request.provider.fingerprint,
            tuple(containers),
            network_id,
            tuple(volumes),
            request.secrets,
        )

    def execute(self, request, *, creation_journal=None):
        completed, attempted, network_id = [], False, None
        try:
            self._authorize(request)
            if request.consent.action == "create":
                if creation_journal is None or any(
                    not callable(getattr(creation_journal, name, None))
                    for name in ("verify_reservation", "record_intent", "record_receipt", "record_outcome")
                ):
                    _fail("ENGINE_CREATION_RECEIPT_REQUIRED")
                creation_journal.verify_reservation(request)
                for spec in request.provider.containers:
                    # Validate translation and the installed pinned image before
                    # allocating even the first provider resource.
                    self._create_args(request, spec, "0" * 64)
                    image = self._inspect("image", spec.image)
                    if (
                        spec.image not in (image.get("RepoDigests") or [])
                        or image.get("Os", "") + "/" + image.get("Architecture", "") != self.capability.platform
                    ):
                        _fail("ENGINE_RESOURCE_DRIFT")
                creation_journal.record_intent(request)
                self._authorize(request)
                creation_journal.verify_reservation(request)
                self._authorize(request)
                attempted = True
                args = ["network", "create", "--internal", "--driver", "bridge"]
                for key, value in request.provider.labels.items():
                    args.extend(("--label", key + "=" + value))
                network_id = _hash(self._call(*args, request.provider.network, timeout=15).decode("ascii").strip())
                creation_journal.record_receipt(request, "network", request.provider.network, network_id)
                for spec in request.provider.containers:
                    self._authorize(request)
                    creation_journal.verify_reservation(request)
                    creation_journal.record_intent(request)
                    self._authorize(request)
                    object_id = _hash(
                        self._call(*self._create_args(request, spec, network_id), timeout=30).decode("ascii").strip()
                    )
                    completed.append(object_id)
                    creation_journal.record_receipt(request, "container", spec.name, object_id)
                records = self._created_records(request, network_id, completed, creation_journal)
                records = self._resources(request, records=records)
                outcome = EngineOutcome(
                    "ENGINE_ACTION_COMPLETED", tuple(completed), records, created_network_id=network_id
                )
                creation_journal.record_outcome(request, outcome)
                return outcome
            self._resources(request)
            ordered = sorted(
                request.recorded.containers,
                key=lambda item: ("postgres", "redis", "mailpit").index(item.component),
                reverse=request.consent.action == "stop",
            )
            current = request
            for record in ordered:
                self._authorize(current)
                self._resources(current)
                self._authorize(current)
                attempted = True
                args = (
                    (
                        "container",
                        "stop",
                        "--time",
                        str(request.compose.policy.health.stop_grace_seconds),
                        record.object_id,
                    )
                    if request.consent.action == "stop"
                    else ("container", "start", record.object_id)
                )
                timeout = (
                    request.compose.policy.health.stop_grace_seconds + 5 if request.consent.action == "stop" else 15
                )
                self._call(*args, timeout=timeout)
                completed.append(record.object_id)
                wanted = {"running"} if request.consent.action == "start" else {"exited", "created"}
                updated = self._resources(current, refresh=True, expected_states={record.component: wanted})
                current = plan_action(
                    request.provider, request.capability, request.consent, compose=request.compose, recorded=updated
                )
            # Birth times can legitimately change on start, but immutable IDs cannot.
            self._engine()
            records = self._resources(current)
            return EngineOutcome("ENGINE_ACTION_COMPLETED", tuple(completed), records)
        except BaseException as error:
            code = error.code if isinstance(error, EngineError) else "ENGINE_ACTION_UNCONFIRMED"
            if attempted:
                code = (
                    "ENGINE_CREATION_UNCONFIRMED" if request.consent.action == "create" else "ENGINE_ACTION_UNCONFIRMED"
                )
            outcome = EngineOutcome(
                code, tuple(completed), child_pid=getattr(error, "child_pid", None), created_network_id=network_id
            )
            if attempted and request.consent.action == "create" and creation_journal is not None:
                try:
                    creation_journal.record_outcome(request, outcome)
                except (Exception, KeyboardInterrupt, EOFError):
                    pass  # Unknown resources are retained; no cleanup/adoption follows.
            return outcome


class PodmanAdapter:
    """Separate future adapter: Docker compatibility is deliberately not assumed."""

    @staticmethod
    def discover(**_options):
        return EngineCapability("UNSUPPORTED", "ENGINE_UNSUPPORTED", kind="podman")

    @staticmethod
    def execute(_request, **_options):
        return EngineOutcome("ENGINE_UNSUPPORTED")


class EngineAdapter(Protocol):
    """Provider-independent execution boundary, with explicit capabilities."""

    def execute(self, request: EngineActionPlan, *, creation_journal=None) -> EngineOutcome: ...


# The implementation uses Docker's exact-ID CLI receipts, while discovery also
# reports a separately pinned optional Compose plugin for manifest consumers.
DockerEngineClient = DockerComposeClient
