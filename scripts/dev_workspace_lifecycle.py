"""Pure isolated-instance launch/cleanup contracts; no live execution adapter.

Caller observations and public descriptors never establish process/provider
ownership. Runtime must independently revalidate every cleanup request. Private
configuration is kept in immutable, non-repr snapshots and never public hashes.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType
from urllib.parse import unquote, urlsplit

if __package__:
    from . import dev_config, dev_instance_plan
else:
    import dev_config
    import dev_instance_plan

COMPONENTS = ("Celery worker", "Celery reports worker", "Celery Beat", "API", "Frontend")
PREREQUISITES = frozenset(
    {
        "dependencies",
        "configuration",
        "database_schema",
        "authentication",
        "tls",
        "frontend_workspace",
        "frontend_compiler",
    }
)
STEPS = (
    "VERIFY_CONFIGURATION",
    "VERIFY_PROVIDER_ATTESTATION",
    "VERIFY_SETTINGS_CHILD_ADAPTER",
    "VERIFY_DATA_TARGETS",
    "VERIFY_EXISTING_SCHEMA",
    "VERIFY_TLS",
    "VERIFY_FRONTEND_WORKSPACE",
    "VERIFY_FRONTEND_COMPILER",
    "BEGIN_RUNTIME",
    "START_DEFAULT_WORKER",
    "START_REPORTS_WORKER",
    "START_BEAT",
    "WAIT_BACKGROUND_READY",
    "START_API",
    "WAIT_API_IAM_READY",
    "START_FRONTEND",
    "WAIT_FRONTEND_HTTPS",
)
_UNAVAILABLE = (
    "INSTANCE_PROVIDER_ATTESTATION_REQUIRED",
    "INSTANCE_CREDENTIAL_OWNERSHIP_ATTESTATION_REQUIRED",
    "INSTANCE_SETTINGS_CHILD_ADAPTER_REQUIRED",
    "INSTANCE_RUNTIME_ADAPTER_REQUIRED",
    "INSTANCE_TLS_ADAPTER_REQUIRED",
)
_PRELOADS = frozenset(
    {
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "CELERY_CONFIG_MODULE",
        "DJANGO_SETTINGS_MODULE",
        "UVICORN_APP",
        "UVICORN_ENV_FILE",
    }
)
_ERRORS = frozenset(
    {
        "INSTANCE_CONTEXT_INVALID",
        "INSTANCE_CONTEXT_CHANGED",
        "INSTANCE_CONFIGURATION_INVALID",
        "INSTANCE_CONFIGURATION_MISMATCH",
        "INSTANCE_AMBIENT_OVERRIDE_REFUSED",
        "INSTANCE_PLATFORM_INVALID",
        "INSTANCE_PATH_LAYOUT_INVALID",
        "INSTANCE_PREREQUISITES_INVALID",
        "INSTANCE_DATA_TARGET_INVALID",
        "INSTANCE_KEY_CONFIGURATION_REQUIRED",
        "INSTANCE_MODE_ADAPTER_REQUIRED",
        "INSTANCE_DATABASE_TARGET_REFUSED",
        "INSTANCE_REDIS_TARGET_REFUSED",
        "INSTANCE_SHARED_NAMESPACE_REFUSED",
        "INSTANCE_SHARED_KEY_REFUSED",
        "INSTANCE_HCL_CONFIGURATION_REQUIRED",
        "INSTANCE_FRONTEND_CONFIGURATION_INVALID",
        "INSTANCE_COMPONENT_INVALID",
        "INSTANCE_PROVIDER_ATTESTATION_REQUIRED",
        "INSTANCE_RUNTIME_OBSERVATION_INVALID",
    }
)


class LifecycleError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _ERRORS else "INSTANCE_CONTEXT_INVALID"
        super().__init__(self.code)


def _fail(code):
    raise LifecycleError(code) from None


def _environment(values):
    if not isinstance(values, Mapping) or len(values) > 256:
        _fail("INSTANCE_CONFIGURATION_INVALID")
    copied = dict(values)
    for name, value in copied.items():
        if (
            type(name) is not str
            or not name
            or len(name) > 96
            or not name.isascii()
            or name != name.upper()
            or not name.replace("_", "").isalnum()
            or type(value) is not str
            or len(value) > 65536
            or "\0" in value
        ):
            _fail("INSTANCE_CONFIGURATION_INVALID")
        if value and (name.startswith("PG") or name in _PRELOADS):
            _fail("INSTANCE_AMBIENT_OVERRIDE_REFUSED")
    return MappingProxyType(copied)


@dataclass(frozen=True, slots=True)
class PreparationSnapshot:
    repository_id: str
    worktree_id: str
    commit: str
    config_generation: str | int | None
    platform: str
    source_root: str = field(repr=False)
    state_root: str = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    prerequisites: Mapping[str, str]

    def __post_init__(self):
        try:
            dev_instance_plan._public_id(self.repository_id)
            dev_instance_plan._public_id(self.worktree_id)
            dev_instance_plan._configuration_generation(self.config_generation)
        except dev_instance_plan.InstancePlanError:
            _fail("INSTANCE_CONTEXT_INVALID")
        if type(self.commit) is not str or not dev_instance_plan._COMMIT.fullmatch(self.commit):
            _fail("INSTANCE_CONTEXT_INVALID")
        if type(self.platform) is not str or self.platform not in {"win32", "darwin", "linux"}:
            _fail("INSTANCE_PLATFORM_INVALID")
        path_type = PureWindowsPath if self.platform == "win32" else PurePosixPath
        if any(
            type(value) is not str or "\0" in value or not path_type(value).is_absolute()
            for value in (self.source_root, self.state_root)
        ):
            _fail("INSTANCE_PATH_LAYOUT_INVALID")
        source, state = path_type(self.source_root), path_type(self.state_root)
        if (
            state == source
            or state.is_relative_to(source)
            or source.is_relative_to(state)
            or any(
                part in {".", ".."}
                for value in (self.source_root, self.state_root)
                for part in value.replace("\\", "/").split("/")
            )
        ):
            _fail("INSTANCE_PATH_LAYOUT_INVALID")
        if (
            not isinstance(self.prerequisites, Mapping)
            or any(type(key) is not str for key in self.prerequisites)
            or set(self.prerequisites) != PREREQUISITES
            or any(
                type(value) is not str or value not in {"PREPARED", "MISSING", "UNVERIFIED"}
                for value in self.prerequisites.values()
            )
        ):
            _fail("INSTANCE_PREREQUISITES_INVALID")
        object.__setattr__(self, "environment", _environment(self.environment))
        object.__setattr__(self, "prerequisites", MappingProxyType(dict(self.prerequisites)))


def _require(env, expected):
    if any(env.get(key) != value for key, value in expected.items()):
        _fail("INSTANCE_CONFIGURATION_MISMATCH")


def _url(value):
    try:
        parsed = urlsplit(value)
        _ = parsed.port  # Force validation without exposing the supplied URL.
        if parsed.fragment or parsed.query:
            raise ValueError()
        return parsed
    except (TypeError, ValueError):
        _fail("INSTANCE_DATA_TARGET_INVALID")


def _key(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == 32:
            return decoded
    except (ValueError, TypeError):
        pass
    _fail("INSTANCE_KEY_CONFIGURATION_REQUIRED")


def _validate_configuration(descriptor, snapshot):
    if descriptor.mode != "isolated":
        _fail("INSTANCE_MODE_ADAPTER_REQUIRED")
    if (
        (descriptor.repository_id, descriptor.worktree_id, descriptor.commit, descriptor.config_generation)
        != (snapshot.repository_id, snapshot.worktree_id, snapshot.commit, snapshot.config_generation)
        or descriptor.config_generation is None
        or not descriptor.configuration_present
    ):
        _fail("INSTANCE_CONTEXT_CHANGED")
    env, ports, resources = snapshot.environment, descriptor.ports, descriptor.resources
    native = descriptor.auth_mode == "native"
    _require(
        env,
        {
            "SBOM_DEV_RESOURCE_ID": descriptor.instance_id,
            "APP_ENVIRONMENT": "development",
            "AUTH_ENABLED": "true",
            "DEV_DEFAULT_TENANT": "false",
            "ENTRA_ENABLED": "false",
            "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false",
            "PYTHON_DOTENV_DISABLED": "1",
            "NATIVE_AUTH_ENABLED": "true" if native else "false",
            "HCL_AUTH_ENABLED": "false" if native else "true",
            "NEXT_PUBLIC_AUTH_ENABLED": "true",
            "NEXT_PUBLIC_ENTRA_ENABLED": "false",
            "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true" if native else "false",
            "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false" if native else "true",
            "AUTH_SESSION_STORE": "redis",
            "APP_ORIGIN": descriptor.origin,
            "CORS_ORIGINS": descriptor.origin,
            "API_RATE_LIMIT_ENABLED": "true",
            "DEV_API_PORT": str(ports["api"]),
            "DEV_FRONTEND_PORT": str(ports["frontend"]),
            "SBOM_API_URL": f"http://127.0.0.1:{ports['api']}",
            "NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{ports['api']}",
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": str(ports["smtp"]),
        },
    )
    if env.get("APP_ENV", "development") != "development" or env.get("ALLOW_SQLITE", "false") != "false":
        _fail("INSTANCE_CONFIGURATION_MISMATCH")
    if env.get("GREENFIELD_STATE") or env.get("SBOM_DEV_PROFILE", "isolated") != "isolated":
        _fail("INSTANCE_SHARED_NAMESPACE_REFUSED")
    database = _url(env.get("DATABASE_URL", ""))
    if (
        database.scheme != "postgresql+psycopg"
        or database.hostname != "127.0.0.1"
        or database.port != ports["postgres"]
        or database.path != "/" + resources["database"]
        or unquote(database.username or "") != resources["restricted_database_role"]
        or not database.password
    ):
        _fail("INSTANCE_DATABASE_TARGET_REFUSED")
    for key, index in (
        ("REDIS_URL", 0),
        ("CELERY_BROKER_URL", 0),
        ("CELERY_RESULT_BACKEND", 2),
        ("AUTH_SESSION_REDIS_URL", 1),
        ("NATIVE_AUTH_RATE_LIMIT_STORAGE_URI", 3),
    ):
        redis = _url(env.get(key, ""))
        if (
            redis.scheme not in {"redis", "rediss"}
            or redis.hostname != "127.0.0.1"
            or redis.port != ports["redis"]
            or redis.path != "/" + str(index)
            or not redis.password
        ):
            _fail("INSTANCE_REDIS_TARGET_REFUSED")
    namespace_values = {
        "CELERY_DEFAULT_QUEUE": resources["queue_default"],
        "CELERY_REPORTS_QUEUE": resources["queue_reports"],
        "SBOM_DEV_BEAT_NAMESPACE": resources["beat_namespace"],
        "AUTH_SESSION_KEY_PREFIX": resources["session_namespace"],
        "NATIVE_AUTH_RATE_LIMIT_NAMESPACE": resources["rate_limit_namespace"],
        "NATIVE_MAIL_WORKER_HEARTBEAT_KEY": resources["rate_limit_namespace"] + "mail-worker",
    }
    if any(key in env and env[key] != expected for key, expected in namespace_values.items()):
        _fail("INSTANCE_SHARED_NAMESPACE_REFUSED")
    path_type = PureWindowsPath if snapshot.platform == "win32" else PurePosixPath
    state = path_type(snapshot.state_root)
    if state.name != descriptor.instance_id:
        _fail("INSTANCE_PATH_LAYOUT_INVALID")
    _require(
        env,
        {
            "REPORT_ARTIFACT_STORAGE_PATH": str(state / "artifacts"),
            "SBOM_WORKSPACE_STORAGE_DIR": str(state / "workspaces"),
        },
    )
    if env.get("SBOM_DEV_STATE_DIR", str(state / ".dev-logs")) != str(state / ".dev-logs") or env.get(
        "LOG_FILE", ""
    ) not in {"", str(state / ".dev-logs" / "application.log")}:
        _fail("INSTANCE_PATH_LAYOUT_INVALID")
    if (
        env.get("SMTP_USE_TLS") not in {"true", "false"}
        or env.get("SMTP_USE_STARTTLS") not in {"true", "false"}
        or env["SMTP_USE_TLS"] == env["SMTP_USE_STARTTLS"] == "true"
    ):
        _fail("INSTANCE_CONFIGURATION_MISMATCH")
    session_key = _key(env.get("AUTH_SESSION_ENCRYPTION_KEY", ""))
    if native:
        _require(
            env,
            {
                "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
                "NATIVE_AUTH_RATE_LIMIT_ENABLED": "true",
                "EMAIL_DELIVERY_ENABLED": "true",
                "NATIVE_JWT_ISSUER": descriptor.origin + "/native",
                "NATIVE_ACTIVATION_FRONTEND_URL": descriptor.origin + "/activate-account",
                "NATIVE_PASSWORD_RESET_FRONTEND_URL": descriptor.origin + "/reset-password",
                "EMAIL_VERIFICATION_FRONTEND_URL": descriptor.origin + "/verify-email",
            },
        )
        if not all(
            env.get(key)
            for key in (
                "NATIVE_JWT_PRIVATE_KEY",
                "NATIVE_JWT_PUBLIC_KEY",
                "NATIVE_JWT_AUDIENCE",
                "NATIVE_JWT_ACTIVE_KID",
            )
        ):
            _fail("INSTANCE_KEY_CONFIGURATION_REQUIRED")
        if (
            session_key == _key(env.get("NATIVE_SECURITY_OUTBOX_KEY", ""))
            or env["NATIVE_JWT_PRIVATE_KEY"] == env["NATIVE_JWT_PUBLIC_KEY"]
        ):
            _fail("INSTANCE_SHARED_KEY_REFUSED")
    else:
        issuer = _url(env.get("HCL_IAM_ISSUER", ""))
        if issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password:
            _fail("INSTANCE_HCL_CONFIGURATION_REQUIRED")
        if not env.get("HCL_IAM_AUDIENCE") or not env.get("NEXT_PUBLIC_HCL_IAM_CLIENT_ID"):
            _fail("INSTANCE_HCL_CONFIGURATION_REQUIRED")
        _require(
            env,
            {
                "NEXT_PUBLIC_HCL_IAM_ISSUER": env["HCL_IAM_ISSUER"],
                "NEXT_PUBLIC_HCL_IAM_REDIRECT_URI": descriptor.origin + "/api/auth/callback",
            },
        )
    try:
        dev_config.component_environment(env, "frontend")
    except dev_config.ConfigurationError:
        _fail("INSTANCE_FRONTEND_CONFIGURATION_INVALID")


@dataclass(frozen=True, slots=True)
class ComponentCommand:
    component: str
    executable_kind: str
    arguments: tuple[str, ...] = field(repr=False)
    working_directory_kind: str

    def __post_init__(self):
        if (
            type(self.component) is not str
            or self.component not in COMPONENTS
            or type(self.executable_kind) is not str
            or self.executable_kind != ("node" if self.component == "Frontend" else "python")
            or type(self.working_directory_kind) is not str
            or self.working_directory_kind != ("frontend_workspace" if self.component == "Frontend" else "source")
            or type(self.arguments) not in {tuple, list}
            or len(self.arguments) > 40
            or any(
                type(value) is not str or not value or len(value) > 256 or any(ord(char) < 32 for char in value)
                for value in self.arguments
            )
        ):
            _fail("INSTANCE_COMPONENT_INVALID")
        object.__setattr__(self, "arguments", tuple(self.arguments))


@dataclass(frozen=True, slots=True)
class LifecyclePlan:
    descriptor: dev_instance_plan.InstanceDescriptor
    snapshot: PreparationSnapshot = field(repr=False)

    def __post_init__(self):
        if (
            type(self.descriptor) is not dev_instance_plan.InstanceDescriptor
            or type(self.snapshot) is not PreparationSnapshot
        ):
            _fail("INSTANCE_CONTEXT_INVALID")
        _validate_configuration(self.descriptor, self.snapshot)

    @property
    def blockers(self):
        missing = tuple(
            "INSTANCE_" + key.upper() + "_PREPARATION_REQUIRED"
            for key in sorted(PREREQUISITES)
            if self.snapshot.prerequisites[key] != "PREPARED"
        )
        extra = ("INSTANCE_LOCAL_PROVIDER_UNAVAILABLE",) if self.descriptor.provider == "local" else ()
        return (*_UNAVAILABLE, *extra, *missing)

    @property
    def steps(self):
        return STEPS

    @property
    def startup_order(self):
        return COMPONENTS

    @property
    def ready(self):
        return False

    @property
    def live_operations_authorized(self):
        return False

    @property
    def ownership_verified(self):
        return False

    @property
    def commands(self):
        ports, resources = self.descriptor.ports, self.descriptor.resources
        commands = []
        for component, queue in (
            ("Celery worker", resources["queue_default"]),
            ("Celery reports worker", resources["queue_reports"]),
        ):
            args = (
                "-B",
                "-m",
                "celery",
                "-A",
                "scripts.dev:celery_app",
                "worker",
                "--queues=" + queue,
                "--hostname={runtime_node}",
                "--concurrency=1",
                "--prefetch-multiplier=1",
                "--pool=" + ("prefork" if self.snapshot.platform == "linux" else "solo"),
            )
            commands.append(ComponentCommand(component, "python", args, "source"))
        commands.extend(
            (
                ComponentCommand(
                    "Celery Beat",
                    "python",
                    (
                        "-B",
                        "-m",
                        "celery",
                        "-A",
                        "scripts.dev:celery_app",
                        "beat",
                        "--scheduler=scripts.dev:LocalScheduler",
                        "--schedule={beat_schedule_path}",
                        "--pidfile={beat_pid_path}",
                    ),
                    "source",
                ),
                ComponentCommand(
                    "API",
                    "python",
                    (
                        "-B",
                        "-m",
                        "uvicorn",
                        "app.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(ports["api"]),
                        "--no-proxy-headers",
                    ),
                    "source",
                ),
                ComponentCommand(
                    "Frontend",
                    "node",
                    (
                        "{next_cli}",
                        "dev",
                        "--webpack",
                        "--hostname",
                        "127.0.0.1",
                        "--port",
                        str(ports["frontend"]),
                        "--experimental-https",
                        "--experimental-https-cert",
                        "{tls_cert_path}",
                        "--experimental-https-key",
                        "{tls_key_path}",
                    ),
                    "frontend_workspace",
                ),
            )
        )
        return tuple(commands)

    def component_environment(self, component):
        if component not in COMPONENTS:
            _fail("INSTANCE_COMPONENT_INVALID")
        role = "frontend" if component == "Frontend" else "api"
        try:
            projected = dict(dev_config.component_environment(self.snapshot.environment, role))
        except dev_config.ConfigurationError:
            _fail("INSTANCE_FRONTEND_CONFIGURATION_INVALID")
        projected["SBOM_DEV_RESOURCE_ID"] = self.descriptor.instance_id
        return MappingProxyType(projected)

    def to_public_dict(self):
        return {
            "instance_id": self.descriptor.instance_id,
            "mode": self.descriptor.mode,
            "steps": list(self.steps),
            "startup_order": list(self.startup_order),
            "blockers": list(self.blockers),
            "ready": False,
            "live_operations_authorized": False,
            "ownership_verified": False,
        }


def plan_lifecycle(descriptor, snapshot):
    return LifecyclePlan(descriptor, snapshot)


def require_current(plan, descriptor, snapshot):
    if (
        type(plan) is not LifecyclePlan
        or type(descriptor) is not dev_instance_plan.InstanceDescriptor
        or type(snapshot) is not PreparationSnapshot
        or descriptor != plan.descriptor
        or snapshot != plan.snapshot
    ):
        _fail("INSTANCE_CONTEXT_CHANGED")


def require_live_execution(plan):
    if type(plan) is not LifecyclePlan:
        _fail("INSTANCE_CONTEXT_INVALID")
    _fail("INSTANCE_PROVIDER_ATTESTATION_REQUIRED")


def live_execution_blockers() -> tuple[str, ...]:
    """Concrete missing adapters; supplied readiness can never remove these."""
    return _UNAVAILABLE


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    pid: int
    birth: str = field(repr=False)
    executable: str = field(repr=False)

    def __post_init__(self):
        if (
            type(self.pid) is not int
            or not 0 < self.pid <= 0xFFFFFFFF
            or any(
                type(value) is not str or not value or len(value) > 4096 or any(ord(char) < 32 for char in value)
                for value in (self.birth, self.executable)
            )
        ):
            _fail("INSTANCE_RUNTIME_OBSERVATION_INVALID")


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    component: str
    status: str
    recorded: RuntimeIdentity | None = field(default=None, repr=False)
    current: RuntimeIdentity | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.component) is not str
            or self.component not in COMPONENTS
            or type(self.status) is not str
            or self.status not in {"RUNNING", "PARTIAL", "STOPPED", "UNKNOWN", "UNOWNED"}
            or any(value is not None and type(value) is not RuntimeIdentity for value in (self.recorded, self.current))
            or self.status == "STOPPED"
            and self.current is not None
        ):
            _fail("INSTANCE_RUNTIME_OBSERVATION_INVALID")


@dataclass(frozen=True, slots=True)
class CleanupDecision:
    component: str
    action: str
    code: str

    def __post_init__(self):
        if (
            type(self.component) is not str
            or self.component not in COMPONENTS
            or type(self.action) is not str
            or self.action not in {"PRESERVE", "REQUEST_RUNTIME_REVALIDATION"}
            or type(self.code) is not str
            or self.code
            not in {
                "INSTANCE_OWNERSHIP_UNVERIFIED",
                "INSTANCE_UNREGISTERED_PROCESS_PRESERVED",
                "INSTANCE_PID_REUSE_PRESERVED",
                "INSTANCE_RUNTIME_REVALIDATION_REQUIRED",
            }
            or (self.action == "REQUEST_RUNTIME_REVALIDATION")
            != (self.code == "INSTANCE_RUNTIME_REVALIDATION_REQUIRED")
        ):
            _fail("INSTANCE_RUNTIME_OBSERVATION_INVALID")


def cleanup_contract(observations: Sequence[RuntimeObservation]) -> tuple[CleanupDecision, ...]:
    """Propose Runtime revalidation only; never terminate, delete or clear state.

    Cleanup remains available after configuration drift. One unknown component
    does not prevent requesting verified Runtime cleanup for the other records.
    """
    if (
        type(observations) not in {tuple, list}
        or len(observations) > len(COMPONENTS)
        or any(type(item) is not RuntimeObservation for item in observations)
        or len({item.component for item in observations}) != len(observations)
    ):
        _fail("INSTANCE_RUNTIME_OBSERVATION_INVALID")
    decisions = []
    for item in sorted(observations, key=lambda value: COMPONENTS.index(value.component), reverse=True):
        action, code = "PRESERVE", "INSTANCE_OWNERSHIP_UNVERIFIED"
        if item.recorded is None:
            code = "INSTANCE_UNREGISTERED_PROCESS_PRESERVED"
        elif item.status in {"UNKNOWN", "UNOWNED"}:
            pass
        elif item.current is not None and item.current != item.recorded:
            code = "INSTANCE_PID_REUSE_PRESERVED"
        elif item.current is not None or item.status in {"PARTIAL", "STOPPED"}:
            action, code = "REQUEST_RUNTIME_REVALIDATION", "INSTANCE_RUNTIME_REVALIDATION_REQUIRED"
        decisions.append(CleanupDecision(item.component, action, code))
    return tuple(decisions)
