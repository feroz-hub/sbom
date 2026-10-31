"""Pure development configuration planning; no public CLI or preparation actions.

Callers supply snapshots read through the existing profile's protected readers.
Resolving a plan proves only local target policy, not live database identity,
ownership, readiness or authorization to prepare/enroll. Values are deliberately
excluded from representations. Do not serialize a plan into logs or issue bodies.
The launcher adapters read snapshots separately; privileged actions still require
their own target confirmation and operator authorization.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from io import StringIO
from pathlib import PurePath
from types import MappingProxyType
from urllib.parse import quote, urlsplit

_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_PUBLIC = frozenset(
    {
        "NEXT_PUBLIC_AUTH_ENABLED",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED",
        "NEXT_PUBLIC_NATIVE_AUTH_ENABLED",
        "NEXT_PUBLIC_ENTRA_ENABLED",
        "NEXT_PUBLIC_API_URL",
        "NEXT_PUBLIC_COMPARE_V1_FALLBACK",
        "NEXT_PUBLIC_HCL_IAM_ISSUER",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID",
        "NEXT_PUBLIC_HCL_IAM_REDIRECT_URI",
        "NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI",
        "NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI",
        "NEXT_PUBLIC_HCL_IAM_SCOPES",
    }
)
_TRANSPORT = frozenset(
    {
        "HOME",
        "PATH",
        "TMPDIR",
        "LANG",
        "TERM",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    }
)
_FRONTEND = (
    _PUBLIC
    | _TRANSPORT
    | frozenset(
        {
            "APP_ORIGIN",
            "SBOM_API_URL",
            "NODE_ENV",
            "NATIVE_AUTH_ENABLED",
            "ENTRA_ENABLED",
            "ENTRA_TENANT_ID",
            "ENTRA_FRONTEND_CLIENT_ID",
            "ENTRA_API_CLIENT_ID",
            "ENTRA_API_SCOPE",
            "HCL_IAM_CA_BUNDLE",
            "AUTH_SESSION_STORE",
            "AUTH_SESSION_REDIS_URL",
            "AUTH_SESSION_ENCRYPTION_KEY",
            "AUTH_TRANSACTION_KEY_FILE",
        }
    )
)
_PRIVATE = _TRANSPORT | frozenset(
    {
        "APP_ORIGIN",
        "SBOM_API_URL",
        "NODE_ENV",
        "AUTH_ENABLED",
        "HCL_AUTH_ENABLED",
        "NATIVE_AUTH_ENABLED",
        "ENTRA_ENABLED",
        "DEV_DEFAULT_TENANT",
        "DEV_API_PORT",
        "DEV_FRONTEND_PORT",
        "PYTHONPATH",
        "PYTHON_DOTENV_DISABLED",
        "PYTHONDONTWRITEBYTECODE",
        "GREENFIELD_STATE",
        "NATIVE_JWT_PUBLIC_KEY",
        "NATIVE_JWT_ACTIVE_KID",
        "NATIVE_JWT_ISSUER",
        "NATIVE_JWT_AUDIENCE",
        "NATIVE_JWT_ALGORITHM",
        "HCL_IAM_CA_BUNDLE",
        "AUTH_SESSION_STORE",
        "AUTH_TRANSACTION_KEY_FILE",
    }
)


class ConfigurationError(ValueError):
    """A stable reason and safe guidance, never raw values or parser exceptions."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class DatabaseTarget:
    host: str
    port: int
    name: str


@dataclass(frozen=True)
class ServicePorts:
    postgres: int
    redis: int
    smtp: int
    postgres_provider: str | None = None
    redis_provider: str | None = None


@dataclass(frozen=True)
class GreenfieldInputs:
    state_root: str
    runtime_password: str = field(repr=False)
    security_mail_key: str | None = field(default=None, repr=False)
    provider_storage_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ConfigurationPlan:
    profile: str
    family: str
    purpose: str
    database: DatabaseTarget
    authentication_enabled: bool | None
    auth_modes: tuple[str, ...]
    environment: Mapping[str, str] = field(repr=False)
    provenance: Mapping[str, str] = field(repr=False)
    classification: Mapping[str, str] = field(repr=False)
    components: Mapping[str, Mapping[str, str]] = field(repr=False)


def _snapshot(values: Mapping[str, str | None]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not _NAME.fullmatch(key):
            raise ConfigurationError("INVALID_ENVIRONMENT", "Environment names must be literal identifiers.")
        if value is None:
            continue  # dotenv represents an unassigned name as None.
        if not isinstance(value, str) or "\0" in value:
            raise ConfigurationError("INVALID_ENVIRONMENT", "Environment values must be strings without NUL bytes.")
        result[key] = value
    return result


def parse_managed(text: str) -> dict[str, str]:
    """Decode the existing managed KEY=JSON-string format, without interpolation."""
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if not separator or not key.isidentifier():
            raise ConfigurationError("INVALID_MANAGED_CONFIG", "Repair the saved managed KEY=VALUE lines.")
        try:
            value = json.loads(raw) if raw.startswith('"') else raw
        except ValueError:
            raise ConfigurationError("INVALID_MANAGED_CONFIG", "Repair a malformed managed quoted value.") from None
        if not isinstance(value, str):
            raise ConfigurationError("INVALID_MANAGED_CONFIG", "Managed configuration values must be strings.")
        result[key] = value
    return _snapshot(result)


def parse_windows(text: str) -> dict[str, str]:
    """Decode literal assignments only; never run PowerShell or evaluate content."""
    result = {}
    for line in text.removeprefix("\ufeff").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*\$env:([A-Za-z_][A-Za-z_0-9]*)\s*=\s*'((?:[^']|'')*)'\s*", line)
        if not match:
            raise ConfigurationError("INVALID_WINDOWS_CONFIG", "Use literal single-quoted environment assignments.")
        result[match[1]] = match[2].replace("''", "'")
    return _snapshot(result)


def parse_dotenv(text: str) -> dict[str, str]:
    """Use the existing dotenv codec on supplied text, with interpolation disabled."""
    from dotenv import dotenv_values

    return _snapshot(dotenv_values(stream=StringIO(text), interpolate=False))


def _database(url: str, profile: str, family: str) -> DatabaseTarget:
    try:
        if url != url.lstrip() or any(ord(char) < 32 or ord(char) == 127 for char in url):
            raise ValueError()
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
        name = parsed.path[1:]
        if "?" in url or "#" in url:
            raise ConfigurationError(
                "TARGET_QUERY_REVIEW_REQUIRED", "Review database URL options explicitly; no options were removed."
            )
        allowed = (
            parsed.scheme in {"postgresql", "postgresql+psycopg"}
            and host in _LOOPBACK
            and bool(name)
            and not name.startswith("/")
            and port != 0
        )
        if profile == "greenfield":
            allowed = allowed and (
                parsed.scheme == "postgresql+psycopg"
                and host == "127.0.0.1"
                and port == 56044
                and name == "sbom_greenfield_uuid"
                and parsed.username == "greenfield_app"
            )
        elif family == "managed":
            allowed = allowed and (
                parsed.scheme == "postgresql+psycopg"
                and host in {"localhost", "127.0.0.1"}
                and parsed.path == "/sbom_analyser_dev"
                and bool(port)
            )
        else:
            allowed = allowed and name not in {"postgres", "template0", "template1", "sbom_greenfield_uuid"}
            allowed = allowed and port != 56044
        if not allowed:
            raise ValueError()
    except ConfigurationError:
        raise
    except (TypeError, ValueError):
        raise ConfigurationError(
            "INVALID_DATABASE_TARGET", "Select the approved local PostgreSQL development target."
        ) from None
    return DatabaseTarget(host, port if port is not None else 5432, name)


def _managed_fixed(ports: ServicePorts) -> dict[str, str]:
    return {
        "DEV_API_PORT": "18000",
        "DEV_FRONTEND_PORT": "13000",
        "AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "ENTRA_ENABLED": "false",
        "NATIVE_JWT_VERIFICATION_KEYS_JSON": "{}",
        "NATIVE_AUTH_ENABLED": "true",
        "NATIVE_USER_CREATION_ENABLED": "true",
        "NATIVE_IAM_PRODUCTION": "false",
        "DEV_DEFAULT_TENANT": "false",
        "AUTHORIZATION_CATALOG_MODE": "DATABASE",
        "AUTHORIZATION_CATALOG_FAIL_CLOSED": "true",
        "TENANT_ROLE_ASSIGNMENT_MODE": "DATABASE",
        "TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED": "true",
        "CELERY_USE_DATABASE_BROKER": "false",
        "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
        "NATIVE_AUTH_RATE_LIMIT_ENABLED": "true",
        "AUTH_SESSION_STORE": "redis",
        "APP_ORIGIN": "https://localhost:13000",
        "NATIVE_ACTIVATION_FRONTEND_URL": "https://localhost:13000/activate-account",
        "NATIVE_PASSWORD_RESET_FRONTEND_URL": "https://localhost:13000/reset-password",
        "EMAIL_VERIFICATION_FRONTEND_URL": "https://localhost:13000/verify-email",
        "NATIVE_JWT_ISSUER": "https://localhost:13000/native",
        "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
        "NATIVE_JWT_ACTIVE_KID": "native-dev",
        "NATIVE_JWT_ALGORITHM": "RS256",
        "EMAIL_PROVIDER": "smtp",
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_FROM_ADDRESS": "sbom-dev@localhost.test",
        "EMAIL_FROM_NAME": "SBOM Analyzer",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(ports.smtp),
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "false",
        "CORS_ORIGINS": "https://localhost:13000",
        "SBOM_API_URL": "http://127.0.0.1:18000",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": "http://127.0.0.1:18000",
        "NEXT_PUBLIC_HCL_IAM_ISSUER": "",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "",
        "REDIS_URL": f"redis://127.0.0.1:{ports.redis}/0",
        "CELERY_BROKER_URL": f"redis://127.0.0.1:{ports.redis}/0",
        "CELERY_RESULT_BACKEND": f"redis://127.0.0.1:{ports.redis}/0",
        "AUTH_SESSION_REDIS_URL": f"redis://127.0.0.1:{ports.redis}/1",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": f"redis://127.0.0.1:{ports.redis}/2",
    }


def _greenfield_fixed(root: str, inputs: GreenfieldInputs) -> dict[str, str]:
    state = inputs.state_root.rstrip("/\\")
    if not inputs.runtime_password or not state:
        raise ConfigurationError("SETUP_REQUIRED", "Restore the existing protected Greenfield runtime configuration.")
    return {
        "PYTHON_DOTENV_DISABLED": "1",
        "GREENFIELD_STATE": inputs.state_root,
        "PYTHONPATH": root,
        "PYTHONDONTWRITEBYTECODE": "1",
        "DATABASE_URL": "postgresql+psycopg://greenfield_app:"
        + quote(inputs.runtime_password, safe=" +")
        + "@127.0.0.1:56044/sbom_greenfield_uuid",
        "AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
        "NATIVE_AUTH_ENABLED": "true",
        "ENTRA_ENABLED": "false",
        "NATIVE_JWT_VERIFICATION_KEYS_JSON": "{}",
        "DEV_DEFAULT_TENANT": "false",
        "NATIVE_IAM_PRODUCTION": "false",
        "NATIVE_SECURITY_OUTBOX_ENABLED": "true",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": "redis://127.0.0.1:56381/3",
        "API_AUTH_MODE": "none",
        "NATIVE_USER_CREATION_ENABLED": "true",
        "NATIVE_PASSWORD_RESET_FRONTEND_URL": "https://localhost:13000/reset-password",
        "API_RATE_LIMIT_ENABLED": "true",
        "NATIVE_JWT_ISSUER": "https://greenfield.local",
        "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
        "NATIVE_JWT_ACCESS_TOKEN_TTL_SECONDS": "3600",
        "AUTHORIZATION_CATALOG_MODE": "DATABASE",
        "AUTHORIZATION_CATALOG_FAIL_CLOSED": "true",
        "TENANT_ROLE_ASSIGNMENT_MODE": "DATABASE",
        "TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED": "true",
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_FROM_ADDRESS": "sbom-greenfield@example.test",
        "EMAIL_VERIFICATION_FRONTEND_URL": "https://localhost:13000/verify-email",
        "NATIVE_ACTIVATION_FRONTEND_URL": "https://localhost:13000/activate-account",
        "REPORT_NOTIFICATIONS_ENABLED": "true",
        "REPORT_NOTIFICATION_BASE_URL": "https://localhost:13000",
        "REPORT_ARTIFACT_STORAGE_PATH": str(PurePath(state) / "reports"),
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": "1026",
        "SMTP_USE_STARTTLS": "false",
        "NVD_ENABLED": "false",
        "ANALYSIS_SOURCES": "OSV",
        "SBOM_WORKSPACE_STORAGE_DIR": str(PurePath(state) / "workspaces"),
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_ENTRA_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": "http://127.0.0.1:18000",
        "SBOM_API_URL": "http://127.0.0.1:18000",
        "APP_ORIGIN": "https://localhost:13000",
        "CORS_ORIGINS": "https://localhost:13000",
        "AUTH_SESSION_STORE": "redis",
        "AUTH_SESSION_REDIS_URL": "redis://127.0.0.1:56381/1",
        "REDIS_URL": "redis://127.0.0.1:56381/0",
        "CELERY_BROKER_URL": "redis://127.0.0.1:56381/0",
        "CELERY_RESULT_BACKEND": "redis://127.0.0.1:56381/2",
        "SBOM_AUTO_REPAIR_ENABLED": "true",
        "NODE_ENV": "development",
        "LOG_FILE": "",
    }


def resolve_configuration(
    *,
    profile: str,
    inherited: Mapping[str, str],
    saved: Mapping[str, str],
    root: str,
    platform: str,
    family: str = "managed",
    purpose: str = "existing",
    frontend: Mapping[str, str] | None = None,
    ports: ServicePorts | None = None,
    greenfield: GreenfieldInputs | None = None,
) -> ConfigurationPlan:
    """Resolve supplied snapshots only. File discovery and action approval stay outside.

    ``existing`` matches inspection precedence; ``startup`` models prepared managed
    startup without generating credentials or changing providers. Runtime instance
    decoration is deliberately left to the existing ownership-aware launcher.
    """
    if profile not in {"legacy", "greenfield"} or purpose not in {"existing", "startup"}:
        raise ConfigurationError("INVALID_SELECTION", "Choose an explicit supported profile and resolution purpose.")
    if family not in {"managed", "windows", "env"} or platform not in {"win32", "darwin", "linux"}:
        raise ConfigurationError("INVALID_SELECTION", "Choose a supported configuration family and operating system.")
    env: dict[str, str] = {}
    provenance: dict[str, str] = {}

    def layer(values: Mapping[str, str], source: str, *, defaults: bool = False) -> None:
        for key, value in _snapshot(values).items():
            if not defaults or key not in env:
                env[key], provenance[key] = value, source

    process = _snapshot(inherited)
    if profile == "greenfield":
        if greenfield is None:
            raise ConfigurationError("SETUP_REQUIRED", "Supply the existing protected Greenfield snapshots.")
        if any(not isinstance(value, str) for value in saved.values()):
            raise ConfigurationError("INVALID_ENVIRONMENT", "Greenfield saved JSON values must all be strings.")
        allowed = _TRANSPORT if platform == "win32" else {"HOME", "PATH", "TMPDIR", "LANG", "TERM"}
        layer({key: value for key, value in process.items() if key in allowed}, "process")
        layer(saved, "greenfield.environment")
        if "NATIVE_SECURITY_OUTBOX_KEY" not in env:
            if greenfield.security_mail_key is None:
                raise ConfigurationError("SETUP_REQUIRED", "Restore the original protected security-mail key.")
            layer({"NATIVE_SECURITY_OUTBOX_KEY": greenfield.security_mail_key}, "greenfield.security-mail-key")
        if "AI_CONFIG_ENCRYPTION_KEY" not in env:
            try:
                key = base64.b64encode(base64.urlsafe_b64decode(greenfield.provider_storage_key)).decode()
            except (TypeError, ValueError, binascii.Error):
                raise ConfigurationError(
                    "SETUP_REQUIRED", "Restore the original protected provider-storage key."
                ) from None
            layer({"AI_CONFIG_ENCRYPTION_KEY": key}, "greenfield.provider-storage-key")
        layer(_greenfield_fixed(root, greenfield), "policy.greenfield")
    else:
        layer(process, "process")
        if family != "managed":
            layer(frontend or {}, "frontend.env.local")
        layer(saved, "managed" if family == "managed" else f"legacy.{family}")
        if not env.get("DATABASE_URL") or (family == "managed" and not saved.get("DATABASE_URL")):
            raise ConfigurationError(
                "SETUP_REQUIRED", "Prepare the selected profile's database configuration explicitly."
            )
        if family == "managed" and purpose == "startup":
            if ports is None or any(
                type(port) is not int or not 1 <= port <= 65535 for port in (ports.postgres, ports.redis, ports.smtp)
            ):
                raise ConfigurationError("INVALID_PORTS", "Supply the selected service ports before resolving startup.")
            pg = ports.postgres_provider or ("docker" if ports.postgres == 55439 else "local")
            redis = ports.redis_provider or ("docker" if ports.redis == 56379 else "local")
            if pg not in {"local", "docker"} or redis not in {"local", "docker"}:
                raise ConfigurationError("INVALID_PROVIDER", "Choose an explicit local or docker dependency provider.")
            target = _database(env["DATABASE_URL"], profile, family)
            if saved.get("DEV_POSTGRES_PROVIDER") not in {None, pg}:
                raise ConfigurationError("SETUP_REQUIRED", "Review an explicit database-provider change during setup.")
            if saved.get("DEV_REDIS_PROVIDER") not in {None, redis}:
                raise ConfigurationError("SETUP_REQUIRED", "Review an explicit Redis-provider change during setup.")
            if target.port != ports.postgres:
                raise ConfigurationError(
                    "DATABASE_PORT_CONFLICT", "Selected PostgreSQL port differs from saved configuration."
                )
            layer({"DEV_POSTGRES_PROVIDER": pg, "DEV_REDIS_PROVIDER": redis}, "selection.providers")
            layer(_managed_fixed(ports), "policy.managed")
            layer({"NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false"}, "default.managed", defaults=True)
        elif family != "managed":
            native = env.get("NATIVE_AUTH_ENABLED", "false").lower() == "true"
            layer(
                {
                    "DEV_API_PORT": "8000",
                    "DEV_FRONTEND_PORT": "3000",
                    "AUTH_ENABLED": "true",
                    "NATIVE_AUTH_ENABLED": "false",
                    "HCL_AUTH_ENABLED": "false" if native else "true",
                    "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false" if native else "true",
                    "NEXT_PUBLIC_NATIVE_AUTH_ENABLED": "true" if native else "false",
                    "REDIS_URL": "redis://127.0.0.1:6379/0",
                },
                "default.legacy",
                defaults=True,
            )
            layer(
                {"CELERY_BROKER_URL": env["REDIS_URL"], "CELERY_RESULT_BACKEND": env["REDIS_URL"]},
                "default.legacy",
                defaults=True,
            )
            if env.get("CELERY_USE_DATABASE_BROKER", "false").lower() == "true":
                raise ConfigurationError("UNSUPPORTED_BROKER", "Select this installation's Redis broker explicitly.")
            layer({"PYTHONPATH": root}, "policy.legacy")

    # Windows environment names are case-insensitive; never emit ambiguous
    # names that can change effective values when passed to another component.
    if len({key.casefold() for key in env}) != len(env):
        raise ConfigurationError("ENVIRONMENT_NAME_CONFLICT", "Resolve case-variant environment names explicitly.")
    target = _database(env["DATABASE_URL"], profile, family)
    for key in (
        "NEXT_PUBLIC_API_URL",
        "NEXT_PUBLIC_HCL_IAM_ISSUER",
        "NEXT_PUBLIC_HCL_IAM_REDIRECT_URI",
        "NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI",
        "NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI",
    ):
        try:
            public_url = urlsplit(env.get(key, ""))
            if public_url.username is not None or public_url.password is not None:
                raise ValueError()
        except ValueError:
            raise ConfigurationError(
                "INVALID_PUBLIC_URL", "Review public endpoint configuration; embedded credentials cannot be projected."
            ) from None
    classification = {key: "public" if key in _PUBLIC else "private" if key in _PRIVATE else "secret" for key in env}
    freeze = lambda values: MappingProxyType(dict(values))  # noqa: E731
    components = {role: freeze(env) for role in ("api", "worker", "beat")}
    components["frontend"] = freeze({key: value for key, value in env.items() if key in _FRONTEND})
    components["public"] = freeze({key: value for key, value in env.items() if key in _PUBLIC})
    # These are explicit observations, not component defaults. In particular,
    # absent flags in an existing snapshot do not prove authentication is off.
    truthy = {"true", "1", "yes", "on"}
    flag = env.get("AUTH_ENABLED", "").lower()
    authentication_enabled = True if flag in truthy else False if flag in {"false", "0", "no", "off"} else None
    modes = tuple(
        mode
        for mode, key in (("native", "NATIVE_AUTH_ENABLED"), ("hclcs", "HCL_AUTH_ENABLED"), ("entra", "ENTRA_ENABLED"))
        if env.get(key, "").lower() in truthy
    )
    return ConfigurationPlan(
        profile,
        family if profile == "legacy" else "greenfield",
        purpose,
        target,
        authentication_enabled,
        modes,
        freeze(env),
        freeze(provenance),
        freeze(classification),
        freeze(components),
    )
