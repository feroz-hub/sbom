"""Native operator context and read-only aggregate status, never enrollment.

This module neither imports application startup/settings nor runs subprocesses.
The child environment is a disabled-bootstrap baseline for a future separately
authorized operator flow, not permission to create/resend an account or token.
"""

from __future__ import annotations

import ast
import base64
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import unquote, urlsplit

if __package__:
    from . import dev_config, dev_diagnostics, dev_environment, dev_prepared
    from .greenfield_migration_graph import discover
else:
    import dev_config
    import dev_diagnostics
    import dev_environment
    import dev_prepared
    from greenfield_migration_graph import discover

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
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    }
)
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


class OperatorError(ValueError):
    """Only an allowlisted reason and fixed safe guidance, never raw exceptions."""

    def __init__(self, code, guidance):
        self.code = code
        super().__init__(f"{code}: {guidance}")


class OperatorEnvironment(Mapping[str, str]):
    """Immutable copied values with a redacted representation."""

    __slots__ = ("_values",)

    def __init__(self, values):
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __getitem__(self, key: str) -> str:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return f"<OperatorEnvironment: {len(self)} values redacted>"

    def __setattr__(self, name, value):
        raise AttributeError("Operator environment snapshots are immutable")


@dataclass(frozen=True)
class NativeOperatorContext:
    profile: str
    family: str
    database: dev_config.DatabaseTarget
    confirmed_database: str
    environment: OperatorEnvironment = field(repr=False)
    root: Path = field(repr=False)
    working_directory: Path = field(repr=False)


@dataclass(frozen=True)
class NativeEnrollmentStatus:
    code: str
    state: str
    platform_admin_available: bool
    enrollment_required: bool
    existing_users_present: bool
    bootstrap_enabled: bool
    live_readiness_verified: bool = False


def _refuse(code, guidance):
    raise OperatorError(code, guidance) from None


def _libpq_overrides(*sources):
    for source in sources:
        for key, value in source.items():
            if key.upper().startswith("PG") and value:
                _refuse(
                    "OPERATOR_LIBPQ_REVIEW_REQUIRED",
                    "Review unsupported libpq routing/TLS overrides explicitly; no transport settings were discarded.",
                )


def _development_scope(environment, launcher):
    try:
        dev_prepared._development_only(environment, launcher)
    except Exception:
        _refuse(
            "OPERATOR_DEVELOPMENT_SCOPE_REQUIRED",
            "Use a consistent explicit development/test environment; staging and production are excluded.",
        )


def _server_names(root):
    try:
        source = dev_environment.bounded_read_text(Path(root) / "app/settings.py", 1048576)
        tree = ast.parse(source)
        settings = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Settings")
        names = {
            node.target.id.upper()
            for node in settings.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        if not {"DATABASE_URL", "AUTH_ENABLED", "NATIVE_AUTH_ENABLED"} <= names:
            raise ValueError()
        return names | {"APP_ENV", "PYTHONPATH", "PYTHON_DOTENV_DISABLED", "PYTHONDONTWRITEBYTECODE"}
    except Exception:
        _refuse(
            "OPERATOR_SETTINGS_SOURCE_UNVERIFIED",
            "Review the current inert settings source before operator configuration is projected.",
        )


def _native_configuration(environment, launcher):
    if (
        environment.get("AUTH_ENABLED", "").lower() not in _TRUE
        or environment.get("NATIVE_AUTH_ENABLED", "").lower() not in _TRUE
        or environment.get("DEV_DEFAULT_TENANT", "").lower() not in _FALSE
        or environment.get("HCL_AUTH_ENABLED", "false").lower() not in _FALSE
        or environment.get("ENTRA_ENABLED", "false").lower() not in _FALSE
        or environment.get("NEXT_PUBLIC_AUTH_ENABLED") != "true"
        or environment.get("NEXT_PUBLIC_HCL_AUTH_ENABLED") != "false"
    ):
        _refuse(
            "OPERATOR_NATIVE_MODE_REQUIRED",
            "Use the explicit authenticated Native profile with bypass disabled; no mode was converted.",
        )
    try:
        launcher.validate_secrets(dict(environment))
        if base64.b64decode(environment["NATIVE_SECURITY_OUTBOX_KEY"], validate=True) == base64.b64decode(
            environment["AUTH_SESSION_ENCRYPTION_KEY"], validate=True
        ):
            raise ValueError()
    except ImportError:
        _refuse(
            "OPERATOR_NATIVE_DEPENDENCIES_REQUIRED",
            "Run this read-only command with the existing project .venv interpreter and its cryptography dependency; no keys were changed.",
        )
    except Exception:
        _refuse(
            "OPERATOR_NATIVE_KEYS_REQUIRED",
            "Restore valid original Native signing and independent session/outbox keys; nothing was generated.",
        )
    required = ("NATIVE_JWT_ISSUER", "NATIVE_ACTIVATION_FRONTEND_URL", "SMTP_HOST")
    if (
        any(not environment.get(name) for name in required)
        or not environment.get("NATIVE_JWT_AUDIENCE", "sbom-analyser-api").strip()
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", environment.get("NATIVE_JWT_ACTIVE_KID", "native-v1"))
        or environment.get("NATIVE_JWT_ALGORITHM", "RS256") != "RS256"
        or environment.get("NATIVE_JWT_ISSUER") == environment.get("HCL_IAM_ISSUER")
        or any(
            environment.get(name, "DATABASE").upper() != "DATABASE"
            for name in ("AUTHORIZATION_CATALOG_MODE", "TENANT_ROLE_ASSIGNMENT_MODE")
        )
        or any(
            environment.get(name, "true").lower() not in _TRUE
            for name in ("AUTHORIZATION_CATALOG_FAIL_CLOSED", "TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED")
        )
        or environment.get("EMAIL_PROVIDER", "smtp") != "smtp"
        or environment.get("AUTH_SESSION_STORE") != "redis"
        or any(
            environment.get(name, "false").lower() not in _TRUE
            for name in ("NATIVE_USER_CREATION_ENABLED", "NATIVE_SECURITY_OUTBOX_ENABLED", "EMAIL_DELIVERY_ENABLED")
        )
        or environment.get("NATIVE_AUTH_RATE_LIMIT_ENABLED", "true").lower() not in _TRUE
    ):
        _refuse(
            "OPERATOR_NATIVE_CONFIGURATION_REQUIRED",
            "Review Native JWT, activation, Redis sessions/rate limits and encrypted mail configuration; live readiness was not established.",
        )
    for name in ("AUTH_SESSION_REDIS_URL", "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"):
        try:
            raw = environment[name]
            parsed = urlsplit(raw)
            if (
                parsed.scheme not in {"redis", "rediss"}
                or not parsed.hostname
                or "?" in raw
                or "#" in raw
                or raw != raw.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in raw)
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)
            ):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            _refuse(
                "OPERATOR_REDIS_CONFIGURATION_REQUIRED",
                "Review the selected session/rate-limit transport without weakening Redis TLS.",
            )
    try:
        if not 1 <= int(environment.get("SMTP_PORT", "587")) <= 65535:
            raise ValueError()
        if any(
            environment.get(name, default).lower() not in _TRUE | _FALSE
            for name, default in (("SMTP_USE_TLS", "false"), ("SMTP_USE_STARTTLS", "true"))
        ):
            raise ValueError()
        tls = environment.get("SMTP_USE_TLS", "false").lower() in _TRUE
        starttls = environment.get("SMTP_USE_STARTTLS", "true").lower() in _TRUE
        if (tls and starttls) or (
            (environment.get("SMTP_USERNAME") or environment.get("SMTP_PASSWORD")) and not (tls or starttls)
        ):
            raise ValueError()
        dev_diagnostics._https_url(environment["NATIVE_ACTIVATION_FRONTEND_URL"])
        dev_diagnostics._https_url(environment["NATIVE_JWT_ISSUER"])
    except (KeyError, TypeError, ValueError):
        _refuse(
            "OPERATOR_MAIL_CONFIGURATION_REQUIRED",
            "Review approved SMTP/TLS and HTTPS activation configuration; no email or token was created.",
        )


def _managed_plan(launcher):
    """Model the same existing provider selection and fixed startup policy."""
    saved, frontend = dev_environment.load_legacy_snapshots("managed", launcher)
    common = {
        "profile": "legacy",
        "family": "managed",
        "inherited": dict(os.environ),
        "saved": saved,
        "frontend": frontend,
        "root": str(launcher.ROOT),
        "platform": "linux" if launcher.sys.platform.startswith("linux") else launcher.sys.platform,
    }
    inspection = dev_config.resolve_configuration(**common)
    _development_scope(inspection.environment, launcher)
    _libpq_overrides(inspection.environment)
    try:
        dev_prepared.validate_managed_mode(inspection.environment, launcher)
    except Exception:
        _refuse(
            "OPERATOR_NATIVE_MODE_REQUIRED",
            "The selected Native operator profile conflicts with authentication flags; no mode was converted.",
        )
    if any(
        not saved.get(name)
        for name in (
            "NATIVE_JWT_PRIVATE_KEY",
            "NATIVE_JWT_PUBLIC_KEY",
            "NATIVE_SECURITY_OUTBOX_KEY",
            "AUTH_SESSION_ENCRYPTION_KEY",
        )
    ):
        _refuse(
            "OPERATOR_NATIVE_KEYS_REQUIRED",
            "Restore the original persistent Managed keys; operator resolution never discovers or generates them.",
        )
    ports = dev_prepared._managed_ports(saved, inspection, launcher)
    return dev_config.resolve_configuration(**common, purpose="startup", ports=ports)


def resolve_native_context(args, launcher):
    """Resolve the selected profile without reading unselected dotenv sources.

    Status never imports Settings/application code and connects with pinned
    explicit database keywords, so unrelated Settings fallbacks do not apply.
    """
    if getattr(args, "profile", None) not in {"auto", "legacy", "greenfield"}:
        _refuse("OPERATOR_PROFILE_REQUIRED", "Select an explicit development profile for this opt-in operator adapter.")
    confirmation = getattr(args, "confirm_database", None)
    if not isinstance(confirmation, str) or not confirmation:
        _refuse(
            "OPERATOR_DATABASE_CONFIRMATION_REQUIRED",
            "Repeat the exact selected database name before any database inspection.",
        )
    try:
        _development_scope(os.environ, launcher)
        _libpq_overrides(os.environ)
        state = dev_diagnostics._runtime_state(launcher)
        profile, family = dev_environment.select_profile(args, launcher, state)
        expected = (
            launcher.GreenfieldStack.DB
            if profile == "greenfield"
            else launcher.DB_NAME
            if family == "managed"
            else None
        )
        if expected is not None and confirmation != expected:
            _refuse(
                "OPERATOR_DATABASE_CONFIRMATION_REQUIRED",
                "Database confirmation differs from the selected profile; nothing was connected or changed.",
            )
        if profile == "greenfield":
            try:
                launcher.LocalHttps.ensure_certificate(launcher.GreenfieldStack.STATE, prepare=False)
            except Exception:
                _refuse(
                    "OPERATOR_TRUST_REQUIRED",
                    "Verify the existing Greenfield certificate and native trust before application credentials are read.",
                )
        plan = (
            _managed_plan(launcher)
            if profile == "legacy" and family == "managed"
            else dev_environment.resolve_existing(args, launcher, state)
        )
        if confirmation != plan.database.name:
            _refuse(
                "OPERATOR_DATABASE_CONFIRMATION_REQUIRED",
                "Database confirmation differs from the selected profile; nothing was connected or changed.",
            )
        _development_scope(plan.environment, launcher)
        _libpq_overrides(plan.environment)
        _native_configuration(plan.environment, launcher)
        credentials = urlsplit(plan.environment["DATABASE_URL"])
        if credentials.path != unquote(credentials.path):
            _refuse(
                "OPERATOR_DATABASE_TARGET_UNVERIFIED",
                "Review encoded database-name ambiguity explicitly before using the operator adapter.",
            )
        if not credentials.username or not credentials.password:
            _refuse(
                "OPERATOR_DATABASE_CREDENTIALS_REQUIRED",
                "The selected development URL must carry its original explicit database credentials; no password source was discovered.",
            )
        root = Path(launcher.ROOT)
        cwd = Path(launcher.GreenfieldStack.STATE) if profile == "greenfield" else root
        names = _server_names(root)
        if any(key.upper() in names and key != key.upper() for key in plan.environment):
            _refuse(
                "OPERATOR_SETTINGS_NAME_AMBIGUOUS",
                "Review case-variant Settings names explicitly; no name or value was converted.",
            )
        allowed = (
            names
            | _TRANSPORT
            | set(plan.components["public"])
            | {
                "DEV_API_PORT",
                "DEV_FRONTEND_PORT",
                "DEV_POSTGRES_PROVIDER",
                "DEV_REDIS_PROVIDER",
                "DEV_MAILPIT_PROVIDER",
                "AUTH_SESSION_STORE",
                "AUTH_SESSION_REDIS_URL",
                "AUTH_SESSION_ENCRYPTION_KEY",
                "APP_ORIGIN",
            }
        )
        environment = {key: value for key, value in plan.environment.items() if key in allowed}
        return NativeOperatorContext(
            profile,
            family if profile == "legacy" else "greenfield",
            plan.database,
            confirmation,
            OperatorEnvironment(environment),
            root,
            cwd,
        )
    except OperatorError:
        raise
    except Exception:
        _refuse(
            "OPERATOR_CONFIGURATION_UNVERIFIED",
            "Review the selected profile, scope, private-file access and Native prerequisites; configuration details were withheld.",
        )


def native_child_environment(context):
    """Return a disabled-bootstrap baseline, never execute or authorize a child.

    A future privileged child additionally needs an explicit Settings(_env_file=None)
    adapter and source revalidation. PYTHON_DOTENV_DISABLED alone does not disable
    Pydantic's independent dotenv source; this snapshot is not execution permission.
    """
    environment = dict(context.environment)
    _libpq_overrides(environment)
    fallback = context.working_directory / ".env"
    try:
        if fallback.exists() or fallback.is_symlink():
            if context.profile != "legacy" or context.family != "env":
                _refuse(
                    "OPERATOR_DOTENV_REVIEW_REQUIRED",
                    "An unselected Settings dotenv source exists in the operator working directory; review configuration without deleting or rewriting it.",
                )
            values = dev_config.parse_dotenv(dev_environment.bounded_read_text(fallback))
            if any(key not in environment or environment[key] != value for key, value in values.items()):
                _refuse(
                    "OPERATOR_DOTENV_REVIEW_REQUIRED",
                    "The selected dotenv source cannot be fully projected unchanged; no implicit settings fallback is allowed.",
                )
    except OperatorError:
        raise
    except Exception:
        _refuse(
            "OPERATOR_DOTENV_REVIEW_REQUIRED",
            "The current Settings dotenv source could not be verified; preserve it for explicit review.",
        )
    environment.update(
        PYTHON_DOTENV_DISABLED="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONPATH=str(context.root),
        NATIVE_PLATFORM_BOOTSTRAP_ENABLED="false",
    )
    return OperatorEnvironment(environment)


def _inspect_native_enrollment(context):
    connection, outcome, failure = None, None, None
    operation = "migration source discovery"
    try:
        head = discover(context.root).head
        operation = "PostgreSQL driver import"
        import psycopg

        operation = "PostgreSQL connection"
        credentials = urlsplit(context.environment["DATABASE_URL"])
        connection = psycopg.connect(
            host=context.database.host,
            port=context.database.port,
            dbname=context.database.name,
            hostaddr="127.0.0.1" if context.database.host == "localhost" else context.database.host,
            user=unquote(credentials.username or ""),
            password=unquote(credentials.password or ""),
            connect_timeout=3,
            autocommit=False,
            application_name="sbom-dev-native-status",
            options="-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog,public",
        )
        operation = "read-only transaction verification"
        if connection.execute("SHOW transaction_read_only").fetchone()[0] != "on":
            _refuse(
                "OPERATOR_DATABASE_NOT_READONLY",
                "The server did not confirm a read-only transaction; enrollment state was not queried.",
            )
        operation = "database identity verification"
        if connection.execute("SELECT pg_catalog.current_database()").fetchone()[0] != context.confirmed_database:
            _refuse(
                "OPERATOR_DATABASE_TARGET_MISMATCH",
                "The connected database differs from confirmation; enrollment state was not queried.",
            )
        operation = "schema marker inspection"
        revisions = connection.execute(
            "SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 2"
        ).fetchall()
        if revisions != [(head,)]:
            _refuse(
                "OPERATOR_SCHEMA_REQUIRED",
                "Review the current schema through explicitly authorized setup; no migration was run.",
            )
        operation = "user count inspection"
        users = connection.execute("SELECT count(*) FROM public.iam_users").fetchone()[0]
        operation = "administrator eligibility inspection"
        admins = connection.execute(
            "SELECT count(*) FROM public.platform_user_roles AS grant_row JOIN public.iam_users AS person "
            "ON person.id=grant_row.user_id WHERE grant_row.role='PLATFORM_ADMIN' AND grant_row.status='ACTIVE' "
            "AND person.status='ACTIVE' AND person.verification_required=false AND (person.email_verified=true OR "
            "EXISTS (SELECT 1 FROM public.user_identities AS identity_row WHERE identity_row.user_id=person.id "
            "AND identity_row.provider_type='MICROSOFT_ENTRA'))"
        ).fetchone()[0]
        operation = "bootstrap reservation inspection"
        reservation = connection.execute("SELECT state FROM public.native_platform_bootstrap WHERE id=1").fetchone()
        state = (
            reservation[0]
            if reservation and reservation[0] in {"PENDING", "COMPLETED"}
            else "UNKNOWN"
            if reservation
            else "NOT_STARTED"
        )
        code = (
            "ADMIN_READY"
            if admins
            else "PENDING_ACTIVATION"
            if state == "PENDING"
            else "BOOTSTRAP_RESERVED"
            if reservation
            else "ENROLLMENT_REQUIRED"
        )
        outcome = NativeEnrollmentStatus(
            code,
            state,
            bool(admins),
            code == "ENROLLMENT_REQUIRED",
            bool(users),
            context.environment.get("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "false").lower() in _TRUE,
        )
    except OperatorError as error:
        failure = error
    except Exception:
        code = {
            "migration source discovery": "OPERATOR_MIGRATION_SOURCE_INVALID",
            "PostgreSQL driver import": "OPERATOR_DATABASE_DRIVER_REQUIRED",
        }.get(operation, "OPERATOR_DATABASE_INSPECTION_FAILED")
        failure = OperatorError(
            code,
            f"Read-only status failed during {operation}; verify project dependencies/source or the selected database as applicable. Private exception details were withheld.",
        )
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                failure = OperatorError(
                    "OPERATOR_DATABASE_CLEANUP_UNCONFIRMED",
                    "The read-only transaction could not confirm rollback; do not infer permission to retry a mutation.",
                )
            try:
                connection.close()
            except Exception:
                failure = OperatorError(
                    "OPERATOR_DATABASE_CLEANUP_UNCONFIRMED",
                    "The read-only connection could not confirm closure; no commit was requested.",
                )
    if failure is not None:
        raise failure from None
    return outcome


def inspect_native_enrollment(context, *, confirm_database):
    """Observe aggregates only; expected enrollment-needed state is not permission."""
    if confirm_database != context.confirmed_database or confirm_database != context.database.name:
        _refuse(
            "OPERATOR_DATABASE_CONFIRMATION_REQUIRED",
            "Repeat the exact selected database name before any driver import or connection.",
        )
    _libpq_overrides(os.environ, context.environment)
    try:
        target = dev_config._database(context.environment["DATABASE_URL"], context.profile, context.family)
    except Exception:
        _refuse(
            "OPERATOR_DATABASE_TARGET_UNVERIFIED",
            "Review the explicit local target policy before any database driver import.",
        )
    if target != context.database:
        _refuse(
            "OPERATOR_DATABASE_TARGET_UNVERIFIED",
            "The immutable target and connection snapshot disagree; no database was contacted.",
        )
    try:
        return dev_diagnostics._bounded(lambda: _inspect_native_enrollment(context), timeout=8)
    except dev_diagnostics.DiagnosticError:
        _refuse(
            "OPERATOR_STATUS_TIMEOUT",
            "Read-only status exceeded its reporting deadline; the read-only probe may finish until CLI exit.",
        )
