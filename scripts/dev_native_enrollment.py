"""Private, approval-gated Native enrollment adapter; no public CLI or setup.

The default readiness adapter deliberately blocks until the running components
can attest their selected configuration and Native enablement. Injected checkers
are an internal integration/testing boundary, never a public bypass switch.
Only the isolated child imports application Settings/services. No live operation
is authorized by importing this module or constructing a plan.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import importlib
import io
import json
import logging
import os
import secrets
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

if __package__:
    from . import dev_config, dev_diagnostics, dev_environment, dev_operator
    from .greenfield_migration_graph import discover
else:
    import dev_config
    import dev_diagnostics
    import dev_environment
    import dev_operator
    from greenfield_migration_graph import discover

_MARKER = "_SBOM_NATIVE_ENROLLMENT_AUTHORIZATION"
_import_module = importlib.import_module
_CHILD_ARGUMENT = "--internal-native-enrollment-child"
_ACTIONS = {"create", "resend-activation"}
_CONTROLS = {"PYTHONPATH", "PYTHON_DOTENV_DISABLED", "PYTHONDONTWRITEBYTECODE", "NATIVE_PLATFORM_BOOTSTRAP_ENABLED"}
_SOURCES = (
    "scripts/dev_native_enrollment.py",
    "scripts/dev_operator.py",
    "scripts/dev_config.py",
    "scripts/dev_environment.py",
    "scripts/dev_prepared.py",
    "app/settings.py",
    "app/db.py",
    "app/services/native_platform_bootstrap.py",
    "app/services/account_action_token_service.py",
    "app/services/security_mail_outbox.py",
    "app/services/native_auth_service.py",
    "app/services/platform_service.py",
    "app/services/identity_verification_policy.py",
    "app/models.py",
    "app/models_mixins.py",
    "app/public_identity.py",
    "app/services/audit_service.py",
    "app/services/identity_service.py",
    "app/core/native_identity.py",
)
_REQUIRED = frozenset(
    {
        ("Native Login", "NATIVE_KEYS_CONFIGURATION_VALID"),
        ("Certificates", "CERTIFICATE_TRUST_VALID"),
        ("Redis", "REDIS_PING_VALID"),
        ("Sessions", "REDIS_PING_VALID"),
        ("Rate limits", "REDIS_PING_VALID"),
        ("SMTP", "SMTP_PROTOCOL_READY"),
        ("API/IAM", "API_HEALTH_VERIFIED"),
        ("Frontend HTTPS", "FRONTEND_TLS_VERIFIED"),
        *(
            (name, code)
            for name in ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")
            for code in ("PROCESS_IDENTITY_VERIFIED",)
        ),
        *((name, "HEARTBEAT_VERIFIED") for name in ("Celery worker", "Celery reports worker", "Celery Beat")),
        # These additional facts are not established by today's diagnose contract.
        ("Native enrollment", "RUNTIME_CONFIGURATION_VERIFIED"),
        ("Native enrollment", "NATIVE_IAM_ENABLED_VERIFIED"),
        ("Native enrollment", "ACTIVATION_ORIGIN_VERIFIED"),
        ("Native enrollment", "APPROVED_MAIL_TARGET_VERIFIED"),
    }
)


class EnrollmentError(ValueError):
    """Fixed allowlisted reason only; external exception details are suppressed."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _refuse(code):
    raise EnrollmentError(code) from None


@dataclass(frozen=True, repr=False)
class EnrollmentIdentity:
    email: str
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    operator_reference: str = ""

    def __repr__(self):
        return "<EnrollmentIdentity: redacted>"


@dataclass(frozen=True)
class EnrollmentPlan:
    action: str
    profile: str
    family: str
    database: dev_config.DatabaseTarget
    existing_users_present: bool
    context: dev_operator.NativeOperatorContext = field(repr=False)
    fingerprint: str = field(repr=False)
    head: str = field(repr=False)


@dataclass(frozen=True)
class EnrollmentOutcome:
    code: str
    exit_code: int
    committed: bool | None = False
    cleanup_confirmed: bool = True
    helper_pid: int | None = None


def _identity(value, action):
    if not isinstance(value, EnrollmentIdentity):
        _refuse("ENROLLMENT_IDENTITY_REQUIRED")
    required = ("email", "first_name", "last_name", "phone", "operator_reference") if action == "create" else ("email",)
    limits = {"email": 320, "first_name": 100, "last_name": 100, "phone": 50, "operator_reference": 128}
    for name, maximum in limits.items():
        item = getattr(value, name)
        if (
            not isinstance(item, str)
            or len(item) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in item)
            or (name in required and not item.strip())
        ):
            _refuse("ENROLLMENT_IDENTITY_INVALID")
    if value.email.count("@") != 1 or any(char.isspace() for char in value.email):
        _refuse("ENROLLMENT_IDENTITY_INVALID")
    if action == "resend-activation" and any(getattr(value, name) for name in limits if name != "email"):
        _refuse("ENROLLMENT_RESEND_IDENTITY_INVALID")
    return value


def _child_environment(context):
    """Only reviewed application settings and OS/CA transport enter the child."""
    dev_operator._libpq_overrides(os.environ, context.environment)
    allowed = dev_operator._server_names(context.root) | dev_operator._TRANSPORT
    environment = {key: value for key, value in context.environment.items() if key in allowed}
    environment.update(
        PYTHON_DOTENV_DISABLED="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONPATH=str(context.root),
        NATIVE_PLATFORM_BOOTSTRAP_ENABLED="false",
    )
    return dev_operator.OperatorEnvironment(environment)


def _fingerprint(context, head, launcher):
    digest = hashlib.sha256()
    stable = {key: value for key, value in _child_environment(context).items() if key not in _CONTROLS}
    digest.update(
        json.dumps([context.profile, context.family, str(context.root), head, stable], sort_keys=True).encode()
    )
    paths = [context.root / name for name in _SOURCES]
    if context.profile == "greenfield":
        # Reuse the protected reader for every private Greenfield credential read.
        for name in ("environment.json", "runtime-password"):
            digest.update(name.encode())
            digest.update(launcher.GreenfieldStack.read_private(name).encode())
    else:
        paths += [
            context.root
            / {"managed": ".env.dev.local", "windows": ".windows/sbom.env.ps1", "env": ".env"}[context.family]
        ]
    for path in paths:
        digest.update(str(path).encode())
        digest.update(dev_environment.bounded_read_bytes(path, 2097152))
    return digest.hexdigest()


def default_readiness_checker(context, args, launcher):
    """Reuse readonly diagnosis, but never mistake incomplete evidence for approval."""
    report = dev_diagnostics.run_checks(args, launcher)
    missing_contract = dev_diagnostics.DiagnosticResult(
        "Native enrollment",
        "BLOCKED",
        "ENROLLMENT_READINESS_CONTRACT_REQUIRED",
        "Running configuration, Native enablement, activation origin and approved mail target need a reviewed attestation contract.",
    )
    return dev_diagnostics.DiagnosticReport((*report.results, missing_contract))


def _readiness(report, action):
    if not isinstance(report, dev_diagnostics.DiagnosticReport):
        _refuse("ENROLLMENT_READINESS_UNVERIFIED")
    if any(
        item.code == "ENROLLMENT_READINESS_CONTRACT_REQUIRED" and item.status == "BLOCKED" for item in report.results
    ):
        _refuse("ENROLLMENT_READINESS_CONTRACT_REQUIRED")
    expected = "ENROLLMENT_REQUIRED" if action == "create" else "PENDING_ACTIVATION"
    observed = set()
    for item in report.results:
        if item.component == "Enrollment" and item.code == expected and item.status == "BLOCKED":
            continue
        if item.status != "PASS":
            _refuse("ENROLLMENT_READINESS_UNVERIFIED")
        observed.add((item.component, item.code))
    if not _REQUIRED <= observed:
        _refuse("ENROLLMENT_READINESS_CONTRACT_REQUIRED")


def inspect_enrollment(args, launcher, *, action, readiness_checker=None):
    """Inspect an existing target and readonly readiness; never prompt or mutate."""
    if action not in _ACTIONS:
        _refuse("ENROLLMENT_ACTION_INVALID")
    context = dev_operator.resolve_native_context(args, launcher)
    status = dev_operator.inspect_native_enrollment(context, confirm_database=args.confirm_database)
    expected = "ENROLLMENT_REQUIRED" if action == "create" else "PENDING_ACTIVATION"
    if status.code != expected:
        _refuse("ENROLLMENT_STATE_REFUSED")
    checker = readiness_checker or default_readiness_checker
    _readiness(checker(context, args, launcher), action)
    head = discover(context.root).head
    return EnrollmentPlan(
        action,
        context.profile,
        context.family,
        context.database,
        status.existing_users_present,
        context,
        _fingerprint(context, head, launcher),
        head,
    )


def run_enrollment(args, launcher, *, action, identity=None, readiness_checker=None, child_runner=None, input_fn=None):
    """Authorize a current plan on a TTY, revalidate, then launch one owned child."""
    try:
        plan = inspect_enrollment(args, launcher, action=action, readiness_checker=readiness_checker)
        print(
            f"Native enrollment plan: {plan.action}; {plan.profile}/{plan.family}; "
            f"{plan.database.host}:{plan.database.port}/{plan.database.name}"
        )
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return EnrollmentOutcome("ENROLLMENT_APPROVAL_REQUIRED", 1)
        prompt = input_fn or input
        if identity is None:
            private_prompt = input_fn or getpass.getpass
            fields = (
                ("email", "first_name", "last_name", "phone", "operator_reference")
                if action == "create"
                else ("email",)
            )
            identity = EnrollmentIdentity(
                **{name: private_prompt(f"Approved {name.replace('_', ' ')}: ") for name in fields}
            )
        identity = _identity(identity, action)
        if action == "create" and plan.existing_users_present:
            if (
                prompt("Existing users require independent review. Type REVIEWED EXISTING USERS: ")
                != "REVIEWED EXISTING USERS"
            ):
                return EnrollmentOutcome("ENROLLMENT_APPROVAL_DECLINED", 1)
        literal = "CREATE NATIVE PLATFORM ADMIN" if action == "create" else "RESEND NATIVE ACTIVATION"
        if prompt(f"Approve the entered identity and this exact target/action. Type {literal}: ") != literal:
            return EnrollmentOutcome("ENROLLMENT_APPROVAL_DECLINED", 1)
        current = inspect_enrollment(args, launcher, action=action, readiness_checker=readiness_checker)
        if (
            not hmac.compare_digest(current.fingerprint, plan.fingerprint)
            or current.existing_users_present is not plan.existing_users_present
        ):
            _refuse("ENROLLMENT_PLAN_CHANGED")
        return (child_runner or _launch_child)(current, identity, launcher)
    except (EOFError, KeyboardInterrupt):
        return EnrollmentOutcome("ENROLLMENT_CANCELLED", 130)
    except EnrollmentError as error:
        # Only a stable category is returned; driver/provider/identity values are never output.
        return EnrollmentOutcome(error.code, 1)
    except dev_operator.OperatorError:
        return EnrollmentOutcome("ENROLLMENT_CONFIGURATION_BLOCKED", 1)
    except Exception:
        return EnrollmentOutcome("ENROLLMENT_INSPECTION_FAILED", 1)


def _payload(plan, identity, authorization):
    return {
        "version": 1,
        "action": plan.action,
        "profile": plan.profile,
        "family": plan.family,
        "confirm_database": plan.database.name,
        "fingerprint": plan.fingerprint,
        "head": plan.head,
        "identity": asdict(identity),
        "authorization": authorization,
        "existing_users_present": plan.existing_users_present,
    }


def _stop_owned(child):
    """Only the original helper handle; never a PID lookup, tree or service signal."""
    try:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        return child.poll() is not None
    except BaseException:
        return False


def _launch_child(plan, identity, launcher):
    authorization = secrets.token_urlsafe(32)
    environment = dict(_child_environment(plan.context))
    environment[_MARKER] = authorization
    command = [str(launcher.venv_python()), "-B", str(Path(__file__).resolve()), _CHILD_ARGUMENT]
    payload = json.dumps(_payload(plan, identity, authorization))
    child = None
    try:
        child = subprocess.Popen(
            command,
            env=environment,
            cwd=plan.context.root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        stdout, _ = child.communicate(payload, timeout=40)
        if len(stdout) > 1024:
            raise ValueError()
        result = json.loads(stdout)
        allowed = {"ACTIVATION_QUEUED": (True, 0), "ENROLLMENT_REFUSED": (False, 1), "OUTCOME_UNCONFIRMED": (None, 1)}
        if (
            not isinstance(result, dict)
            or set(result) != {"version", "code", "committed"}
            or type(result["version"]) is not int
            or result["version"] != 1
            or result["code"] not in allowed
        ):
            raise ValueError()
        committed, exit_code = allowed[result["code"]]
        if result["committed"] is not committed or child.returncode != exit_code:
            raise ValueError()
        return EnrollmentOutcome(result["code"], exit_code, committed)
    except (KeyboardInterrupt, subprocess.TimeoutExpired, OSError, ValueError, TypeError):
        if child is None:
            return EnrollmentOutcome("ENROLLMENT_HELPER_NOT_STARTED", 1)
        cleaned = _stop_owned(child)
        pid = child.pid if not cleaned and type(child.pid) is int else None
        return EnrollmentOutcome("OUTCOME_UNCONFIRMED", 1, None, cleaned, pid)


def _decode_request(raw, authorization):
    try:
        if len(raw) > 16384 or not authorization:
            raise ValueError()
        request = json.loads(raw)
        required = {
            "version",
            "action",
            "profile",
            "family",
            "confirm_database",
            "fingerprint",
            "head",
            "identity",
            "authorization",
            "existing_users_present",
        }
        if (
            not isinstance(request, dict)
            or set(request) != required
            or type(request["version"]) is not int
            or request["version"] != 1
            or type(request["existing_users_present"]) is not bool
            or not isinstance(request["authorization"], str)
            or not hmac.compare_digest(request["authorization"], authorization)
            or request["action"] not in _ACTIONS
            or not isinstance(request["fingerprint"], str)
            or len(request["fingerprint"]) != 64
            or not isinstance(request["head"], str)
            or not isinstance(request["identity"], dict)
        ):
            raise ValueError()
        identity = _identity(EnrollmentIdentity(**request["identity"]), request["action"])
        return request, identity
    except Exception:
        _refuse("ENROLLMENT_PROTOCOL_REFUSED")


def _execute_child(request, identity, launcher):
    """Application imports only after current source/target/authorization proof."""
    args = SimpleNamespace(
        profile=request["profile"], legacy_config=request["family"], confirm_database=request["confirm_database"]
    )
    context = dev_operator.resolve_native_context(args, launcher)
    head = discover(context.root).head
    if request["head"] != head or not hmac.compare_digest(
        request["fingerprint"], _fingerprint(context, head, launcher)
    ):
        _refuse("ENROLLMENT_PLAN_CHANGED")
    if any(name == "app.db" or name == "app.models" or name.startswith("app.services") for name in sys.modules):
        _refuse("ENROLLMENT_CHILD_NOT_FRESH")
    dev_operator._libpq_overrides(os.environ, context.environment)
    connection, session, engine, settings_module = None, None, None, None
    commit_started, committed, cleanup_confirmed, installed_settings = False, False, True, False
    previous_flag = os.environ.get("NATIVE_PLATFORM_BOOTSTRAP_ENABLED")
    previous_dotenv = os.environ.get("PYTHON_DOTENV_DISABLED")
    try:
        os.environ["PYTHON_DOTENV_DISABLED"] = "1"
        os.environ["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] = "true"
        settings_module = _import_module("app.settings")
        if settings_module._settings_instance is not None:
            _refuse("ENROLLMENT_CHILD_NOT_FRESH")
        settings_module._settings_instance = settings_module.Settings(_env_file=None)
        installed_settings = True
        # app.db is necessarily imported by models; its global engine is never used.
        app_db = _import_module("app.db")
        sqlalchemy = _import_module("sqlalchemy")
        pool = _import_module("sqlalchemy.pool")
        psycopg = _import_module("psycopg")
        credentials = urlsplit(context.environment["DATABASE_URL"])
        keywords = dict(
            host=context.database.host,
            hostaddr="127.0.0.1" if context.database.host == "localhost" else context.database.host,
            port=context.database.port,
            dbname=context.database.name,
            user=unquote(credentials.username or ""),
            password=unquote(credentials.password or ""),
            connect_timeout=3,
            application_name="sbom-native-enrollment",
            autocommit=False,
            options="-c statement_timeout=15000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=20000 -c search_path=pg_catalog,public",
        )
        engine = sqlalchemy.create_engine(
            "postgresql+psycopg://",
            creator=lambda: psycopg.connect(**keywords),
            hide_parameters=True,
            echo=False,
            poolclass=pool.NullPool,
        )
        session = app_db.TenantSession(bind=engine, autoflush=False)
        connection = session.connection()
        if (
            connection.execute(sqlalchemy.text("SELECT pg_catalog.current_database()")).scalar_one()
            != args.confirm_database
        ):
            _refuse("ENROLLMENT_DATABASE_TARGET_MISMATCH")
        revisions = connection.execute(
            sqlalchemy.text("SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 2")
        ).fetchall()
        if revisions != [(head,)]:
            _refuse("ENROLLMENT_SCHEMA_REQUIRED")
        bootstrap = _import_module("app.services.native_platform_bootstrap")
        if request["action"] == "create":
            bootstrap._lock(session)
            observed_users = connection.execute(
                sqlalchemy.text("SELECT EXISTS (SELECT 1 FROM public.iam_users)")
            ).scalar_one()
            if type(observed_users) is not bool or observed_users is not request["existing_users_present"]:
                _refuse("ENROLLMENT_PLAN_CHANGED")
            bootstrap.create(session, **asdict(identity))
        else:
            models = _import_module("app.models")
            bootstrap._lock(session)
            row = session.get(models.NativePlatformBootstrap, 1, with_for_update=True)
            person = session.get(models.IAMUser, row.user_id, with_for_update=True) if row else None
            if (
                not person
                or row.state != "PENDING"
                or bootstrap.normalize_email(person.email) != bootstrap.normalize_email(identity.email)
            ):
                _refuse("ENROLLMENT_RESERVED_IDENTITY_MISMATCH")
            bootstrap.resend(session)
        session.flush()
        commit_started = True
        session.commit()
        committed = True
    except BaseException:
        if session is not None:
            try:
                session.rollback()
            except BaseException:
                cleanup_confirmed = False
    finally:
        if session is not None:
            try:
                session.close()
            except BaseException:
                cleanup_confirmed = False
        if engine is not None:
            try:
                engine.dispose()
            except BaseException:
                cleanup_confirmed = False
        if installed_settings:
            settings_module._settings_instance = None
        if previous_flag is None:
            os.environ.pop("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", None)
        else:
            os.environ["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] = previous_flag
        if previous_dotenv is None:
            os.environ.pop("PYTHON_DOTENV_DISABLED", None)
        else:
            os.environ["PYTHON_DOTENV_DISABLED"] = previous_dotenv
    if committed and cleanup_confirmed:
        return {"version": 1, "code": "ACTIVATION_QUEUED", "committed": True}
    if commit_started or not cleanup_confirmed:
        return {"version": 1, "code": "OUTCOME_UNCONFIRMED", "committed": None}
    return {"version": 1, "code": "ENROLLMENT_REFUSED", "committed": False}


class _Discard(io.TextIOBase):
    def write(self, value):
        return len(value)


def child_main():
    """Private pipe protocol only; suppress all imported-module output and traces."""
    sys.dont_write_bytecode = True
    authorization = os.environ.pop(_MARKER, None)
    result = {"version": 1, "code": "ENROLLMENT_REFUSED", "committed": False}
    previous_logging = logging.root.manager.disable
    execution_started = False
    logging.disable(logging.CRITICAL)
    try:
        with redirect_stdout(_Discard()), redirect_stderr(_Discard()):
            request, identity = _decode_request(sys.stdin.read(16385), authorization)
            if __package__:
                from . import dev as launcher
            else:
                import dev as launcher
            execution_started = True
            result = _execute_child(request, identity, launcher)
    except BaseException:
        if execution_started:
            result = {"version": 1, "code": "OUTCOME_UNCONFIRMED", "committed": None}
    finally:
        logging.disable(previous_logging)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["code"] == "ACTIVATION_QUEUED" else 1


if __name__ == "__main__":
    if sys.argv[1:] != [_CHILD_ARGUMENT]:
        raise SystemExit("Private Native operator helper; use the unified launcher after review.")
    raise SystemExit(child_main())
