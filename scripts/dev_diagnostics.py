"""Bounded, secret-safe development inspections; never prepares or repairs state.

Network checks use read-only protocol operations. Existing servers may log those
requests; this process does not write configuration, caches or runtime records.
Frontend readiness uses TLS only so Next.js is not asked to compile a page.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener

if __package__:
    from . import dev_components, dev_config, dev_environment, dev_frontend
    from .greenfield_migration_graph import discover
else:
    import dev_components
    import dev_config
    import dev_environment
    import dev_frontend
    from greenfield_migration_graph import discover


@dataclass(frozen=True)
class DiagnosticResult:
    component: str
    status: str
    code: str
    guidance: str


@dataclass(frozen=True)
class DiagnosticReport:
    results: tuple[DiagnosticResult, ...]

    @property
    def exit_code(self) -> int:
        return int(any(result.status in {"FAIL", "BLOCKED"} for result in self.results))


class DiagnosticError(ValueError):
    """Internal safe category; external exception text is never displayed."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _result(component, status, code, guidance):
    return DiagnosticResult(component, status, code, guidance)


def _true(value):
    return str(value).lower() in {"true", "1", "yes", "on"}


def _bounded(call, timeout=6):
    """Bound reporting even when DNS or peer headers ignore socket deadlines.

    A timed-out daemon can finish its read-only operation until CLI exit. It has
    no runtime/configuration mutation capability and is never signalled/killed.
    Callers must not pass mutable preparation or print external exceptions.
    """
    completed = Queue(maxsize=1)

    def inspect():
        try:
            completed.put((True, call()))
        except BaseException as error:
            completed.put((False, error))

    thread = threading.Thread(target=inspect, daemon=True, name="sbom-readonly-probe")
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise DiagnosticError("PROBE_TIMEOUT")
    succeeded, value = completed.get_nowait()
    if not succeeded:
        raise value
    return value


def _read_text(path, limit=131072):
    try:
        return dev_environment.bounded_read_text(path, limit)
    except dev_environment.EnvironmentReadError as error:
        raise DiagnosticError(error.code) from None


def _command_environment():
    names = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "HOME", "TEMP", "TMP"}
    return {key: value for key, value in os.environ.items() if key.upper() in names}


def _dependency_checks(launcher):
    results = []
    if launcher.sys.version_info < launcher.MIN_PYTHON:
        results.append(
            _result(
                "Python",
                "FAIL",
                "PYTHON_UNSUPPORTED",
                "Use Python 3.11 or newer; diagnose does not create or replace a virtualenv.",
            )
        )
    else:
        results.append(
            _result("Python", "PASS", "PYTHON_SUPPORTED", "The current interpreter meets the launcher minimum.")
        )
    results.append(
        _result(
            "Virtualenv",
            "PASS" if launcher.venv_python().is_file() else "FAIL",
            "VIRTUALENV_PRESENT" if launcher.venv_python().is_file() else "VIRTUALENV_MISSING",
            "Use an explicitly reviewed setup plan if the project virtualenv needs preparation.",
        )
    )
    try:
        launcher.validate_repository_layout()
        results.append(_result("Repository", "PASS", "CHECKOUT_COMPLETE", "Required project manifests are present."))
    except Exception:
        results.append(
            _result(
                "Repository", "FAIL", "CHECKOUT_INCOMPLETE", "Restore missing project manifests; no files were created."
            )
        )
    for package in ("dotenv", "cryptography", "psycopg", "redis"):
        try:
            present = importlib.util.find_spec(package) is not None
        except (ImportError, ValueError):
            present = False
        results.append(
            _result(
                "Dependencies",
                "PASS" if present else "FAIL",
                "PACKAGE_PRESENT" if present else "PACKAGE_MISSING",
                f"{package}: available."
                if present
                else f"{package}: prepare approved project dependencies through setup.",
            )
        )
    try:
        node = launcher.GreenfieldStack.node_binary()
        completed = subprocess.run(
            [str(node), "--version"], capture_output=True, text=True, timeout=3, env=_command_environment()
        )
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)\s*", completed.stdout)
        if completed.returncode or not match or tuple(map(int, match.groups())) < launcher.MIN_NODE:
            raise DiagnosticError("NODE_UNSUPPORTED")
        results.append(
            _result("Node", "PASS", "NODE_SUPPORTED", "The selected Node runtime meets the project minimum.")
        )
        npm = shutil.which("npm", path=str(Path(node).parent) + os.pathsep + os.environ.get("PATH", ""))
        if not npm:
            raise DiagnosticError("NPM_MISSING")
        # npm --version can create cache/log files. Inspect the selected CLI
        # package instead of executing npm during a read-only diagnostic.
        command = launcher.normalize_command([npm, "--version"])
        cli = Path(command[1]) if len(command) > 2 else Path(npm)
        if not cli.is_file():
            raise DiagnosticError("NPM_MISSING")
        results.append(
            _result("npm", "PASS", "NPM_PRESENT", "The selected npm entry point is present; npm was not executed.")
        )
    except Exception:
        results.append(
            _result(
                "Node/npm",
                "FAIL",
                "NODE_NPM_UNAVAILABLE",
                "Review the selected Node/npm installation; diagnose installs and executes no npm commands.",
            )
        )
    return tuple(results)


def _select_profile(args, launcher, state):
    try:
        return dev_environment.select_profile(args, launcher, state)
    except dev_environment.EnvironmentReadError as error:
        raise DiagnosticError(error.code) from None


def _runtime_state(launcher):
    """Mirror registry validation on a bounded, pinned regular-file snapshot."""
    try:
        state = json.loads(_read_text(launcher.ROOT / ".dev-runtime.json", limit=1048576))
    except FileNotFoundError:
        return None
    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or state.get("root") != str(launcher.ROOT.resolve())
        or not isinstance(state.get("services"), dict)
        or not set(state.get("services", {}))
        <= {"API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat"}
        or not isinstance(state.get("instance"), str)
        or any(
            not isinstance(record, dict) or type(record.get("pid")) is not int for record in state["services"].values()
        )
    ):
        raise DiagnosticError("RUNTIME_STATE_UNVERIFIED")
    return state


def _configuration(args, launcher, state):
    try:
        return dev_environment.resolve_existing(args, launcher, state)
    except dev_environment.EnvironmentReadError as error:
        raise DiagnosticError(error.code) from None


def _certificate_check(profile, launcher):
    try:
        if profile == "greenfield":
            _, _, root, _ = launcher.LocalHttps.ensure_certificate(launcher.GreenfieldStack.STATE, prepare=False)
            context = ssl.create_default_context(cafile=str(root))
        else:
            context = launcher.legacy_https_context()
            certificate = launcher.ROOT / "frontend/certificates/localhost.pem"
            if not launcher.LocalHttps.system_trusted(certificate, hostname="localhost"):
                return (
                    _result(
                        "Certificates",
                        "FAIL",
                        "OS_TRUST_REQUIRED",
                        "The preserved localhost pair validates, but OS trust is missing. Trust changes require separate approval.",
                    ),
                    context,
                )
        return (
            _result(
                "Certificates",
                "PASS",
                "CERTIFICATE_TRUST_VALID",
                "Existing certificate, key and OS trust validate; browser acceptance remains separate.",
            ),
            context,
        )
    except Exception:
        return (
            _result(
                "Certificates",
                "FAIL",
                "CERTIFICATE_VALIDATION_FAILED",
                "Review existing localhost certificate/key access, pairing, expiry, SAN and OS trust; nothing was generated or trusted.",
            ),
            None,
        )


def _database_checks(plan, launcher):
    results = []
    connection = None
    try:
        head = discover(launcher.ROOT).head
        import psycopg

        credentials = urlsplit(plan.environment["DATABASE_URL"])
        connection = psycopg.connect(
            host=plan.database.host,
            port=plan.database.port,
            dbname=plan.database.name,
            hostaddr="127.0.0.1" if plan.database.host == "localhost" else plan.database.host,
            user=unquote(credentials.username or ""),
            password=unquote(credentials.password or ""),
            connect_timeout=3,
            autocommit=False,
            options="-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=250 -c search_path=public,pg_catalog",
        )
        if connection.execute("SHOW transaction_read_only").fetchone()[0] != "on":
            raise DiagnosticError("DATABASE_NOT_READONLY")
        if connection.execute("SELECT current_database()").fetchone()[0] != plan.database.name:
            raise DiagnosticError("DATABASE_TARGET_MISMATCH")
        results.append(
            _result(
                "Database",
                "PASS",
                "DATABASE_TARGET_CONFIRMED",
                "Authenticated read-only connection returned the selected database; this grants no preparation permission.",
            )
        )
        revisions = connection.execute(
            "SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 2"
        ).fetchall()
        if revisions != [(head,)]:
            results.append(
                _result(
                    "Schema",
                    "FAIL",
                    "SCHEMA_NOT_CURRENT",
                    "Review explicit database setup/migration with exact database confirmation; diagnose made no schema changes.",
                )
            )
            results.append(
                _result(
                    "Enrollment",
                    "BLOCKED",
                    "ENROLLMENT_SCHEMA_BLOCKED",
                    "Enrollment inspection requires the current accepted schema.",
                )
            )
        else:
            results.append(
                _result(
                    "Schema",
                    "PASS",
                    "SCHEMA_CURRENT",
                    "The selected schema matches the inertly inspected migration head.",
                )
            )
            users = connection.execute("SELECT count(*) FROM public.iam_users").fetchone()[0]
            admins = connection.execute(
                "SELECT count(*) FROM public.platform_user_roles AS grant_row "
                "JOIN public.iam_users AS person ON person.id=grant_row.user_id "
                "WHERE grant_row.role='PLATFORM_ADMIN' AND grant_row.status='ACTIVE' "
                "AND person.status='ACTIVE' AND person.verification_required=false "
                "AND (person.email_verified=true OR EXISTS (SELECT 1 FROM public.user_identities AS identity_row "
                "WHERE identity_row.user_id=person.id AND identity_row.provider_type='MICROSOFT_ENTRA'))"
            ).fetchone()[0]
            reservation = connection.execute("SELECT state FROM public.native_platform_bootstrap WHERE id=1").fetchone()
            if admins:
                results.append(
                    _result(
                        "Enrollment",
                        "PASS",
                        "ADMIN_READY",
                        "An effective Platform Admin grant exists; no identity or grant was changed.",
                    )
                )
            elif reservation and reservation[0] == "PENDING":
                results.append(
                    _result(
                        "Enrollment",
                        "BLOCKED",
                        "PENDING_ACTIVATION",
                        "Use the approved operator recovery and email activation flow for the reserved Native identity.",
                    )
                )
            elif reservation:
                results.append(
                    _result(
                        "Enrollment",
                        "BLOCKED",
                        "BOOTSTRAP_RESERVED",
                        "A durable bootstrap reservation exists without an effective admin. Request independent recovery review; never delete it.",
                    )
                )
            elif "hclcs" in plan.auth_modes and "native" not in plan.auth_modes:
                results.append(
                    _result(
                        "Enrollment",
                        "BLOCKED",
                        "HCL_ENROLLMENT_APPROVAL_REQUIRED",
                        "The first eligible HCL.CS user procedure requires Engineering Lead and provider-owner approval.",
                    )
                )
            else:
                detail = "Existing non-administrator identities require operator review. " if users else ""
                results.append(
                    _result(
                        "Enrollment",
                        "BLOCKED",
                        "ENROLLMENT_REQUIRED",
                        detail
                        + "Authorize the existing Native pending-account/email activation flow separately; startup never creates an admin.",
                    )
                )
    except Exception as error:
        code = error.code if isinstance(error, DiagnosticError) else "DATABASE_INSPECTION_FAILED"
        if code not in {"DATABASE_TARGET_MISMATCH", "DATABASE_NOT_READONLY"}:
            code = "DATABASE_INSPECTION_FAILED"
        results.append(
            _result(
                "Database",
                "FAIL",
                code,
                "Verify the selected local target, credentials, dependencies and schema availability; connection details were withheld.",
            )
        )
        results.append(
            _result(
                "Enrollment",
                "BLOCKED",
                "ENROLLMENT_DATABASE_BLOCKED",
                "Read-only target/schema inspection must succeed before enrollment state can be assessed.",
            )
        )
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                results.append(
                    _result(
                        "Database",
                        "WARN",
                        "READONLY_ROLLBACK_UNCONFIRMED",
                        "The read-only connection could not confirm rollback; it is being closed.",
                    )
                )
            try:
                connection.close()
            except Exception:
                results.append(
                    _result(
                        "Database",
                        "FAIL",
                        "DATABASE_CLOSE_UNCONFIRMED",
                        "The read-only connection could not confirm closure; no commit was requested.",
                    )
                )
    return tuple(results)


def _redis_ping(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"redis", "rediss"}
        or not parsed.hostname
        or url != url.strip()
        or "?" in url
        or "#" in url
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
    ):
        raise DiagnosticError("REDIS_CONFIGURATION_INVALID")
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    tls_options = {"ssl_cert_reqs": "required", "ssl_check_hostname": True} if parsed.scheme == "rediss" else {}
    client = redis.Redis.from_url(
        url,
        socket_connect_timeout=2,
        socket_timeout=2,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
        **tls_options,
    )
    try:
        return client.ping() is True
    finally:
        client.close()


def _smtp_check(env):
    host, port = env.get("SMTP_HOST", ""), int(env.get("SMTP_PORT", "587"))
    if not host or not 1 <= port <= 65535:
        raise DiagnosticError("SMTP_CONFIGURATION_INVALID")
    if env.get("DEV_MAILPIT_UI_PORT") or env.get("DEV_MAILPIT_PROVIDER") == "local":
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise DiagnosticError("MAILPIT_EXPOSED")
        if sys.platform == "win32":
            if __package__:
                from .dev_local_services import LocalServiceError, mailpit_bindings
            else:
                from dev_local_services import LocalServiceError, mailpit_bindings
            try:
                mailpit_bindings({port, int(env.get("DEV_MAILPIT_UI_PORT", "8025"))})
            except LocalServiceError as error:
                raise DiagnosticError("MAILPIT_EXPOSED" if str(error).startswith("MAILPIT_EXPOSED:") else "MAILPIT_BINDING_UNVERIFIED") from None
    tls, starttls = _true(env.get("SMTP_USE_TLS", "false")), _true(env.get("SMTP_USE_STARTTLS", "true"))
    if tls and starttls:
        raise DiagnosticError("SMTP_TLS_CONFLICT")
    if (env.get("SMTP_USERNAME") or env.get("SMTP_PASSWORD")) and not (tls or starttls):
        raise DiagnosticError("SMTP_TLS_REQUIRED")
    if _true(env.get("NATIVE_IAM_PRODUCTION", "false")) and not (tls or starttls):
        raise DiagnosticError("SMTP_TLS_REQUIRED")
    context = ssl.create_default_context()
    client = smtplib.SMTP_SSL(host, port, timeout=3, context=context) if tls else smtplib.SMTP(host, port, timeout=3)
    try:
        code, _ = client.ehlo()
        if code != 250:
            raise DiagnosticError("SMTP_UNAVAILABLE")
        if starttls and not tls:
            client.starttls(context=context)
            code, _ = client.ehlo()
            if code != 250:
                raise DiagnosticError("SMTP_UNAVAILABLE")
    finally:
        client.close()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise DiagnosticError("HTTP_REDIRECT_REFUSED")


def _json_get(url, context=None):
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())
    with opener.open(url, timeout=3) as response:
        if response.status != 200:
            raise DiagnosticError("HTTP_STATUS_UNHEALTHY")
        data = bytearray()
        deadline = time.monotonic() + 3
        while True:
            chunk = response.read1(min(4096, 65537 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536 or time.monotonic() > deadline:
                raise DiagnosticError("HTTP_RESPONSE_LIMIT")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise DiagnosticError("HTTP_INVALID_JSON")
        return payload


def _https_url(url):
    parsed = urlsplit(url)
    if (
        url != url.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in url
        or "#" in url
    ):
        raise DiagnosticError("HCL_TLS_CONFIGURATION_INVALID")
    return parsed


def _hcl_check(env, root):
    required = (
        "HCL_IAM_ISSUER",
        "HCL_IAM_AUDIENCE",
        "HCL_IAM_CLIENT_ID",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID",
        "NEXT_PUBLIC_HCL_IAM_REDIRECT_URI",
        "APP_ORIGIN",
    )
    if any(not env.get(key, "").strip() for key in required):
        raise DiagnosticError("HCL_CONFIGURATION_INCOMPLETE")
    issuer = env["HCL_IAM_ISSUER"]
    discovery = env.get("HCL_IAM_DISCOVERY_URL") or issuer.rstrip("/") + "/.well-known/openid-configuration"
    for url in (issuer, discovery, env.get("HCL_IAM_JWKS_URL") or issuer):
        _https_url(url)
    origin = _https_url(env["APP_ORIGIN"])
    if origin.path not in {"", "/"}:
        raise DiagnosticError("HCL_REDIRECT_CONFIGURATION_INVALID")
    redirect = _https_url(env["NEXT_PUBLIC_HCL_IAM_REDIRECT_URI"])
    logout = _https_url(
        env.get("NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI")
        or env.get("NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI")
        or env["APP_ORIGIN"]
    )
    if redirect.netloc != origin.netloc or logout.netloc != origin.netloc:
        raise DiagnosticError("HCL_REDIRECT_CONFIGURATION_INVALID")
    if [
        value.strip().upper() for value in env.get("HCL_IAM_ALLOWED_ALGORITHMS", "RS256").split(",") if value.strip()
    ] != ["RS256"]:
        raise DiagnosticError("HCL_ALGORITHM_INVALID")
    if env.get("NEXT_PUBLIC_HCL_IAM_ISSUER", "").removesuffix("/") != issuer:
        raise DiagnosticError("HCL_FRONTEND_MISMATCH")
    if env["NEXT_PUBLIC_HCL_IAM_CLIENT_ID"] != env["HCL_IAM_CLIENT_ID"]:
        raise DiagnosticError("HCL_FRONTEND_MISMATCH")
    ca = env.get("HCL_IAM_CA_BUNDLE", "")
    path = Path(ca) if ca else None
    if path is not None and not path.is_absolute():
        backend_path = Path(root) / path
        frontend_path = Path(root) / "frontend" / path
        if backend_path.resolve() != frontend_path.resolve():
            raise DiagnosticError("HCL_CA_PATH_AMBIGUOUS")
        path = backend_path
    context = ssl.create_default_context(cafile=str(path) if path is not None else None)
    document = _json_get(discovery, context)
    jwks_url = env.get("HCL_IAM_JWKS_URL") or document.get("jwks_uri", "")
    _https_url(jwks_url)
    if document.get("issuer") != issuer:
        raise DiagnosticError("HCL_DISCOVERY_INVALID")
    advertised_pkce = document.get("code_challenge_methods_supported")
    if advertised_pkce is not None and (not isinstance(advertised_pkce, list) or "S256" not in advertised_pkce):
        raise DiagnosticError("HCL_PKCE_UNSUPPORTED")
    keys = _json_get(jwks_url, context).get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 100:
        raise DiagnosticError("HCL_JWKS_INVALID")
    from cryptography.hazmat.primitives.asymmetric import rsa

    for key in keys:
        if not isinstance(key, dict) or key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256":
            continue
        if key.get("use", "sig") != "sig" or any(field in key for field in ("d", "p", "q")):
            continue
        try:
            numbers = []
            for field in ("e", "n"):
                value = key[field]
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16384}", value):
                    raise ValueError()
                numbers.append(int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"))
            public = rsa.RSAPublicNumbers(*numbers).public_key()
            if public.key_size >= 2048:
                return
        except (KeyError, ValueError, TypeError):
            continue
    raise DiagnosticError("HCL_JWKS_INVALID")


def _authentication_checks(plan, launcher):
    # Literal application defaults, not mode selection or file/environment writes.
    # Keep parity with app/settings.py:280-294; mode/bypass flags remain explicit.
    env = {
        "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
        "NATIVE_JWT_ALGORITHM": "RS256",
        "NATIVE_JWT_ACTIVE_KID": "native-v1",
        "NATIVE_AUTH_RATE_LIMIT_ENABLED": "true",
        **plan.environment,
    }
    results = []
    fallback = launcher.GreenfieldStack.STATE / ".env" if plan.profile == "greenfield" else launcher.ROOT / ".env"
    defaulted = {
        "NATIVE_JWT_AUDIENCE",
        "NATIVE_JWT_ALGORITHM",
        "NATIVE_JWT_ACTIVE_KID",
        "NATIVE_AUTH_RATE_LIMIT_ENABLED",
        "SMTP_PORT",
        "SMTP_USE_STARTTLS",
    }
    if fallback.is_file():
        try:
            inherited_defaults = {key.upper() for key in dev_config.parse_dotenv(_read_text(fallback))}
            if any(key not in plan.environment and key in inherited_defaults for key in defaulted):
                results.append(
                    _result(
                        "Configuration",
                        "BLOCKED",
                        "IMPLICIT_DOTENV_FALLBACK",
                        "An unprojected security/mail setting can come from dotenv instead of its application default. Review source precedence explicitly.",
                    )
                )
        except Exception:
            results.append(
                _result(
                    "Configuration",
                    "BLOCKED",
                    "DOTENV_FALLBACK_UNVERIFIED",
                    "An implicit dotenv source could not be safely inspected; no configuration was changed.",
                )
            )
    if plan.authentication_enabled is not True or env.get("DEV_DEFAULT_TENANT", "").lower() not in {
        "false",
        "0",
        "no",
        "off",
    }:
        results.append(
            _result(
                "Authentication",
                "BLOCKED",
                "AUTHENTICATION_CONFIGURATION_REQUIRED",
                "Require explicit authenticated mode with development bypass disabled; no mode was changed.",
            )
        )
    elif env.get("NEXT_PUBLIC_AUTH_ENABLED") != "true":
        results.append(
            _result(
                "Authentication",
                "FAIL",
                "FRONTEND_AUTHENTICATION_MISMATCH",
                "Backend and frontend authenticated mode must agree exactly.",
            )
        )
    elif not plan.auth_modes:
        results.append(
            _result(
                "Authentication",
                "BLOCKED",
                "AUTHENTICATION_PROVIDER_REQUIRED",
                "Select the authorized Native Login or HCL.CS configuration explicitly.",
            )
        )
    else:
        results.append(
            _result(
                "Authentication",
                "PASS",
                "AUTHENTICATED_MODE_SELECTED",
                "Authentication is enabled and the development bypass is disabled.",
            )
        )
    if "native" in plan.auth_modes:
        try:
            launcher.validate_secrets(dict(env))
            if not all(env.get(key) for key in ("NATIVE_JWT_ISSUER", "NATIVE_JWT_AUDIENCE", "NATIVE_JWT_ACTIVE_KID")):
                raise DiagnosticError("NATIVE_JWT_CONFIGURATION_REQUIRED")
            if env.get("NATIVE_JWT_ALGORITHM", "RS256") != "RS256" or env.get("AUTH_SESSION_STORE") != "redis":
                raise DiagnosticError("NATIVE_CONFIGURATION_INVALID")
            if env.get("NATIVE_SECURITY_OUTBOX_KEY") == env.get("AUTH_SESSION_ENCRYPTION_KEY"):
                raise DiagnosticError("NATIVE_KEY_REUSE")
            if not all(
                _true(env.get(key, "false"))
                for key in (
                    "NATIVE_SECURITY_OUTBOX_ENABLED",
                    "NATIVE_AUTH_RATE_LIMIT_ENABLED",
                    "EMAIL_DELIVERY_ENABLED",
                )
            ):
                raise DiagnosticError("NATIVE_SECURITY_CONFIGURATION_REQUIRED")
            results.append(
                _result(
                    "Native Login",
                    "PASS",
                    "NATIVE_KEYS_CONFIGURATION_VALID",
                    "Signing pair, independent encryption keys, sessions, rate limits and encrypted mail configuration validate.",
                )
            )
        except Exception:
            results.append(
                _result(
                    "Native Login",
                    "FAIL",
                    "NATIVE_CONFIGURATION_INVALID",
                    "Review existing JWT pairing/issuer/audience/key ID, independent encryption keys, Redis sessions, rate limits and encrypted outbox flags.",
                )
            )
        if not _true(env.get("NATIVE_USER_CREATION_ENABLED", "false")):
            results.append(
                _result(
                    "Native enrollment",
                    "WARN",
                    "NATIVE_ENROLLMENT_DISABLED",
                    "User creation is disabled; any enrollment change requires explicit operator authorization.",
                )
            )
        if _true(env.get("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "false")):
            results.append(
                _result(
                    "Native enrollment",
                    "WARN",
                    "TEMPORARY_BOOTSTRAP_ENABLED",
                    "Review temporary enrollment enablement; ordinary startup must not create privileged users.",
                )
            )
    if "hclcs" in plan.auth_modes:
        safe_hcl_codes = {
            "PROBE_TIMEOUT",
            "HCL_AUTHENTICATION_BLOCKED",
            "HCL_CONFIGURATION_INCOMPLETE",
            "HCL_TLS_CONFIGURATION_INVALID",
            "HCL_REDIRECT_CONFIGURATION_INVALID",
            "HCL_ALGORITHM_INVALID",
            "HCL_FRONTEND_MISMATCH",
            "HCL_CA_PATH_AMBIGUOUS",
            "HCL_DISCOVERY_INVALID",
            "HCL_PKCE_UNSUPPORTED",
            "HCL_JWKS_INVALID",
            "HTTP_REDIRECT_REFUSED",
            "HTTP_STATUS_UNHEALTHY",
            "HTTP_RESPONSE_LIMIT",
            "HTTP_INVALID_JSON",
        }
        try:
            if plan.authentication_enabled is not True:
                raise DiagnosticError("HCL_AUTHENTICATION_BLOCKED")
            _bounded(lambda: _hcl_check(env, launcher.ROOT), timeout=8)
            results.append(
                _result(
                    "HCL.CS",
                    "PASS",
                    "HCL_CONFIGURATION_DISCOVERY_VALID",
                    "Configured issuer/client/redirect consistency, trusted discovery and RS256 JWKS validate; provider registration and login are not verified.",
                )
            )
        except Exception as error:
            results.append(
                _result(
                    "HCL.CS",
                    "FAIL",
                    error.code
                    if isinstance(error, DiagnosticError) and error.code in safe_hcl_codes
                    else "HCL_CONFIGURATION_DISCOVERY_FAILED",
                    "Review approved issuer/audience/client/redirect configuration, CA trust and HTTPS discovery/JWKS; no login or provisioning was attempted.",
                )
            )
    if "entra" in plan.auth_modes:
        results.append(
            _result(
                "Entra",
                "WARN",
                "ENTRA_ACCEPTANCE_SEPARATE",
                "Existing Entra settings were preserved; this diagnostic does not establish Entra login acceptance.",
            )
        )
    if len(plan.auth_modes) > 1:
        results.append(
            _result(
                "Authentication",
                "WARN",
                "MULTIPLE_PROVIDERS_SELECTED",
                "Existing multiple-provider settings were preserved; verify their approved mode-specific acceptance.",
            )
        )
    return tuple(results)


def _greenfield_inventory(launcher):
    identities = json.loads(launcher.GreenfieldStack.read_private("docker-identities.json"))
    names = {"sbom-greenfield-uuid-dev-" + service + "-1" for service in ("postgres", "redis", "mailpit")}
    if not isinstance(identities, dict) or set(identities) != names:
        raise DiagnosticError("CONTAINER_IDENTITY_UNVERIFIED")
    completed = subprocess.run(
        launcher.GreenfieldStack.docker_command() + ["inspect", *sorted(names)],
        capture_output=True,
        text=True,
        timeout=5,
        env=_command_environment(),
    )
    if completed.returncode or len(completed.stdout) > 1048576:
        raise DiagnosticError("CONTAINER_INSPECTION_FAILED")
    actual = json.loads(completed.stdout)
    if not isinstance(actual, list) or len(actual) != 3:
        raise DiagnosticError("CONTAINER_IDENTITY_UNVERIFIED")
    found = set()
    for item in actual:
        name = item["Name"].removeprefix("/")
        service = name.removeprefix("sbom-greenfield-uuid-dev-").removesuffix("-1")
        publications = {
            "postgres": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56044"}]},
            "redis": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56381"}]},
            "mailpit": {
                "1025/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1026"}],
                "8025/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8026"}],
            },
        }
        if (
            name not in identities
            or item["Id"] != identities[name]
            or item["Config"]["Labels"].get("com.docker.compose.project") != "sbom-greenfield-uuid-dev"
            or set(item["NetworkSettings"]["Networks"]) != {"sbom-greenfield-uuid-dev_access"}
            or item["HostConfig"]["PortBindings"] != publications[service]
        ):
            raise DiagnosticError("CONTAINER_IDENTITY_UNVERIFIED")
        volumes = [mount["Name"] for mount in item["Mounts"] if mount["Type"] == "volume"]
        if service in {"postgres", "redis"} and volumes != [
            "sbom-greenfield-uuid-dev_" + ("pgdata" if service == "postgres" else "redisdata")
        ]:
            raise DiagnosticError("CONTAINER_STORAGE_UNVERIFIED")
        if (
            service == "postgres"
            and item["Image"] != "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"
        ):
            raise DiagnosticError("CONTAINER_IMAGE_UNVERIFIED")
        found.add(name)
    if found != names:
        raise DiagnosticError("CONTAINER_IDENTITY_UNVERIFIED")


def _heartbeat_check(component, role, queues, record, state, plan, launcher):
    directory = launcher.GreenfieldStack.STATE if plan.profile == "greenfield" else launcher.ROOT / ".dev-logs"
    value = json.loads(_read_text(directory / f"{role}-health.json", limit=65536))
    if value.get("instance") != state["instance"] or not 0 <= time.time() - value.get("time", 0) <= 20:
        raise DiagnosticError("HEARTBEAT_STALE")
    pid = value.get("pid")
    saved = next((member for member in [record, *record.get("members", [])] if member.get("pid") == pid), None)
    if type(pid) is not int or not saved or not launcher.matches(saved, launcher.process_info(pid)):
        raise DiagnosticError("HEARTBEAT_IDENTITY_UNVERIFIED")
    if queues is not None:
        node = launcher.worker_node(role, state["instance"], plan.profile)
        if value.get("connected") is not True or value.get("node") != node or set(value.get("queues", [])) != queues:
            raise DiagnosticError("WORKER_QUEUES_UNVERIFIED")


def _tls_handshake(port, context):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname="localhost"):
            pass


def _same_leader(component, state, launcher):
    record = state["services"][component]
    if record.get("tree_unverified") or not launcher.matches(record, launcher.process_info(record["pid"])):
        raise DiagnosticError("PROCESS_IDENTITY_CHANGED")


def _process_guidance(component, state, launcher, record, message, error=None):
    profile = "greenfield" if state.get("profile") == "greenfield" else "legacy"
    directory = launcher.GreenfieldStack.STATE if profile == "greenfield" else launcher.ROOT / ".dev-logs"
    filenames = {
        "API": "backend.log" if profile == "greenfield" else "api.log",
        "Frontend": "frontend.log",
        "Celery worker": "worker.log" if profile == "greenfield" else "celery-worker.log",
        "Celery reports worker": "reports-worker.log" if profile == "greenfield" else "celery-reports-worker.log",
        "Celery Beat": "beat.log" if profile == "greenfield" else "celery-beat.log",
    }
    details = str(error) if error is not None else str(record.get("inspection_error", ""))
    match = re.search(r"(?:winerror=|WinError\s+)([0-9]{1,10})\b", details)
    code = getattr(error, "winerror", None)
    if code is None and match:
        code = int(match[1])
    if type(code) is int and 0 <= code <= 0xFFFFFFFF:
        message += f" Windows error={code}."
    if type(record.get("pid")) is int:
        message += f" Recorded PID={record['pid']}."
    return message + f" Log: {directory / filenames[component]}"


def _runtime_checks(plan, state, launcher, context=None):
    if not state or not state.get("services"):
        return (
            _result(
                "Runtime",
                "SKIPPED",
                "RUNTIME_STOPPED",
                "No managed application runtime is recorded; diagnose does not start it.",
            ),
        )
    results, verified = [], set()
    components = ("API", "Frontend", "Celery worker", "Celery reports worker", "Celery Beat")
    if set(state["services"]) - set(components):
        results.append(
            _result(
                "Runtime",
                "BLOCKED",
                "UNRECOGNIZED_SERVICE_RECORD",
                "Additional component records require independent inspection; unknown names/arguments were not displayed or changed.",
            )
        )
    for component in components:
        record = state["services"].get(component)
        if not record:
            results.append(
                _result(
                    component,
                    "FAIL" if state.get("ready") else "SKIPPED",
                    "PROCESS_NOT_REGISTERED",
                    "No owned component record exists; inspect status/logs if startup has failed.",
                )
            )
            continue
        if (
            record.get("tree_unverified")
            or not record.get("birth")
            or not record.get("exe")
            or type(record.get("pid")) is not int
        ):
            results.append(
                _result(
                    component,
                    "BLOCKED",
                    "PROCESS_TREE_UNVERIFIED",
                    _process_guidance(
                        component,
                        state,
                        launcher,
                        record,
                        "Ownership/tree proof is incomplete; preserve runtime records. Nothing was signalled.",
                    ),
                )
            )
            continue
        try:
            current = launcher.process_info(record["pid"])
            if not launcher.matches(record, current):
                results.append(
                    _result(
                        component,
                        "BLOCKED" if current else "FAIL",
                        "PROCESS_IDENTITY_CHANGED" if current else "PROCESS_EXITED",
                        _process_guidance(
                            component,
                            state,
                            launcher,
                            record,
                            "Recorded leader is absent or changed; saved descendants were not cleared or adopted.",
                        ),
                    )
                )
                continue
            verified.add(component)
            results.append(
                _result(
                    component,
                    "PASS",
                    "PROCESS_IDENTITY_VERIFIED",
                    "Recorded leader creation/executable identity matches; no process tree was refreshed.",
                )
            )
        except Exception as error:
            results.append(
                _result(
                    component,
                    "BLOCKED",
                    "PROCESS_INSPECTION_UNAVAILABLE",
                    _process_guidance(
                        component,
                        state,
                        launcher,
                        record,
                        "Identity is unverified; access denial/unknown ownership never permits termination.",
                        error,
                    ),
                )
            )
    if plan is None:
        results.append(
            _result(
                "Runtime health",
                "SKIPPED",
                "RUNTIME_CONFIGURATION_BLOCKED",
                "Configuration must resolve before service health can be checked.",
            )
        )
        return tuple(results)
    for component, role, queues in (
        ("Celery worker", "default", {"celery"}),
        ("Celery reports worker", "reports", {"reports"}),
        ("Celery Beat", "beat", None),
    ):
        if component not in verified:
            continue
        try:
            _heartbeat_check(component, role, queues, state["services"][component], state, plan, launcher)
            results.append(
                _result(
                    component,
                    "PASS",
                    "HEARTBEAT_VERIFIED",
                    "Stored instance/PID/queue or scheduler progress heartbeat is current; no broker RPC was published.",
                )
            )
        except Exception:
            results.append(
                _result(
                    component,
                    "FAIL",
                    "HEARTBEAT_UNVERIFIED",
                    "Inspect this component's logs: stored heartbeat is missing, stale, malformed or mismatched.",
                )
            )
    if "API" in verified:
        try:
            port = int(plan.environment.get("DEV_API_PORT", "18000"))
            if not 1 <= port <= 65535 or state["services"]["API"].get("port") != port:
                raise DiagnosticError("RUNTIME_PORT_CONFLICT")
            _same_leader("API", state, launcher)
            # /health can initialize NVD mirror settings. The root identifier
            # is inert; database health is inspected separately in readonly SQL.
            if (
                _bounded(lambda port=port: _json_get(f"http://127.0.0.1:{port}/"), timeout=4).get("service")
                != "sbom-analyzer-api"
            ):
                raise DiagnosticError("API_UNHEALTHY")
            if (
                "native" in plan.auth_modes
                and _bounded(lambda port=port: _json_get(f"http://127.0.0.1:{port}/ready/iam"), timeout=4).get("ready")
                is not True
            ):
                raise DiagnosticError("IAM_UNHEALTHY")
            _same_leader("API", state, launcher)
            results.append(
                _result(
                    "API/IAM",
                    "PASS",
                    "API_HEALTH_VERIFIED",
                    "Owned API identifier and selected Native IAM readiness passed; database is checked through readonly SQL, HCL login separately.",
                )
            )
        except Exception as error:
            results.append(
                _result(
                    "API/IAM",
                    "FAIL",
                    "PROBE_TIMEOUT"
                    if isinstance(error, DiagnosticError) and error.code == "PROBE_TIMEOUT"
                    else "API_HEALTH_FAILED",
                    "Inspect API logs and this profile's database/Native IAM readiness; no startup was attempted.",
                )
            )
    if "Frontend" in verified and context is not None:
        try:
            port = int(plan.environment.get("DEV_FRONTEND_PORT", "13000"))
            if not 1 <= port <= 65535 or state["services"]["Frontend"].get("port") != port:
                raise DiagnosticError("RUNTIME_PORT_CONFLICT")
            _same_leader("Frontend", state, launcher)
            _bounded(lambda port=port, context=context: _tls_handshake(port, context), timeout=4)
            _same_leader("Frontend", state, launcher)
            results.append(
                _result(
                    "Frontend HTTPS",
                    "PASS",
                    "FRONTEND_TLS_VERIFIED",
                    "Owned frontend completed certificate-verified TLS; no HTTP page request or browser was launched.",
                )
            )
        except Exception as error:
            results.append(
                _result(
                    "Frontend HTTPS",
                    "FAIL",
                    "PROBE_TIMEOUT"
                    if isinstance(error, DiagnosticError) and error.code == "PROBE_TIMEOUT"
                    else "FRONTEND_TLS_FAILED",
                    "Review frontend logs, selected port and preserved certificate; no TLS bypass was used.",
                )
            )
    if not state.get("ready"):
        results.append(
            _result(
                "Runtime",
                "WARN",
                "RUNTIME_NOT_READY",
                "The saved runtime has not reported readiness; inspect status/logs for startup or shutdown progress.",
            )
        )
    return tuple(results)


def _workspace_check(profile, launcher, environment=None):
    try:
        if environment is not None:
            dev_components.review_source_environment(launcher, environment, profile)
        if not dev_frontend.inspect_workspace(launcher, profile):
            raise launcher.SetupError("FRONTEND_WORKSPACE_SETUP_REQUIRED")
        if environment is not None:
            dev_components.process_environment(
                launcher, "Frontend", environment, dev_frontend.workspace_path(launcher, profile), profile=profile
            )
        return _result(
            "Frontend configuration",
            "PASS",
            "FRONTEND_WORKSPACE_VERIFIED",
            "The prepared environment-free workspace and source/dependency links validate; no files were changed.",
        )
    except launcher.SetupError as error:
        code = str(error).partition(":")[0]
        if code == "FRONTEND_GUARD_REQUIRED":
            return _result(
                "Frontend configuration",
                "BLOCKED",
                code,
                "Restore the reviewed launcher guard source before startup; no Node helper was executed.",
            )
        if code in {
            "FRONTEND_SOURCE_CONFIGURATION_UNVERIFIED",
            "FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED",
            "TLS_CA_PATH_REVIEW_REQUIRED",
            "TLS_VERIFICATION_REQUIRED",
        }:
            return _result(
                "Frontend configuration",
                "BLOCKED",
                code,
                "Review approved profile settings and Next-only fallback files; no private file was changed or implicitly adopted.",
            )
        return _result(
            "Frontend configuration",
            "BLOCKED",
            "FRONTEND_WORKSPACE_REVIEW_REQUIRED",
            "Review the setup plan for missing/stale workspace preparation or unknown files/links; preserve existing environment files.",
        )
    except Exception:
        return _result(
            "Frontend configuration",
            "BLOCKED",
            "FRONTEND_WORKSPACE_REVIEW_REQUIRED",
            "Review the setup plan for missing/stale workspace preparation or unknown files/links; preserve existing environment files.",
        )


def run_checks(args, launcher):
    """Aggregate inspections without printing configuration or preparing anything."""
    try:
        results = list(_bounded(lambda: _dependency_checks(launcher), timeout=8))
    except Exception:
        results = [
            _result(
                "Dependencies",
                "FAIL",
                "PROBE_TIMEOUT",
                "Dependency inspection exceeded its reporting deadline; no preparation was attempted.",
            )
        ]
    try:
        state = _bounded(lambda: _runtime_state(launcher), timeout=3)
    except Exception:
        results.append(
            _result(
                "Runtime",
                "BLOCKED",
                "RUNTIME_STATE_UNVERIFIED",
                "Retain the malformed/unreadable ownership record and request independent inspection.",
            )
        )
        results.append(
            _result(
                "Configuration",
                "BLOCKED",
                "CONFIGURATION_RUNTIME_BLOCKED",
                "Recorded profile/family cannot be safely established; dependency checks still completed.",
            )
        )
        return DiagnosticReport(tuple(results))
    try:
        profile, family = _bounded(lambda: _select_profile(args, launcher, state), timeout=3)
    except Exception:
        results.append(
            _result(
                "Configuration",
                "BLOCKED",
                "PROFILE_CONFIGURATION_CONFLICT",
                "Review selected versus recorded profile/configuration family and incomplete installation files; no fallback occurred.",
            )
        )
        results.extend(_runtime_checks(None, state, launcher))
        return DiagnosticReport(tuple(results))
    label = (
        "protected Greenfield state"
        if profile == "greenfield"
        else {"managed": ".env.dev.local", "windows": ".windows/sbom.env.ps1", "env": ".env"}[family]
    )
    results.append(
        _result(
            "Profile",
            "PASS",
            "PROFILE_SELECTED",
            f"Selected {profile}/{family}: {label}; runtime-family pinning is preserved.",
        )
    )
    try:
        certificate, context = _bounded(lambda: _certificate_check(profile, launcher), timeout=35)
    except Exception:
        certificate, context = (
            _result(
                "Certificates",
                "FAIL",
                "PROBE_TIMEOUT",
                "Read-only certificate/trust inspection exceeded its reporting deadline.",
            ),
            None,
        )
    results.append(certificate)
    if profile == "greenfield" and certificate.status != "PASS":
        results.append(
            _result(
                "Configuration",
                "BLOCKED",
                "GREENFIELD_TRUST_REQUIRED",
                "Existing Greenfield trust must validate before application credentials are read; nothing was prepared.",
            )
        )
        results.extend(_runtime_checks(None, state, launcher))
        return DiagnosticReport(tuple(results))
    try:
        plan = _bounded(lambda: _configuration(args, launcher, state), timeout=5)
        results.append(
            _result(
                "Configuration",
                "PASS",
                "CONFIGURATION_RESOLVED",
                "Selected snapshots and local database target policy validate; secrets remain in memory.",
            )
        )
    except Exception as error:
        safe_codes = {
            "SETUP_REQUIRED",
            "INVALID_SELECTION",
            "INVALID_ENVIRONMENT",
            "INVALID_MANAGED_CONFIG",
            "INVALID_WINDOWS_CONFIG",
            "INVALID_DATABASE_TARGET",
            "TARGET_QUERY_REVIEW_REQUIRED",
            "INVALID_PORTS",
            "INVALID_PROVIDER",
            "DATABASE_PORT_CONFLICT",
            "UNSUPPORTED_BROKER",
            "ENVIRONMENT_NAME_CONFLICT",
            "INVALID_PUBLIC_URL",
            "TLS_VERIFICATION_REQUIRED",
            "NODE_OPTIONS_REVIEW_REQUIRED",
            "FRONTEND_SETTING_NAME_REVIEW_REQUIRED",
        }
        code = (
            error.code
            if isinstance(error, dev_config.ConfigurationError) and error.code in safe_codes
            else "CONFIGURATION_INVALID"
        )
        if isinstance(error, FileNotFoundError):
            code = "CONFIGURATION_MISSING"
        elif isinstance(error, PermissionError):
            code = "CONFIGURATION_ACCESS_DENIED"
        source = (
            "protected Greenfield snapshots"
            if profile == "greenfield"
            else {"managed": ".env.dev.local", "windows": ".windows/sbom.env.ps1", "env": ".env"}[family]
        )
        results.append(
            _result(
                "Configuration",
                "BLOCKED",
                code,
                f"Review selected {source}, explicit local target, conflicting names and setup-required values; no file was changed.",
            )
        )
        results.extend(_runtime_checks(None, state, launcher))
        return DiagnosticReport(tuple(results))
    try:
        results.append(_bounded(lambda: _workspace_check(profile, launcher, plan.environment), timeout=6))
    except DiagnosticError:
        results.append(
            _result(
                "Frontend configuration",
                "BLOCKED",
                "PROBE_TIMEOUT",
                "Read-only workspace inspection exceeded its reporting deadline; no files were changed.",
            )
        )
    try:
        results.extend(_bounded(lambda: _authentication_checks(plan, launcher), timeout=10))
    except Exception:
        results.append(
            _result(
                "Authentication",
                "FAIL",
                "PROBE_TIMEOUT",
                "Read-only authentication inspection exceeded its reporting deadline; no mode or settings were changed.",
            )
        )
    data_safe = True
    if profile == "greenfield":
        try:
            _greenfield_inventory(launcher)
            results.append(
                _result(
                    "Containers",
                    "PASS",
                    "CONTAINER_IDENTITY_VERIFIED",
                    "Recorded containers, publications, storage and PostgreSQL image match; none were started.",
                )
            )
        except Exception:
            data_safe = False
            results.append(
                _result(
                    "Containers",
                    "BLOCKED",
                    "CONTAINER_IDENTITY_UNVERIFIED",
                    "Inspect approved Docker context and saved container identities; dependent service probes were skipped.",
                )
            )
    if data_safe:
        try:
            results.extend(_bounded(lambda: _database_checks(plan, launcher), timeout=8))
        except Exception:
            results.append(
                _result(
                    "Database",
                    "FAIL",
                    "PROBE_TIMEOUT",
                    "Read-only database inspection exceeded its reporting deadline; a read-only connection may finish until CLI exit.",
                )
            )
            results.append(
                _result(
                    "Enrollment",
                    "BLOCKED",
                    "ENROLLMENT_DATABASE_BLOCKED",
                    "Database target/schema inspection must complete before enrollment can be assessed.",
                )
            )
        urls = [("Redis", plan.environment.get("REDIS_URL", ""))]
        if "native" in plan.auth_modes:
            urls += [
                ("Sessions", plan.environment.get("AUTH_SESSION_REDIS_URL", "")),
                ("Rate limits", plan.environment.get("NATIVE_AUTH_RATE_LIMIT_STORAGE_URI", "")),
            ]
        for component, url in urls:
            try:
                if not _bounded(lambda url=url: _redis_ping(url), timeout=4):
                    raise DiagnosticError("REDIS_UNAVAILABLE")
                results.append(
                    _result(
                        component,
                        "PASS",
                        "REDIS_PING_VALID",
                        "Selected Redis endpoint answered PING; no keys were written. To verify Lua, Celery and session semantics, review setup --profile legacy --legacy-config managed --check-local-services --plan, then separately approve its disposable probes.",
                    )
                )
            except Exception as error:
                results.append(
                    _result(
                        component,
                        "FAIL",
                        "PROBE_TIMEOUT"
                        if isinstance(error, DiagnosticError) and error.code == "PROBE_TIMEOUT"
                        else "REDIS_PING_FAILED",
                        "Review this profile's Redis URL, TLS, credentials and running provider; values were withheld.",
                    )
                )
        if "native" in plan.auth_modes or _true(plan.environment.get("EMAIL_DELIVERY_ENABLED", "false")):
            try:
                _bounded(lambda: _smtp_check(plan.environment), timeout=6)
                results.append(
                    _result(
                        "SMTP",
                        "PASS",
                        "SMTP_PROTOCOL_READY",
                        "Configured SMTP greeting/EHLO and selected TLS validate; no authentication or message was sent.",
                    )
                )
            except Exception as error:
                results.append(
                    _result(
                        "SMTP",
                        "FAIL",
                        "PROBE_TIMEOUT"
                        if isinstance(error, DiagnosticError) and error.code == "PROBE_TIMEOUT"
                        else error.code if isinstance(error, DiagnosticError) and error.code in {"MAILPIT_EXPOSED", "MAILPIT_BINDING_UNVERIFIED"}
                        else "SMTP_PROTOCOL_FAILED",
                        "For local Mailpit, verify both SMTP/UI bind only to loopback (mailpit --smtp 127.0.0.1:<smtp-port> --listen 127.0.0.1:<ui-port>); review saved ports and TLS. No service was changed and no message or activation token was created.",
                    )
                )
    else:
        results.append(
            _result(
                "Data services",
                "BLOCKED",
                "DATA_SERVICE_IDENTITY_BLOCKED",
                "Restore verified container identity before database, Redis or SMTP probes.",
            )
        )
    results.extend(_runtime_checks(plan if data_safe else None, state, launcher, context))
    return DiagnosticReport(tuple(results))
