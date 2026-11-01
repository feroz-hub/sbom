"""Read-only gates for ordinary startup of an explicitly prepared installation."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from . import dev_config, dev_environment
else:
    import dev_config
    import dev_environment


def _required(launcher, code, guidance):
    raise launcher.SetupError(f"{code}: {guidance} No installation or configuration change was attempted.")


def _development_only(environment, launcher):
    aliases = {
        "": None,
        "dev": "development",
        "development": "development",
        "local": "development",
        "test": "test",
        "testing": "test",
    }
    values = [
        str(value).strip().lower()
        for key, value in environment.items()
        if key.casefold() in {"app_env", "app_environment"}
    ]
    if any(value not in aliases for value in values):
        _required(
            launcher, "DEVELOPMENT_ENVIRONMENT_REQUIRED", "Development preparation cannot target staging or production."
        )
    if len({aliases[value] for value in values if aliases[value] is not None}) > 1:
        _required(
            launcher,
            "ENVIRONMENT_NAME_CONFLICT",
            "APP_ENV and APP_ENVIRONMENT identify different environments; review their authoritative configuration.",
        )


def require_project(launcher):
    """Verify existing stamps and entry points; return npm without executing it."""
    _development_only(os.environ, launcher)
    try:
        if not launcher.venv_python().is_file():
            raise ValueError()
        for package in ("alembic", "celery", "cryptography", "dotenv", "psycopg", "redis", "uvicorn"):
            if importlib.util.find_spec(package) is None:
                raise ValueError()
        requirements = dev_environment.bounded_read_bytes(launcher.ROOT / "requirements.txt", 1048576)
        digest = hashlib.sha256(requirements).hexdigest()
        if dev_environment.bounded_read_text(launcher.VENV / ".sbom-requirements-sha256", 256).strip() != digest:
            raise ValueError()
    except (OSError, ValueError, ImportError):
        _required(
            launcher,
            "PROJECT_SETUP_REQUIRED",
            "Review python scripts/dev.py setup for the project virtualenv/dependencies.",
        )
    try:
        frontend = launcher.ROOT / "frontend"
        manifest = dev_environment.bounded_read_bytes(frontend / "package.json", 1048576)
        lock = dev_environment.bounded_read_bytes(frontend / "package-lock.json", 8388608)
        digest = hashlib.sha256(manifest + b"\0" + lock).hexdigest()
        modules = frontend / "node_modules"
        if (
            not modules.is_dir()
            or dev_environment.bounded_read_text(modules / ".sbom-dependencies-sha256", 256).strip() != digest
        ):
            raise ValueError()
        if not (modules / "next/dist/bin/next").is_file():
            raise ValueError()
        npm = shutil.which(
            "npm", path=str(launcher.GreenfieldStack.node_binary().parent) + os.pathsep + os.environ.get("PATH", "")
        )
        if not npm:
            raise ValueError()
        command = launcher.normalize_command([npm, "--version"])
        if not Path(command[1] if len(command) > 2 else npm).is_file():
            raise ValueError()
        return npm
    except (OSError, ValueError):
        _required(
            launcher,
            "FRONTEND_SETUP_REQUIRED",
            "Review python scripts/dev.py setup for the saved frontend dependencies and Node/npm entry points.",
        )


def _managed_ports(saved, inspection, launcher):
    pg_port = inspection.database.port
    pg = saved.get("DEV_POSTGRES_PROVIDER") or ("docker" if pg_port == launcher.POSTGRES_PORT else "local")
    redis_url = saved.get("REDIS_URL") or saved.get("CELERY_BROKER_URL")
    try:
        if any(
            saved[key] not in {"local", "docker"}
            for key in ("DEV_POSTGRES_PROVIDER", "DEV_REDIS_PROVIDER")
            if key in saved
        ):
            raise ValueError()
        redis = urlsplit(redis_url) if redis_url else None
        redis_port = (redis.port or 6379) if redis is not None else None
        if redis is not None and (
            redis.scheme != "redis"
            or redis.hostname not in {"localhost", "127.0.0.1"}
            or redis.username is not None
            or redis.password is not None
            or "?" in redis_url
            or "#" in redis_url
        ):
            raise ValueError()
        provider = saved.get("DEV_REDIS_PROVIDER") or (
            "docker" if redis_port == launcher.REDIS_PORT else "local" if redis_port is not None else None
        )
        if provider not in {"local", "docker"} or pg not in {"local", "docker"}:
            raise ValueError()
        expected = launcher.REDIS_PORT if provider == "docker" else 6379
        if redis_port is not None and not 1 <= redis_port <= 65535:
            raise ValueError()
        shared_zero = saved.get("DEV_REDIS_DATABASE_MODE") == "shared-db0"
        if saved.get("DEV_REDIS_DATABASE_MODE") not in {None, "shared-db0"} or (shared_zero and not saved.get("SBOM_DEV_RESOURCE_ID")):
            raise ValueError()
        for key, database in (
            ("REDIS_URL", "0"),
            ("CELERY_BROKER_URL", "0"),
            ("CELERY_RESULT_BACKEND", "0"),
            ("AUTH_SESSION_REDIS_URL", "1"),
            ("NATIVE_AUTH_RATE_LIMIT_STORAGE_URI", "2"),
        ):
            if key in saved:
                database = "0" if shared_zero else database
                selected = urlsplit(saved[key])
                if (
                    selected.scheme != "redis"
                    or selected.hostname not in {"localhost", "127.0.0.1"}
                    or selected.username is not None
                    or selected.password is not None
                    or (selected.port or 6379) != (redis_port or expected)
                    or selected.path not in ({"", "/0"} if database == "0" else {"/" + database})
                    or "?" in saved[key]
                    or "#" in saved[key]
                ):
                    raise ValueError()
        smtp = int(saved.get("SMTP_PORT", str(launcher.MAILPIT_SMTP_PORT)))
        if (not 1 <= smtp <= 65535 or
                (smtp != launcher.MAILPIT_SMTP_PORT and not saved.get("DEV_MAILPIT_UI_PORT"))):
            raise ValueError()
        if saved.get("DEV_MAILPIT_UI_PORT") and not 1 <= int(saved["DEV_MAILPIT_UI_PORT"]) <= 65535:
            raise ValueError()
    except (ValueError, TypeError):
        _required(
            launcher,
            "SAVED_PROVIDER_REVIEW_REQUIRED",
            "Restore the selected managed provider/port configuration; no provider fallback is permitted.",
        )
    return dev_config.ServicePorts(pg_port, redis_port or expected, smtp, pg, provider)


def validate_managed_mode(environment, launcher):
    """Refuse mode conversion before setup or prepared Native startup."""
    names = {"AUTH_ENABLED", "NATIVE_AUTH_ENABLED", "HCL_AUTH_ENABLED", "ENTRA_ENABLED", "DEV_DEFAULT_TENANT"}
    if any(key.upper() in names and key not in names for key in environment):
        _required(
            launcher,
            "MANAGED_AUTHENTICATION_REVIEW_REQUIRED",
            "Use unambiguous canonical authentication flags; no mode was converted.",
        )
    for key, expected in (
        ("AUTH_ENABLED", True),
        ("NATIVE_AUTH_ENABLED", True),
        ("HCL_AUTH_ENABLED", False),
        ("ENTRA_ENABLED", False),
        ("DEV_DEFAULT_TENANT", False),
    ):
        if key in environment:
            value = environment[key].lower()
            if (
                value not in {"true", "1", "yes", "on", "false", "0", "no", "off"}
                or (value in {"true", "1", "yes", "on"}) != expected
            ):
                _required(
                    launcher,
                    "MANAGED_AUTHENTICATION_REVIEW_REQUIRED",
                    "The selected managed Native profile conflicts with existing authentication flags; no mode was converted.",
                )


def prepared_legacy_environment(launcher, family):
    """Resolve prepared Legacy settings without discovery, generation or SQL.

    The caller retains authenticated connectivity, current-schema and check-only
    Mailpit checks before launching. This helper never resumes Legacy containers.
    """
    try:
        saved, frontend = dev_environment.load_legacy_snapshots(family, launcher)
        common = {
            "profile": "legacy",
            "family": family,
            "inherited": dict(os.environ),
            "saved": saved,
            "frontend": frontend,
            "root": str(launcher.ROOT),
            "platform": "linux" if launcher.sys.platform.startswith("linux") else launcher.sys.platform,
        }
        inspection = dev_config.resolve_configuration(**common)
        _development_only(inspection.environment, launcher)
        plan = inspection
        if family == "managed":
            validate_managed_mode(inspection.environment, launcher)
            launcher.validate_secrets(saved)
            plan = dev_config.resolve_configuration(
                **common, purpose="startup", ports=_managed_ports(saved, inspection, launcher)
            )
        elif "native" in plan.auth_modes:
            launcher.validate_secrets(dict(plan.environment))
        if plan.environment.get("AUTH_ENABLED", "").lower() not in {"true", "1", "yes", "on"} or plan.environment.get(
            "DEV_DEFAULT_TENANT", ""
        ).lower() not in {"false", "0", "no", "off"}:
            _required(
                launcher,
                "AUTHENTICATED_CONFIGURATION_REQUIRED",
                "The unified launcher requires authentication enabled and the development tenant bypass explicitly disabled.",
            )
        launcher.legacy_https_context()
        environment = dict(plan.environment)
        environment["PYTHONPATH"] = str(launcher.ROOT)
        return environment
    except (OSError, ValueError):
        _required(
            launcher,
            "CONFIGURATION_SETUP_REQUIRED",
            "Review the selected saved Legacy configuration, persistent Native keys and certificate pair through setup.",
        )
