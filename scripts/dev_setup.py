"""Inspect and authorize development preparation through the unified launcher.

Planning is observational. Only the supplied apply callback can prepare state,
and it receives the explicitly authorized categories after a second inspection.
The internal environment marker carries consent across a virtualenv handoff;
it is not a credential, public CLI option or authorization for privileged users.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from . import dev_config, dev_frontend, dev_prepared, dev_private
else:
    import dev_config
    import dev_frontend
    import dev_prepared
    import dev_private

APPROVAL_ENV = "_SBOM_DEV_SETUP_APPROVAL"
_MISSING = object()
_CATEGORIES = frozenset(
    {
        "project-dependencies",
        "configuration",
        "secrets",
        "certificates",
        "data-providers",
        "database-initialize",
        "database-migrate",
        "frontend-build",
        "frontend-workspace",
        "local-postgres-provision",
        "database-credentials",
        "local-service-checks",
    }
)
SETUP_CATEGORIES = _CATEGORIES
_KEYS = frozenset(
    {
        "NATIVE_JWT_PRIVATE_KEY",
        "NATIVE_JWT_PUBLIC_KEY",
        "NATIVE_SECURITY_OUTBOX_KEY",
        "AUTH_SESSION_ENCRYPTION_KEY",
    }
)


@dataclass(frozen=True)
class SetupAction:
    category: str
    description: str


@dataclass(frozen=True)
class SetupPlan:
    profile: str
    family: str
    actions: tuple[SetupAction, ...]
    blockers: tuple[str, ...]
    fingerprint: str = field(repr=False)


class _ObservationError(ValueError):
    pass


class _Snapshot:
    def __init__(self):
        self.observed = {}

    def record(self, path, raw, info=None):
        path = Path(path)
        info = path.lstat() if info is None else info
        self.observed[str(path.absolute())] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "mode": stat.S_IMODE(info.st_mode),
            "uid": getattr(info, "st_uid", None),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mtime_ns": info.st_mtime_ns,
            "size": info.st_size,
            "attributes": getattr(info, "st_file_attributes", None),
        }

    def read(self, path, *, limit=1048576):
        path = Path(path)
        key = str(path.absolute())
        try:
            before = path.lstat()
        except FileNotFoundError:
            self.observed[key] = "absent"
            return None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
        ):
            raise _ObservationError("A preparation input is redirected or not a regular file.")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise _ObservationError("A preparation input changed while being inspected.")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise _ObservationError("A preparation input exceeds the inspection limit.")
        self.record(path, data, opened)
        return data

    def text(self, path):
        raw = self.read(path)
        return None if raw is None else raw.decode("utf-8-sig")


def _enabled(value):
    return str(value).lower() in {"true", "1", "yes", "on"}


def _scope_check(layers, blockers):
    aliases = {
        "dev": "development",
        "local": "development",
        "development": "development",
        "test": "test",
        "testing": "test",
        "stage": "staging",
        "staging": "staging",
        "prod": "production",
        "production": "production",
    }
    effective = {}
    for layer in layers:
        for source_key, value in layer.items():
            key = source_key.upper()
            if key in {"APP_ENVIRONMENT", "APP_ENV"}:
                raw = str(value).strip().lower()
                canonical = aliases.get(raw)
                if canonical is None or canonical in {"production", "staging"}:
                    blockers.append(
                        "DEVELOPMENT_SCOPE_REQUIRED: setup refuses staging, production or unknown environment scope."
                    )
                effective[key] = canonical
    if len(effective) == 2 and effective["APP_ENVIRONMENT"] != effective["APP_ENV"]:
        blockers.append("ENVIRONMENT_SCOPE_CONFLICT: APP_ENVIRONMENT and APP_ENV disagree; no setting was changed.")


def _dependencies(snapshot, launcher, actions, blockers):
    root = Path(launcher.ROOT)
    if launcher.sys.version_info < launcher.MIN_PYTHON:
        blockers.append(
            "PYTHON_UNSUPPORTED: inspect and prepare with an approved Python 3.11+ interpreter; no virtualenv was created."
        )
    manifests = {}
    for name in launcher.REQUIRED_FILES:
        raw = snapshot.read(root / name)
        if raw is None:
            blockers.append("CHECKOUT_INCOMPLETE: restore the required project manifests before preparation.")
        manifests[name] = raw
    requirements = manifests.get("requirements.txt")
    package = manifests.get("frontend/package.json")
    lock = manifests.get("frontend/package-lock.json")
    python_stamp = snapshot.text(Path(launcher.VENV) / ".sbom-requirements-sha256")
    frontend_stamp = snapshot.text(root / "frontend/node_modules/.sbom-dependencies-sha256")
    python_ready = bool(
        requirements
        and python_stamp
        and python_stamp.strip() == hashlib.sha256(requirements).hexdigest()
        and launcher.venv_python().is_file()
    )
    if python_ready:
        if not _in_project_venv(launcher):
            blockers.append(
                "INSPECTION_DEPENDENCY_REQUIRED: verify installed packages with the existing project interpreter before authorizing preparation."
            )
        elif any(
            importlib.util.find_spec(name) is None
            for name in ("alembic", "celery", "cryptography", "dotenv", "psycopg", "redis", "uvicorn")
        ):
            python_ready = False
    frontend_ready = bool(
        package
        and lock
        and frontend_stamp
        and frontend_stamp.strip() == hashlib.sha256(package + b"\0" + lock).hexdigest()
        and (root / "frontend/node_modules/next/dist/bin/next").is_file()
    )
    # Generated dependency state must not invalidate an approved venv handoff.
    snapshot.observed.pop(str((Path(launcher.VENV) / ".sbom-requirements-sha256").absolute()), None)
    snapshot.observed.pop(str((root / "frontend/node_modules/.sbom-dependencies-sha256").absolute()), None)
    if not python_ready or not frontend_ready:
        actions["project-dependencies"] = (
            "Prepare only missing or stale project virtualenv and pinned Python/npm dependencies."
        )
    for directory in (root / "scripts", root / "alembic/versions"):
        for path in sorted(directory.glob("*.py")):
            snapshot.read(path)
    snapshot.read(root / "scripts/schema/postgresql_047_baseline.sql")
    snapshot.read(root / "app/settings.py")


def _runtime(snapshot, launcher, blockers):
    raw = snapshot.text(Path(launcher.ROOT) / ".dev-runtime.json")
    if raw is None:
        return
    try:
        state = json.loads(raw)
        valid = (
            isinstance(state, dict)
            and state.get("version") == 1
            and state.get("root") == str(Path(launcher.ROOT).resolve())
            and isinstance(state.get("services"), dict)
            and isinstance(state.get("instance"), str)
        )
    except (ValueError, TypeError):
        valid = False
    blockers.append(
        "RUNTIME_PRESENT: inspect status and use verified-ownership stop before preparation; saved records were retained."
        if valid
        else "RUNTIME_OWNERSHIP_UNVERIFIED: retain the runtime record and request independent ownership inspection."
    )


def _legacy_values(args, launcher, family, snapshot, actions, blockers):
    root = Path(launcher.ROOT)
    if family == "managed":
        text = snapshot.text(launcher.CONFIG)
        if text is None:
            if getattr(args, "postgres_provider", None) == "docker":
                blockers.append(
                    "APPROVED_DATABASE_CONFIGURATION_REQUIRED: fresh Legacy setup cannot adopt default Docker credentials; restore approved configuration or review explicit Greenfield provisioning."
                )
            try:
                dev_prepared.validate_managed_mode(os.environ, launcher)
            except launcher.SetupError:
                blockers.append(
                    "MANAGED_MODE_REVIEW_REQUIRED: managed Native setup cannot convert an existing authentication mode."
                )
            if not getattr(args, "initialize_database", False):
                blockers.append(
                    "CONFIGURATION_MISSING: for a fresh Docker-free installation run setup --profile legacy --legacy-config managed --provision-local-postgres --initialize-database --confirm-database sbom_analyser_dev. For an existing installation restore the original managed file."
                )
            else:
                actions["configuration"] = (
                    "Prepare a new private managed Native configuration using already-running selected dependencies, after approved target/empty-database checks."
                )
                actions["secrets"] = (
                    "Create fresh Native signing and independent session/outbox keys only for an explicitly verified fresh installation."
                )
            return {}, text is None
        values = dev_config.parse_managed(text)
    else:
        path = root / (".windows/sbom.env.ps1" if family == "windows" else ".env")
        text = snapshot.text(path)
        if text is None:
            blockers.append(
                "CONFIGURATION_MISSING: restore the selected existing Windows/env configuration; setup will not invent HCL provider details."
            )
            return {}, False
        values = dev_config.parse_windows(text) if family == "windows" else dev_config.parse_dotenv(text)
        frontend = snapshot.text(root / "frontend/.env.local")
        values = {**dev_config.parse_dotenv(frontend or ""), **values}
    _scope_check([values], blockers)
    if not values.get("DATABASE_URL"):
        blockers.append("DATABASE_CONFIGURATION_MISSING: restore the selected approved local database configuration.")
        return values, False
    plan = dev_config.resolve_configuration(
        profile="legacy",
        family=family,
        inherited=dict(os.environ),
        saved=values,
        root=str(root),
        platform="linux" if launcher.sys.platform.startswith("linux") else launcher.sys.platform,
    )
    if values.get("AUTH_ENABLED", "true").lower() in {"false", "0", "no", "off"} or _enabled(
        values.get("DEV_DEFAULT_TENANT", "false")
    ):
        blockers.append(
            "AUTHENTICATION_CONFIGURATION_REQUIRED: authenticated onboarding cannot enable bypass or silently convert an existing disabled mode."
        )
    if family == "managed":
        try:
            dev_prepared.validate_managed_mode(plan.environment, launcher)
        except launcher.SetupError:
            blockers.append(
                "MANAGED_MODE_REVIEW_REQUIRED: managed Native setup cannot convert an existing authentication mode."
            )
    elif family != "managed" and "hclcs" in plan.auth_modes:
        names = ("HCL_IAM_ISSUER", "HCL_IAM_AUDIENCE", "HCL_IAM_CLIENT_ID", "NEXT_PUBLIC_HCL_IAM_CLIENT_ID")
        if any(not plan.environment.get(name) for name in names):
            blockers.append(
                "HCL_CONFIGURATION_REQUIRED: obtain approved issuer, audience and client registration; no provider values were invented."
            )
    return values, False


def _keys(values, fresh, launcher, actions, blockers, *, native_default=True):
    present = _KEYS.intersection(values)
    native = _enabled(values.get("NATIVE_AUTH_ENABLED", "true" if native_default else "false"))
    if not native:
        if "AUTH_SESSION_ENCRYPTION_KEY" in values:
            try:
                if len(base64.b64decode(values["AUTH_SESSION_ENCRYPTION_KEY"], validate=True)) != 32:
                    raise ValueError()
            except (ValueError, TypeError, binascii.Error):
                blockers.append(
                    "SESSION_KEY_INVALID: restore the original valid session encryption key; setup will not replace it."
                )
        return
    if present and present != _KEYS:
        blockers.append(
            "PERSISTENT_KEYS_INCOMPLETE: restore the original signing/session/outbox material; setup will not regenerate it."
        )
    elif present == _KEYS:
        try:
            launcher.validate_secrets(dict(values))
        except ImportError:
            blockers.append(
                "KEY_VALIDATION_DEPENDENCY_REQUIRED: inspect with the existing project interpreter before approving changes."
            )
        except Exception:
            blockers.append(
                "PERSISTENT_KEYS_INVALID: restore the original valid matching keys; no rotation or replacement is authorized."
            )
    elif native and not fresh:
        blockers.append("PERSISTENT_KEYS_MISSING: restore original Native signing/session/outbox keys before setup.")


def _certificates(launcher, snapshot, actions, blockers):
    root = Path(launcher.ROOT)
    cert, key = root / "frontend/certificates/localhost.pem", root / "frontend/certificates/localhost-key.pem"
    try:
        dev_private.validate_parent(cert, root, allow_missing=True)
        dev_private.validate_parent(key, root, allow_missing=True)
    except dev_private.PrivateFileError:
        blockers.append(
            "CERTIFICATE_PARENT_UNVERIFIED: restore nonredirected certificate directories inside this checkout; no material was read or generated."
        )
        return
    cert_data, key_data = snapshot.read(cert), snapshot.read(key)
    if (cert_data is None) != (key_data is None):
        blockers.append(
            "CERTIFICATE_PAIR_INCOMPLETE: restore both original localhost files; setup will not replace either file."
        )
    elif cert_data is None:
        actions["certificates"] = (
            "Create a new missing localhost certificate/key pair; OS/browser trust requires separate approval."
        )
    else:
        try:
            launcher.legacy_https_context()
        except ImportError:
            blockers.append(
                "CERTIFICATE_VALIDATION_DEPENDENCY_REQUIRED: existing certificate inspection requires project dependencies; no file was changed."
            )
        except Exception:
            blockers.append(
                "CERTIFICATE_VALIDATION_REQUIRED: restore a valid existing localhost pair or use its project interpreter. On Windows inspect setup --repair-private-file frontend/certificates/localhost-key.pem --plan for explicit ACL narrowing; certificate trust still requires separate approval. No certificate will be replaced."
            )


def inspect_setup(args, launcher):
    """Return a secret-safe immutable plan; never prepare or connect to services."""
    snapshot, actions, blockers = _Snapshot(), {}, []
    requested = getattr(args, "profile", "auto")
    state_root = Path(launcher.GreenfieldStack.STATE)
    profile = (
        ("greenfield" if state_root.exists() or state_root.is_symlink() else "legacy")
        if requested == "auto"
        else requested
    )
    family = "managed"
    flags = {
        name: getattr(args, name, None)
        for name in (
            "profile",
            "legacy_config",
            "initialize_database",
            "migrate",
            "provision_greenfield",
            "frontend_build",
            "confirm_database",
            "postgres_provider",
            "redis_provider",
            "mailpit_provider",
            "repair_dependencies",
            "provision_local_postgres",
            "local_database",
            "local_postgres_port",
            "transition_database_credentials",
            "check_local_services",
            "local_mailpit_smtp_port",
            "local_mailpit_ui_port",
        )
    }
    values, fresh, phase = {}, False, "configuration selection"
    try:
        if profile not in {"legacy", "greenfield"}:
            raise _ObservationError("Unsupported development profile.")
        family = (
            launcher.select_legacy_configuration(getattr(args, "legacy_config", "auto"))
            if profile == "legacy"
            else "greenfield"
        )
        _scope_check([os.environ], blockers)
        phase = "dependency manifests and project interpreter"
        _dependencies(snapshot, launcher, actions, blockers)
        if getattr(args, "repair_dependencies", False):
            actions["project-dependencies"] = (
                "Repair project Python/npm dependencies from the pinned manifests after explicit consent; preserve private configuration and data."
            )
        phase = "runtime ownership records"
        _runtime(snapshot, launcher, blockers)
        if not any(item.startswith("RUNTIME_") for item in blockers):
            if profile == "legacy":
                phase = "saved configuration and authentication mode"
                values, fresh = _legacy_values(args, launcher, family, snapshot, actions, blockers)
                phase = "persistent Native keys"
                _keys(values, fresh, launcher, actions, blockers, native_default=family == "managed")
                phase = "localhost certificates and private-key ACL"
                _certificates(launcher, snapshot, actions, blockers)
                if getattr(args, "provision_greenfield", False) or getattr(args, "frontend_build", False):
                    blockers.append(
                        "PROFILE_OPTIONS_INVALID: Greenfield provisioning/build flags cannot prepare Legacy."
                    )
            elif not state_root.exists():
                if not getattr(args, "provision_greenfield", False):
                    blockers.append(
                        "GREENFIELD_SETUP_REQUIRED: new Greenfield state requires explicit provisioning and database confirmation."
                    )
                else:
                    launcher.LocalHttps.local_ca()  # Existing trusted CA only; never install trust.
                    actions.update(
                        configuration="Create a new protected Greenfield runtime configuration.",
                        secrets="Create fresh Greenfield credentials and independent keys for the new installation.",
                        certificates="Create a missing localhost leaf pair under the existing approved CA.",
                        **{
                            "data-providers": "Create the explicitly selected Greenfield containers and fresh data resources."
                        },
                    )
            else:
                launcher.resolve_profile("greenfield")
                cert, key, ca, _ = launcher.LocalHttps.ensure_certificate(state_root, prepare=False)
                for path in (cert, key, ca):
                    snapshot.read(path)
                private = {}
                for name in (
                    "environment.json",
                    "runtime-password",
                    "setup-password",
                    "security-mail-key",
                    "provider-storage-key",
                    "docker-identities.json",
                    "processes.json",
                ):
                    path = state_root / name
                    if path.exists() or path.is_symlink():
                        private[name] = launcher.GreenfieldStack.read_private(name)
                        snapshot.record(path, private[name].encode())
                    else:
                        snapshot.observed[str(path.absolute())] = "absent"
                values = json.loads(private["environment.json"])
                if not isinstance(values, dict) or any(
                    not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()
                ):
                    raise _ObservationError("Invalid protected configuration.")
                _scope_check([values], blockers)
                if "NATIVE_SECURITY_OUTBOX_KEY" not in values and "security-mail-key" in private:
                    values["NATIVE_SECURITY_OUTBOX_KEY"] = private["security-mail-key"]
                _keys(values, False, launcher, actions, blockers)
                if not values.get("AI_CONFIG_ENCRYPTION_KEY") and "provider-storage-key" not in private:
                    blockers.append("PERSISTENT_KEYS_MISSING: restore the original protected provider-storage key.")
                if "docker-identities.json" not in private:
                    blockers.append(
                        "GREENFIELD_IDENTITY_UNVERIFIED: restore the recorded container identities before preparation."
                    )
                processes = json.loads(private["processes.json"]) if "processes.json" in private else {}
                if not isinstance(processes, dict) or processes:
                    blockers.append(
                        "GREENFIELD_RUNTIME_REVIEW_REQUIRED: review shared installation process records before preparation."
                    )
                if getattr(args, "provision_greenfield", False):
                    blockers.append(
                        "GREENFIELD_ALREADY_PREPARED: preserve the existing installation; provisioning is not required."
                    )

        if not any(item.startswith("RUNTIME_") for item in blockers):
            phase = "frontend workspace ownership and configuration"
            try:
                current_workspace = dev_frontend.inspect_workspace(launcher, profile)
            except launcher.SetupError as error:
                if str(error).startswith("FRONTEND_WORKSPACE_SETUP_REQUIRED:"):
                    current_workspace = False
                else:
                    blockers.append(
                        "FRONTEND_WORKSPACE_REVIEW_REQUIRED: retain unknown frontend files/links and review their ownership before setup."
                    )
                    current_workspace = True
            for path in dev_frontend.configuration_inputs(launcher, profile):
                # An absent Greenfield parent is expected only for explicitly
                # authorized provisioning; no directory is created by inspection.
                snapshot.read(path)
            if not current_workspace or getattr(args, "repair_dependencies", False):
                actions["frontend-workspace"] = (
                    "Prepare an environment-free Next workspace with verified live source/dependency links and owned public configuration copies."
                )
        target_name = launcher.GreenfieldStack.DB if profile == "greenfield" else (getattr(args, "local_database", None) or launcher.DB_NAME)
        if profile == "legacy" and values.get("DATABASE_URL"):
            target_name = urlsplit(values["DATABASE_URL"]).path[1:]
        phase = "local PostgreSQL provisioning target and recovery record"
        local_provision = getattr(args, "provision_local_postgres", False)
        transition = getattr(args, "transition_database_credentials", False)
        local_selection = local_provision or transition or getattr(args, "local_database", None) or getattr(args, "local_postgres_port", None)
        for option in ("local_mailpit_smtp_port", "local_mailpit_ui_port"):
            port = getattr(args, option, None)
            if port is not None and (type(port) is not int or not 1 <= port <= 65535):
                blockers.append("MAILPIT_PORT_INVALID: select SMTP/UI ports from 1 to 65535.")
            saved_port = values.get("SMTP_PORT" if option == "local_mailpit_smtp_port" else "DEV_MAILPIT_UI_PORT")
            if port is not None and (not local_provision or (values and str(port) != saved_port)):
                blockers.append("MAILPIT_TARGET_PINNED: Mailpit port overrides require fresh local provisioning; existing saved service settings were retained.")
        if local_selection and (profile != "legacy" or family != "managed"):
            blockers.append("LOCAL_POSTGRES_PROFILE_REQUIRED: select --profile legacy --legacy-config managed for local PostgreSQL actions.")
        if local_provision:
            if not getattr(args, "initialize_database", False) or transition or getattr(args, "migrate", False):
                blockers.append("LOCAL_POSTGRES_ACTION_REQUIRED: provisioning requires --initialize-database and cannot be combined with migration or credential transition.")
            if getattr(args, "postgres_provider", None) == "docker":
                blockers.append("LOCAL_POSTGRES_PROVIDER_CONFLICT: select --postgres-provider local for Docker-free provisioning.")
            from_module = launcher._development_library("dev_local_postgres")
            from_module.validate_target(target_name, getattr(args, "local_postgres_port", None) or 5432)
            recovery = from_module.record_path(launcher)
            snapshot.read(recovery)
            if values and not recovery.is_file():
                blockers.append("LOCAL_POSTGRES_EXISTING_CONFIG: existing installations require --transition-database-credentials; provisioning cannot adopt them.")
            if recovery.is_file():
                record = from_module.read_record(launcher)
                if (record["database"], record["port"]) != (target_name, getattr(args, "local_postgres_port", None) or 5432):
                    blockers.append("LOCAL_POSTGRES_RECORD_TARGET_CHANGED: repeat the recorded database name and port; retain the recovery file.")
            actions["local-postgres-provision"] = f"Provision only absent PostgreSQL resources at 127.0.0.1:{getattr(args, 'local_postgres_port', None) or 5432}/{target_name} with separate {target_name}_setup and {target_name}_app roles; retain recovery credentials; administrator password stays in memory."
        elif getattr(args, "local_database", None) or getattr(args, "local_postgres_port", None):
            blockers.append("LOCAL_POSTGRES_PROVISION_REQUIRED: target overrides apply only to --provision-local-postgres; saved installations retain their target.")
        if transition:
            if not values.get("DATABASE_URL") or getattr(args, "initialize_database", False) or getattr(args, "migrate", False):
                blockers.append("CREDENTIAL_TRANSITION_REQUIRES_SAVED_TARGET: select an existing managed installation without initialization or migration.")
            actions["database-credentials"] = "Validate a separately provisioned runtime login for the exact saved target; back up original bytes and change only DATABASE_URL; keep all keys and certificates."
        if local_provision or getattr(args, "check_local_services", False):
            if profile != "legacy" or family != "managed":
                blockers.append("LOCAL_SERVICE_PROFILE_REQUIRED: select --profile legacy --legacy-config managed for disposable local service checks.")
            actions["local-service-checks"] = "Check local Redis/Garnet Lua, Celery and session commands using only disposable expiring keys; validate loopback Mailpit without sending email."
            if local_provision and fresh:
                actions["local-service-checks"] += " Fresh configuration uses database zero and unique queue/session/rate-limit namespaces; existing installations keep their saved layout."
        database_action = transition or any(
            getattr(args, name, False) for name in ("initialize_database", "migrate", "provision_greenfield")
        )
        if getattr(args, "initialize_database", False) and getattr(args, "migrate", False):
            blockers.append("DATABASE_ACTION_CONFLICT: choose empty initialization or migration, never both.")
        for service in ("postgres", "redis", "mailpit"):
            selected = getattr(args, service + "_provider", None)
            if selected not in {None, "local", "docker"}:
                blockers.append("PROVIDER_SELECTION_INVALID: dependency providers must be explicit local or docker.")
            if profile == "greenfield" and selected == "local":
                blockers.append(
                    "GREENFIELD_PROVIDER_CONFLICT: the existing Greenfield profile cannot be converted to local data providers."
                )
            saved = values.get("DEV_" + service.upper() + "_PROVIDER")
            if selected and saved and selected != saved:
                blockers.append(
                    "PROVIDER_CHANGE_REVIEW_REQUIRED: saved dependency providers cannot be silently converted."
                )
            # Legacy selection only authorizes reuse of an already-running
            # dependency. It never implies container/volume creation or resume;
            # the apply callback verifies availability before using it.
        if database_action and getattr(args, "confirm_database", None) != target_name:
            blockers.append(
                "DATABASE_CONFIRMATION_REQUIRED: repeat the exact selected local database name before any setup change."
            )
        if getattr(args, "confirm_database", None) and not database_action:
            blockers.append(
                "DATABASE_ACTION_REQUIRED: database confirmation alone does not select an authorized operation."
            )
        if getattr(args, "initialize_database", False):
            actions["database-initialize"] = (
                "Initialize only the explicitly confirmed fresh empty development database; never reset existing content. Recorded local setup requires an administrator-approved, expiring login window; disable its login/password and close only its setup-role sessions on exit."
            )
        elif profile == "greenfield" and getattr(args, "provision_greenfield", False):
            actions["database-initialize"] = (
                "Create only the explicitly confirmed new Greenfield PostgreSQL data resources; application schema initialization requires its separate explicit flag."
            )
        if getattr(args, "migrate", False):
            actions["database-migrate"] = (
                "Run only the explicitly confirmed reviewed migration path, retaining all existing safeguards. Recorded local setup requires an administrator-approved, expiring login window; disable its login/password and close only its setup-role sessions on exit."
            )
        if getattr(args, "frontend_build", False):
            actions["frontend-build"] = "Build the selected isolated Greenfield frontend workspace."
    except ImportError:
        blockers.append(
            "INSPECTION_DEPENDENCY_REQUIRED: existing configuration inspection requires project dependencies; no preparation occurred."
        )
    except Exception as error:
        code = getattr(error, "code", None)
        safe_code = code if isinstance(code, str) and code.isascii() and code.replace("_", "").isalnum() and len(code) <= 80 else "INPUT_UNVERIFIED"
        blockers.append(
            f"SETUP_INSPECTION_BLOCKED: {phase} ({safe_code}). Review that exact setup input and rerun setup --plan; no preparation occurred."
        )
    scope = {key: os.environ[key] for key in ("APP_ENVIRONMENT", "APP_ENV") if key in os.environ}
    identity = {
        "root": str(Path(launcher.ROOT).absolute()),
        "profile": profile,
        "family": family,
        "flags": flags,
        "scope": scope,
        "observed": snapshot.observed,
    }
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return SetupPlan(
        profile,
        family,
        tuple(SetupAction(name, description) for name, description in actions.items()),
        tuple(dict.fromkeys(blockers)),
        fingerprint,
    )


def _in_project_venv(launcher):
    return Path(launcher.sys.prefix).resolve() == Path(launcher.VENV).resolve()


def _handoff_lineage(parent_pid, launcher):
    """Bind approval to the consenting launcher: this process or its parent.

    On Windows, ``.venv\\Scripts\\python.exe`` is a redirector that runs the base
    interpreter as its own child, so the consenting launcher is the grandparent.
    Accept that only through this project's redirector, using pinned process
    identities; any inspection failure keeps the refusal.
    """
    if parent_pid in {os.getpid(), os.getppid()}:
        return True
    if launcher.sys.platform != "win32" or not _in_project_venv(launcher):
        return False
    try:
        lineage = {info["pid"]: info for info in launcher.windows_children(parent_pid)}
        redirector = lineage.get(os.getppid())
        return (
            os.getpid() in lineage
            and redirector is not None
            and os.path.normcase(str(Path(redirector["exe"]).resolve()))
            == os.path.normcase(str(Path(launcher.venv_python()).resolve()))
        )
    except Exception:
        return False


def _approval(marker, plan, launcher):
    try:
        value = json.loads(marker)
        categories = frozenset(value["categories"])
        if (
            not isinstance(value, dict)
            or value["fingerprint"] != plan.fingerprint
            or type(value["parent_pid"]) is not int
            or not _handoff_lineage(value["parent_pid"], launcher)
            or not categories <= _CATEGORIES
            or not {action.category for action in plan.actions} <= categories
        ):
            raise ValueError()
        return categories
    except (ValueError, TypeError, KeyError):
        return None


def _report_retained_preparation():
    print(
        "[WARN] SETUP_PARTIAL_PREPARATION: preparation did not finish. Any authorized project/private artifacts already created were retained; no rollback or deletion was attempted. Review diagnose and a new setup plan before recovery.",
        flush=True,
    )


def run_setup(args, launcher, apply_callback):
    """Display, authorize and revalidate a plan before delegating preparation."""
    inherited = os.environ.pop(APPROVAL_ENV, None)
    try:
        if getattr(args, "repair_private_file", None):
            if any(getattr(args, name, False) for name in (
                "provision_local_postgres", "local_database", "local_postgres_port", "transition_database_credentials",
                "check_local_services", "initialize_database", "migrate", "provision_greenfield", "frontend_build", "repair_dependencies",
                "confirm_database", "postgres_provider", "redis_provider", "mailpit_provider",
                "local_mailpit_smtp_port", "local_mailpit_ui_port",
            )):
                raise launcher.SetupError("ACL_REPAIR_SEPARATE_ACTION: review exact private-file ACL repair separately from other preparation actions.")
            return launcher._development_library("dev_acl_repair").run(args, launcher)
        plan = inspect_setup(args, launcher)
        print(f"[PLAN] Setup: {plan.profile}/{plan.family}; no changes have been applied.", flush=True)
        if plan.profile == "legacy":
            print(
                "[INFO] Legacy dependencies: reuse only already-running explicitly selected local/Docker services; setup never creates or resumes Legacy containers.",
                flush=True,
            )
            if launcher.sys.platform == "win32":
                print("[INFO] Windows without Docker: install PostgreSQL, a Redis-compatible service with Lua enabled, and Mailpit. Start services on loopback only. Mailpit: mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025. TLS certificate trust is a separate explicit OS action.", flush=True)
        for action in plan.actions:
            print(f"[PLAN] {action.category}: {action.description}", flush=True)
        for blocker in plan.blockers:
            print("[BLOCKED] " + blocker, flush=True)
        dependency_codes = {
            "KEY_VALIDATION_DEPENDENCY_REQUIRED",
            "CERTIFICATE_VALIDATION_DEPENDENCY_REQUIRED",
            "INSPECTION_DEPENDENCY_REQUIRED",
        }
        if (
            plan.blockers
            and all(item.partition(":")[0] in dependency_codes for item in plan.blockers)
            and not _in_project_venv(launcher)
            and launcher.venv_python().is_file()
            and hasattr(launcher, "require_virtualenv")
        ):
            print(
                "[INFO] Setup: continuing read-only inspection in the existing project interpreter; nothing was prepared."
            )
            return launcher.require_virtualenv() or 1
        if getattr(args, "plan", False) or plan.blockers:
            return int(bool(plan.blockers))
        categories = _approval(inherited, plan, launcher) if inherited is not None else None
        if inherited is not None and categories is None:
            print(
                "[BLOCKED] SETUP_APPROVAL_INVALID: preparation inputs or handoff identity changed; review a new plan."
            )
            return 1
        if not plan.actions:
            print("[PASS] Setup: existing preparation is reusable; no changes are required.")
            return 0
        if categories is None:
            if not launcher.sys.stdin.isatty():
                print(
                    "[BLOCKED] SETUP_APPROVAL_REQUIRED: review this plan in an interactive terminal; nothing was prepared."
                )
                return 1
            try:
                for action in plan.actions:
                    if input(f"Authorize {action.category}? Type yes to approve: ").strip().lower() != "yes":
                        print("[INFO] SETUP_DECLINED: no preparation was performed.")
                        return 1
            except (EOFError, KeyboardInterrupt):
                print("[INFO] SETUP_CANCELLED: no preparation was performed.")
                return 130
            categories = frozenset(action.category for action in plan.actions)
        current = inspect_setup(args, launcher)
        if (
            current.blockers
            or current.fingerprint != plan.fingerprint
            or not {action.category for action in current.actions} <= categories
        ):
            print(
                "[BLOCKED] SETUP_PLAN_CHANGED: inputs changed after inspection; review a new plan before preparation."
            )
            return 1
        previous = getattr(args, "_setup_authorized_categories", _MISSING)
        previous_profile = getattr(args, "profile", "auto")
        previous_family = getattr(args, "legacy_config", "auto")
        args._setup_authorized_categories = frozenset(action.category for action in current.actions)
        args.profile = current.profile
        if current.profile == "legacy":
            args.legacy_config = current.family
        try:
            if not _in_project_venv(launcher):
                os.environ[APPROVAL_ENV] = json.dumps(
                    {"fingerprint": current.fingerprint, "categories": sorted(categories), "parent_pid": os.getpid()}
                )
            try:
                result = apply_callback(args) or 0
            except SystemExit as error:
                if error.code not in (None, 0):
                    _report_retained_preparation()
                raise
            except BaseException:
                _report_retained_preparation()
                raise
            if result:
                _report_retained_preparation()
            return result
        finally:
            os.environ.pop(APPROVAL_ENV, None)
            if previous is _MISSING:
                if hasattr(args, "_setup_authorized_categories"):
                    delattr(args, "_setup_authorized_categories")
            else:
                args._setup_authorized_categories = previous
            args.profile = previous_profile
            args.legacy_config = previous_family
    finally:
        os.environ.pop(APPROVAL_ENV, None)
