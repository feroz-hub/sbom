"""Start the complete local Native IAM stack with one command."""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".env.dev.local"
VENV = ROOT / ".venv"
DB_NAME = "sbom_analyser_dev"
POSTGRES_PORT = 55439
REDIS_PORT = 56379
MAILPIT_SMTP_PORT = 1025
MAILPIT_UI_PORT = 8025
DEV_API_PORT = 18000
DEV_FRONTEND_PORT = 13000
BEAT_LOCK = ROOT / ".dev-beat.pid"
VERBOSE = False


class SetupError(Exception):
    """A local prerequisite needs developer attention."""


def say(kind: str, name: str, value: str) -> None:
    print(f"[{kind}] {name:<18} {value}", flush=True)


def run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if VERBOSE:
        print(redact(result.stdout, env), end="", flush=True)
        print(redact(result.stderr, env), end="", file=sys.stderr, flush=True)
    return result


def redact(output: str | None, env: dict[str, str] | None) -> str:
    text = output or ""
    for key, value in (env or os.environ).items():
        if (
            value
            and len(value) >= 4
            and any(word in key.upper() for word in ("PASSWORD", "SECRET", "KEY", "TOKEN", "DATABASE_URL"))
        ):
            text = text.replace(value, "[REDACTED]")
        if key.upper().endswith("_URL") and value:
            try:
                password = urlsplit(value).password
            except ValueError:
                password = None
            if password and len(password) >= 4:
                text = text.replace(password, "[REDACTED]")
    return text


def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def service_available(service: str, port: int) -> bool:
    """A listening port must actually answer as the expected service."""
    if service == "mailpit":
        return reachable("127.0.0.1", port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
            connection.settimeout(1)
            if service == "postgres":
                connection.sendall(struct.pack("!II", 8, 80877103))
                return connection.recv(1) in (b"S", b"N")
            if service == "redis":
                connection.sendall(b"*1\r\n$4\r\nPING\r\n")
                reply = b""
                while not reply.endswith(b"\r\n") and len(reply) < 64:
                    chunk = connection.recv(64)
                    if not chunk:
                        break
                    reply += chunk
                return reply == b"+PONG\r\n"
    except OSError:
        return False
    return False


def mailpit_ready() -> bool:
    try:
        with urlopen(f"http://127.0.0.1:{MAILPIT_UI_PORT}/api/v1/info", timeout=2) as response:
            return response.status == 200 and "Version" in json.load(response)
    except (OSError, ValueError):
        return False


def docker_available() -> bool:
    return bool(shutil.which("docker") and run(["docker", "info"]).returncode == 0)


def compose_container(service: str) -> bool:
    result = run(["docker", "compose", "ps", "-q", service])
    if result.returncode != 0 or not result.stdout.strip():
        return False
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", result.stdout.strip()])
    if state.returncode != 0 or state.stdout.strip() != "true":
        return False
    internal, expected = {
        "postgres": (5432, POSTGRES_PORT),
        "redis": (6379, REDIS_PORT),
        "mailpit": (1025, MAILPIT_SMTP_PORT),
    }[service]
    mapped = run(["docker", "compose", "port", service, str(internal)])
    if mapped.returncode or not mapped.stdout.strip().endswith(f":{expected}"):
        raise SetupError(
            f"Project {service} is running without expected host port {expected}. Check its mapping or a port conflict; no container was changed."
        )
    return True


def legacy_redis_container() -> bool:
    """Recognize the older SBOM Native Redis container by exact name and port."""
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", "sbom-native-redis"])
    if state.returncode or state.stdout.strip() != "true":
        return False
    mapped = run(["docker", "port", "sbom-native-redis", "6379"])
    return (
        mapped.returncode == 0
        and mapped.stdout.strip() == f"127.0.0.1:{REDIS_PORT}"
        and service_available("redis", REDIS_PORT)
    )


def start_compose(service: str, env: dict[str, str]) -> None:
    result = run(["docker", "compose", "up", "-d", service], env=env)
    if result.returncode and not compose_container(service):
        # Docker Desktop can report a transient container-start failure.
        time.sleep(1)
        result = run(["docker", "compose", "up", "-d", service], env=env)
    if result.returncode and not compose_container(service):
        raise SetupError(f"Could not start project {service} service. Check Docker Compose and its fixed port.")


def wait_for_service(service: str, port: int) -> bool:
    for _ in range(20):
        if service_available(service, port):
            return True
        time.sleep(0.5)
    return False


def select_service(
    service: str, docker_port: int, local_port: int, *, check: bool, env: dict[str, str], preferred: str | None = None
) -> tuple[str, int]:
    """Reuse the saved provider; choose another only when it is unavailable."""
    if preferred not in (None, "docker", "local"):
        raise SetupError(f"Saved {service} provider must be docker or local.")
    docker = docker_available()
    order = ("local", "docker") if preferred == "local" else ("docker", "local")
    for provider in order:
        if provider == "local":
            if service_available(service, local_port):
                return "local", local_port
            continue
        if not docker:
            continue
        if service == "redis" and legacy_redis_container():
            return "Docker (sbom-native-redis)", docker_port
        if compose_container(service):
            if wait_for_service(service, docker_port):
                return "Docker", docker_port
            raise SetupError(
                f"Project {service} is running but port {docker_port} is unreachable. Check its port mapping."
            )
        if reachable("127.0.0.1", docker_port):
            if service_available(service, local_port) and local_port != docker_port:
                continue
            raise SetupError(
                f"Port {docker_port} is occupied, so project {service} cannot start. Stop the owner of that port or use a local {service} service. No process was changed."
            )
        if check:
            return "Docker (available to start)", docker_port
        try:
            start_compose(service, env)
        except SetupError:
            if service_available(service, local_port) and local_port != docker_port:
                continue
            raise
        if wait_for_service(service, docker_port):
            return "Docker", docker_port
        raise SetupError(f"Project {service} started but port {docker_port} is unreachable. Check Docker port mapping.")
    raise SetupError(
        f"{service.title()} is unavailable. Install/start it locally or install/start Docker Desktop, then rerun python scripts/dev.py."
    )


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_virtualenv() -> None:
    if not venv_python().exists():
        result = run([sys.executable, "-m", "venv", str(VENV)])
        if result.returncode:
            raise SetupError("Could not create .venv. Install Python 3.11+ with venv support.")
    if Path(sys.prefix).resolve() != VENV.resolve():
        command = [str(venv_python()), str(Path(__file__).resolve()), *sys.argv[1:]]
        if sys.platform == "win32":
            # Windows execv can release the shell while the new Python still
            # reads its console. Keep this parent alive, with inherited stdio
            # and the same console group so Ctrl+C reaches the child directly.
            # A Python handler (not SIG_IGN) avoids inheriting ignored Ctrl+C.
            previous_handler = signal.signal(signal.SIGINT, lambda signum, frame: None)
            try:
                child = subprocess.Popen(command)
                raise SystemExit(child.wait())
            finally:
                signal.signal(signal.SIGINT, previous_handler)
        os.execv(command[0], command)


def ensure_dependencies() -> None:
    """Install only when the requirements file changes or core imports are missing."""
    import hashlib

    stamp = VENV / ".sbom-requirements-sha256"
    digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes()).hexdigest()
    try:
        import alembic  # noqa: F401
        import cryptography  # noqa: F401
        import psycopg  # noqa: F401
        import uvicorn  # noqa: F401

        installed = stamp.exists() and stamp.read_text().strip() == digest
    except ImportError:
        installed = False
    if installed:
        return
    say("...", "Dependencies", "installing requirements.txt")
    result = run([str(venv_python()), "-m", "pip", "install", "-r", "requirements.txt"])
    if result.returncode:
        raise SetupError("Python dependency installation failed. Check pip output above.")
    stamp.write_text(digest)


def read_config(path: Path = CONFIG) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if not separator or not key.isidentifier():
            raise SetupError(".env.dev.local is malformed. Fix its KEY=VALUE lines.")
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SetupError(f".env.dev.local has an invalid value for {key}.") from exc
            if not isinstance(value, str):
                raise SetupError(f".env.dev.local value {key} must be a string.")
        else:
            value = raw
        values[key] = value
    return values


def write_config(values: dict[str, str], path: Path = CONFIG) -> None:
    # Replace atomically so interrupted setup cannot leave half a keypair.
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("# Local Native IAM development only. Never commit this file.\n")
            for key, value in sorted(values.items()):
                stream.write(f"{key}={json.dumps(value)}\n")
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def generate_keys(values: dict[str, str]) -> None:
    has_private = "NATIVE_JWT_PRIVATE_KEY" in values
    has_public = "NATIVE_JWT_PUBLIC_KEY" in values
    if has_private != has_public:
        raise SetupError("Local JWT keypair is incomplete. Restore both keys in .env.dev.local before continuing.")
    if not has_private:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        values["NATIVE_JWT_PRIVATE_KEY"] = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        values["NATIVE_JWT_PUBLIC_KEY"] = (
            private.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
    for key in ("NATIVE_SECURITY_OUTBOX_KEY", "AUTH_SESSION_ENCRYPTION_KEY"):
        values.setdefault(key, base64.b64encode(secrets.token_bytes(32)).decode())
    validate_secrets(values)


def validate_secrets(values: dict[str, str]) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        private = serialization.load_pem_private_key(values["NATIVE_JWT_PRIVATE_KEY"].encode(), password=None)
        public = serialization.load_pem_public_key(values["NATIVE_JWT_PUBLIC_KEY"].encode())
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size < 2048:
            raise ValueError()
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
            raise ValueError()
        if private.public_key().public_numbers() != public.public_numbers():
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise SetupError(
            "Local Native JWT keypair is invalid or does not match. Restore .env.dev.local from a safe copy."
        ) from None
    for name in ("NATIVE_SECURITY_OUTBOX_KEY", "AUTH_SESSION_ENCRYPTION_KEY"):
        try:
            encoded = values[name]
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode() != encoded:
                raise ValueError()
        except (KeyError, ValueError, TypeError, binascii.Error):
            raise SetupError(f"{name} must be a valid 32-byte base64 key in .env.dev.local.") from None


def validate_database_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise SetupError(
            f"DATABASE_URL must target local PostgreSQL database {DB_NAME}; refusing another database."
        ) from None
    if (
        parsed.scheme != "postgresql+psycopg"
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or parsed.path != "/" + DB_NAME
        or not port
        or parsed.query
        or parsed.fragment
    ):
        raise SetupError(f"DATABASE_URL must target local PostgreSQL database {DB_NAME}; refusing another database.")


def provider_name(label: str) -> str:
    return "docker" if label.startswith("Docker") else "local"


def default_database_url(provider: str, port: int) -> str:
    user = "sbom" if provider == "docker" else "postgres"
    password = "sbom" if provider == "docker" else ""
    return f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}@127.0.0.1:{port}/{DB_NAME}"


def local_database_url(user: str, password: str, port: int) -> str:
    return (
        f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@127.0.0.1:{port}/{DB_NAME}"
    )


def repository_database_candidate(path: Path, port: int) -> str | None:
    """Reuse only credentials from a repository URL for this local server."""
    if not path.exists():
        return None
    from dotenv import dotenv_values

    raw = dotenv_values(path).get("DATABASE_URL")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = urlsplit(raw)
        source_port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"postgresql", "postgresql+psycopg"}
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or source_port != port
        or parsed.username is None
        or parsed.query
        or parsed.fragment
    ):
        return None
    return local_database_url(unquote(parsed.username), unquote(parsed.password or ""), port)


def default_pgpass_path(
    *,
    platform_name: str | None = None,
    environment: dict[str, str] | None = None,
    home: Path | None = None,
) -> Path | None:
    platform_name = platform_name or os.name
    environment = environment if environment is not None else os.environ
    if platform_name == "nt":
        appdata = environment.get("APPDATA")
        return Path(appdata) / "postgresql" / "pgpass.conf" if appdata else None
    return (home or Path.home()) / ".pgpass"


def split_pgpass_line(line: str) -> list[str]:
    fields = [""]
    escaped = False
    for character in line:
        if escaped:
            fields[-1] += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("")
        else:
            fields[-1] += character
    if escaped:
        fields[-1] += "\\"
    return fields


def pgpass_database_candidates(path: Path | None, port: int) -> list[str]:
    if path is None or not path.is_file():
        return []
    candidates = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw_line in lines:
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = split_pgpass_line(raw_line)
        if len(fields) != 5:
            continue
        host, saved_port, database, user, password = fields
        if (
            host not in {"localhost", "127.0.0.1", "*"}
            or saved_port not in {str(port), "*"}
            or database not in {DB_NAME, "*"}
            or not user
            or user == "*"
        ):
            continue
        candidates.append(local_database_url(user, password, port))
    return candidates


def read_password(prompt: str) -> str:
    if sys.platform != "win32":
        return getpass.getpass(prompt)

    import msvcrt

    print(prompt, end="", flush=True)
    characters: list[str] = []
    try:
        while True:
            character = msvcrt.getwch()
            if character in {"\x00", "\xe0"}:
                msvcrt.getwch()  # Discard the scan code following a special key.
            elif character in {"\r", "\n"}:
                return "".join(characters)
            elif character == "\x03":
                raise KeyboardInterrupt
            elif character in {"\x1a", ""}:
                raise EOFError
            elif character == "\b":
                if characters:
                    characters.pop()
                    print("\b \b", end="", flush=True)
            elif character.isprintable():
                characters.append(character)
                print("*", end="", flush=True)
    finally:
        print()


def read_postgres_credentials(
    default_user: str = "postgres", *, input_fn=input, password_fn=None,
) -> tuple[str, str]:
    try:
        user = input_fn(f"PostgreSQL user [{default_user}]: ").strip() or default_user
        password = (password_fn or read_password)("PostgreSQL password: ")
        return user, password
    except (KeyboardInterrupt, EOFError):
        raise SetupError("PostgreSQL credential entry cancelled. Rerun the launcher to try again.") from None


def resolve_local_database_url(
    saved_url: str | None,
    port: int,
    *,
    repository_env: Path,
    pgpass_path: Path | None,
    interactive: bool,
    input_fn=input,
    password_fn=None,
) -> str:
    candidates = []
    if saved_url:
        validate_database_url(saved_url)
        candidates.append(saved_url)
    else:
        repository_url = repository_database_candidate(repository_env, port)
        if repository_url:
            candidates.append(repository_url)
        candidates.extend(pgpass_database_candidates(pgpass_path, port))
        candidates.append(default_database_url("local", port))

    for candidate in dict.fromkeys(candidates):
        try:
            ensure_database(candidate)
            return candidate
        except SetupError:
            pass

    if not interactive:
        raise SetupError(
            f"PostgreSQL credentials are required for {DB_NAME}. Run python scripts/dev.py in an interactive terminal."
        )

    print(f"[INFO] Local PostgreSQL detected at 127.0.0.1:{port}")
    print(f"[INFO] PostgreSQL credentials are required for {DB_NAME}.")
    for attempt in range(3):
        user, password = read_postgres_credentials(input_fn=input_fn, password_fn=password_fn)
        candidate = local_database_url(user, password, port)
        try:
            ensure_database(candidate)
            return candidate
        except SetupError:
            if attempt < 2:
                print("[ERROR] PostgreSQL credentials were not accepted or cannot create the development database. Try again.")
    raise SetupError("PostgreSQL credentials were not accepted after 3 attempts. Check the local login and rerun.")


def configure_local_database(
    values: dict[str, str],
    saved: dict[str, str],
    port: int,
    *,
    config_path: Path = CONFIG,
    repository_env: Path | None = None,
    pgpass_path: Path | None = None,
    interactive: bool,
    input_fn=input,
    password_fn=None,
) -> None:
    saved_url = saved.get("DATABASE_URL") if saved.get("DATABASE_URL") == values.get("DATABASE_URL") else None
    values["DATABASE_URL"] = resolve_local_database_url(
        saved_url,
        port,
        repository_env=repository_env or ROOT / ".env",
        pgpass_path=pgpass_path if pgpass_path is not None else default_pgpass_path(),
        interactive=interactive,
        input_fn=input_fn,
        password_fn=password_fn,
    )
    if values != saved:
        write_config(values, config_path)


def resolve_config(
    saved: dict[str, str],
    pg_port: int,
    redis_port: int,
    smtp_port: int,
    pg_provider: str | None = None,
    redis_provider: str | None = None,
) -> dict[str, str]:
    values = dict(saved)
    pg_provider = pg_provider or ("docker" if pg_port == POSTGRES_PORT else "local")
    redis_provider = redis_provider or ("docker" if redis_port == REDIS_PORT else "local")
    previous_provider = saved.get("DEV_POSTGRES_PROVIDER")
    if "DATABASE_URL" in values:
        validate_database_url(values["DATABASE_URL"])
    if "DATABASE_URL" not in values or (previous_provider and previous_provider != pg_provider):
        values["DATABASE_URL"] = default_database_url(pg_provider, pg_port)
    elif urlsplit(values["DATABASE_URL"]).port != pg_port:
        raise SetupError(
            "Saved DATABASE_URL points to a different local PostgreSQL port. Check .env.dev.local before continuing."
        )
    values["DEV_POSTGRES_PROVIDER"] = pg_provider
    values["DEV_REDIS_PROVIDER"] = redis_provider
    # Local mode is explicit so a checked-in .env cannot turn on HCL or a remote mailer.
    fixed = {
        "DEV_API_PORT": str(DEV_API_PORT),
        "DEV_FRONTEND_PORT": str(DEV_FRONTEND_PORT),
        "AUTH_ENABLED": "true",
        "HCL_AUTH_ENABLED": "false",
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
        "APP_ORIGIN": f"https://localhost:{DEV_FRONTEND_PORT}",
        "NATIVE_ACTIVATION_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/activate-account",
        "NATIVE_PASSWORD_RESET_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/reset-password",
        "EMAIL_VERIFICATION_FRONTEND_URL": f"https://localhost:{DEV_FRONTEND_PORT}/verify-email",
        "NATIVE_JWT_ISSUER": f"https://localhost:{DEV_FRONTEND_PORT}/native",
        "NATIVE_JWT_AUDIENCE": "sbom-analyser-api",
        "NATIVE_JWT_ACTIVE_KID": "native-dev",
        "NATIVE_JWT_ALGORITHM": "RS256",
        "EMAIL_PROVIDER": "smtp",
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_FROM_ADDRESS": "sbom-dev@localhost.test",
        "EMAIL_FROM_NAME": "SBOM Analyzer",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(smtp_port),
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
        "SMTP_USE_TLS": "false",
        "SMTP_USE_STARTTLS": "false",
        "CORS_ORIGINS": f"https://localhost:{DEV_FRONTEND_PORT}",
        "SBOM_API_URL": f"http://127.0.0.1:{DEV_API_PORT}",
        "NEXT_PUBLIC_AUTH_ENABLED": "true",
        "NEXT_PUBLIC_HCL_AUTH_ENABLED": "false",
        "NEXT_PUBLIC_API_URL": f"http://127.0.0.1:{DEV_API_PORT}",
        "NEXT_PUBLIC_HCL_IAM_ISSUER": "",
        "NEXT_PUBLIC_HCL_IAM_CLIENT_ID": "",
        "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        "CELERY_BROKER_URL": f"redis://127.0.0.1:{redis_port}/0",
        "CELERY_RESULT_BACKEND": f"redis://127.0.0.1:{redis_port}/0",
        "AUTH_SESSION_REDIS_URL": f"redis://127.0.0.1:{redis_port}/1",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI": f"redis://127.0.0.1:{redis_port}/2",
    }
    values.update(fixed)
    values.setdefault("NATIVE_PLATFORM_BOOTSTRAP_ENABLED", "false")
    return values


def ensure_database(url: str) -> None:
    import psycopg

    validate_database_url(url)
    parsed = urlsplit(url)
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=parsed.port,
            user=user,
            password=password,
            dbname="postgres",
            connect_timeout=3,
            autocommit=True,
        ) as connection:
            row = connection.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)).fetchone()
            if not row:
                connection.execute(f'CREATE DATABASE "{DB_NAME}"')
    except psycopg.Error as exc:
        raise SetupError(
            "Cannot access/create the local development database. Check PostgreSQL credentials in .env.dev.local."
        ) from exc


def check_schema_objects(objects: set[str], revision: str | None, known_revisions: set[str]) -> None:
    if not objects:
        return
    if not {"alembic_version", "iam_users", "tenants"}.issubset(objects) or revision not in known_revisions:
        raise SetupError(
            "Existing sbom_analyser_dev has an unknown or incomplete schema. Alembic was not run; inspect this database before continuing."
        )


def validate_existing_schema(url: str) -> None:
    """Refuse to migrate an unrelated database that happens to have the dev name."""
    import psycopg
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    validate_database_url(url)
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    known = {revision.revision for revision in script.walk_revisions()}
    try:
        with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://", 1)) as connection:
            rows = connection.execute(
                "SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' "
                "AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')"
            ).fetchall()
            objects = {name for _, name in rows}
            public_objects = {name for schema, name in rows if schema == "public"}
            revisions = (
                [row[0] for row in connection.execute("SELECT version_num FROM public.alembic_version")]
                if "alembic_version" in public_objects
                else []
            )
    except psycopg.Error as exc:
        raise SetupError("Could not inspect the development database schema before Alembic.") from exc
    check_schema_objects(public_objects if objects else set(), revisions[0] if len(revisions) == 1 else None, known)
    if objects and not public_objects:
        raise SetupError("Existing sbom_analyser_dev has an unknown non-empty schema. Alembic was not run.")


def run_migrations(env: dict[str, str]) -> str:
    result = run([str(venv_python()), "-m", "alembic", "upgrade", "head"], env=env)
    if result.returncode:
        raise SetupError("Alembic upgrade failed for the development database. Run with --verbose to inspect it.")
    import psycopg
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    with psycopg.connect(env["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)) as connection:
        current = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    if not current or current[0] != head:
        raise SetupError("Development database did not reach the current Alembic head.")
    return head


def ensure_frontend() -> str:
    npm = shutil.which("npm")
    if not npm:
        raise SetupError("Node.js/npm is missing. Install Node.js, then rerun python scripts/dev.py.")
    if not (ROOT / "frontend/node_modules").exists():
        say("...", "Frontend", "installing npm dependencies")
        result = run([npm, "ci", "--prefix", "frontend"])
        if result.returncode:
            raise SetupError("Frontend npm ci failed. Check npm output above.")
    cert = ROOT / "frontend/certificates/localhost.pem"
    key = ROOT / "frontend/certificates/localhost-key.pem"
    if not cert.exists() or not key.exists():
        create_local_certificate(cert, key)
        say("NOTE", "HTTPS", "self-signed local certificate; trust it in your browser")
    return npm


def create_local_certificate(cert: Path, key: Path) -> None:
    """Create the same localhost certificate files consumed by dev:https."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .sign(private, hashes.SHA256())
    )
    cert.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(
            private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def acquire_beat_lock() -> None:
    try:
        fd = os.open(BEAT_LOCK, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            pid = int(BEAT_LOCK.read_text())
            os.kill(pid, 0)
        except (ValueError, ProcessLookupError):
            BEAT_LOCK.unlink(missing_ok=True)
            return acquire_beat_lock()
        raise SetupError("A dev launcher already owns Celery Beat. Stop it before starting another.")
    with os.fdopen(fd, "w") as stream:
        stream.write(str(os.getpid()))


def log_path(name: str) -> Path:
    return ROOT / ".dev-logs" / (name.lower().replace(" ", "-") + ".log")


def show_log(name: str, env: dict[str, str]) -> None:
    path = log_path(name)
    if VERBOSE and path.exists():
        print(redact(path.read_text(errors="replace"), env), file=sys.stderr)


def http_ready(url: str, *, json_ready: bool = False) -> bool:
    try:
        context = ssl._create_unverified_context() if url.startswith("https://localhost:") else None
        with urlopen(url, timeout=1, context=context) as response:
            if not 200 <= response.status < 400:
                return False
            return not json_ready or json.load(response).get("ready") is True
    except (OSError, ValueError):
        return False


def check_application_ports(api_port: int, frontend_port: int) -> None:
    occupied = [
        str(port)
        for port in (api_port, frontend_port)
        if any(reachable(host, port) for host in ("127.0.0.1", "::1"))
    ]
    if not occupied:
        return
    try:
        owner = int(BEAT_LOCK.read_text())
        os.kill(owner, 0)
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        owner = None
    if (
        owner
        and http_ready(f"http://127.0.0.1:{api_port}/health")
        and http_ready(f"http://127.0.0.1:{api_port}/ready/iam", json_ready=True)
    ):
        raise SetupError(
            f"An SBOM dev launcher appears to be running (PID {owner}). Stop it with Ctrl+C in its terminal."
        )
    raise SetupError(
        f"Development port(s) {', '.join(occupied)} are unavailable because they are occupied by another or "
        "unrecognized process. Stop that process, then rerun python scripts/dev.py. Nothing was killed."
    )


def wait_for_ready(
    processes: list[subprocess.Popen],
    env: dict[str, str],
    api_port: int,
    frontend_port: int,
    timeout: int = 60,
) -> None:
    checks = (
        ("API", f"http://127.0.0.1:{api_port}/health", False),
        ("API", f"http://127.0.0.1:{api_port}/ready/iam", True),
        ("Frontend", f"https://localhost:{frontend_port}", False),
    )
    names = ("API", "Celery worker", "Celery Beat", "Frontend")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, process in zip(names, processes, strict=True):
            if process.poll() is not None:
                show_log(name, env)
                raise SetupError(f"{name} exited during startup. See {log_path(name).relative_to(ROOT)}.")
        if all(http_ready(url, json_ready=needs_ready) for _, url, needs_ready in checks):
            return
        time.sleep(0.5)
    for name, url, needs_ready in checks:
        if not http_ready(url, json_ready=needs_ready):
            show_log(name, env)
            raise SetupError(f"{url} did not become ready. See {log_path(name).relative_to(ROOT)}.")


def start_process(name: str, command: list[str], env: dict[str, str], cwd: Path = ROOT) -> subprocess.Popen:
    path = log_path(name)
    path.parent.mkdir(exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    kwargs = {"cwd": cwd, "env": env, "stdout": fd, "stderr": subprocess.STDOUT}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **kwargs)
    finally:
        os.close(fd)
    say("OK", name, f"running (pid {process.pid})")
    return process


def stop_processes(processes: list[subprocess.Popen]) -> None:
    for process in reversed(processes):
        if process.poll() is not None:
            continue
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)


def main() -> None:
    global VERBOSE
    parser = argparse.ArgumentParser(description="Start local SBOM Analyzer development")
    parser.add_argument("--check", action="store_true", help="inspect prerequisites without starting services")
    parser.add_argument("--verbose", action="store_true", help="show technical errors")
    args = parser.parse_args()
    VERBOSE = args.verbose
    if not args.check:
        ensure_virtualenv()
        ensure_dependencies()
    print("SBOM Analyzer Development Setup\n", flush=True)
    say("OK", "Python", platform.python_version())
    saved = read_config()
    if args.check and any(
        key in saved
        for key in (
            "NATIVE_JWT_PRIVATE_KEY",
            "NATIVE_JWT_PUBLIC_KEY",
            "NATIVE_SECURITY_OUTBOX_KEY",
            "AUTH_SESSION_ENCRYPTION_KEY",
        )
    ):
        try:
            validate_secrets(saved)
        except ImportError:
            raise SetupError(
                "Cannot validate saved Native IAM keys without Python dependencies. Run python scripts/dev.py first."
            ) from None
    if not args.check and CONFIG.exists() and os.name != "nt":
        CONFIG.chmod(0o600)
    docker_env = os.environ.copy()
    docker_env.update(
        {
            "POSTGRES_PORT": str(POSTGRES_PORT),
            "REDIS_PORT": str(REDIS_PORT),
            "MAILPIT_SMTP_PORT": str(MAILPIT_SMTP_PORT),
            "MAILPIT_UI_PORT": str(MAILPIT_UI_PORT),
        }
    )
    postgres, pg_port = select_service(
        "postgres",
        POSTGRES_PORT,
        5432,
        check=args.check,
        env=docker_env,
        preferred=saved.get("DEV_POSTGRES_PROVIDER"),
    )
    redis, redis_port = select_service(
        "redis",
        REDIS_PORT,
        6379,
        check=args.check,
        env=docker_env,
        preferred=saved.get("DEV_REDIS_PROVIDER"),
    )
    # An older SBOM-specific Mailpit container is accepted, never an arbitrary SMTP server.
    old_mailpit = (
        docker_available()
        and run(["docker", "inspect", "-f", "{{.State.Running}}", "sbom-mailpit"]).stdout.strip() == "true"
    )
    if old_mailpit and reachable("127.0.0.1", MAILPIT_SMTP_PORT) and mailpit_ready():
        mailpit = "Docker (sbom-mailpit)"
    else:
        mailpit, _ = select_service("mailpit", MAILPIT_SMTP_PORT, MAILPIT_SMTP_PORT, check=args.check, env=docker_env)
        if not args.check and not mailpit_ready():
            raise SetupError("Mailpit could not be verified on port 8025. Check the project Mailpit service.")
    values = resolve_config(
        saved,
        pg_port,
        redis_port,
        MAILPIT_SMTP_PORT,
        pg_provider=provider_name(postgres),
        redis_provider=provider_name(redis),
    )
    if not args.check:
        generate_keys(values)
    env = os.environ.copy()
    env.update(values)
    env["PYTHONPATH"] = str(ROOT)
    api_port = int(values["DEV_API_PORT"])
    frontend_port = int(values["DEV_FRONTEND_PORT"])
    db_url = urlsplit(values["DATABASE_URL"])
    say("OK", "PostgreSQL", f"{postgres}, {db_url.hostname}:{db_url.port}")
    say("OK", "Redis", f"{redis}, 127.0.0.1:{redis_port}")
    say("OK", "Database", DB_NAME)
    say("OK", "Mailpit", f"{mailpit}, http://127.0.0.1:{MAILPIT_UI_PORT}")
    if args.check:
        say("OK", "Check", "no services or processes started")
        return
    check_application_ports(api_port, frontend_port)
    if postgres == "local":
        configure_local_database(values, saved, pg_port, interactive=sys.stdin.isatty())
        env["DATABASE_URL"] = values["DATABASE_URL"]
    else:
        ensure_database(values["DATABASE_URL"])
        if values != saved:
            write_config(values)
    validate_existing_schema(values["DATABASE_URL"])
    head = run_migrations(env)
    say("OK", "Schema", head)
    npm = ensure_frontend()
    check_application_ports(api_port, frontend_port)
    acquire_beat_lock()
    processes = []
    try:
        processes.append(
            start_process(
                "API",
                [
                    str(venv_python()),
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                    "--no-proxy-headers",
                ],
                env,
            )
        )
        celery = [str(venv_python()), "-m", "celery", "-A", "app.workers.celery_app"]
        worker_command = [*celery, "worker", "--loglevel=info"]
        if sys.platform == "win32":
            worker_command.append("--pool=solo")
        processes.append(start_process("Celery worker", worker_command, env))
        processes.append(start_process("Celery Beat", [*celery, "beat", "--loglevel=info"], env))
        processes.append(
            start_process(
                "Frontend",
                [npm, "run", "dev:https", "--", "--port", str(frontend_port)],
                env,
                ROOT / "frontend",
            )
        )
        wait_for_ready(processes, env, api_port, frontend_port)
        say("OK", "Native IAM", "enabled")
        say("OK", "API", f"http://127.0.0.1:{api_port}")
        say("OK", "Frontend", f"https://localhost:{frontend_port}")
        print("\nSBOM Analyzer is ready. Logs: .dev-logs/. Press Ctrl+C to stop.\n", flush=True)
        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
        for name, process in zip(("API", "Celery worker", "Celery Beat", "Frontend"), processes, strict=True):
            if process.poll() is not None:
                show_log(name, env)
                raise SetupError(f"{name} exited. See {log_path(name).relative_to(ROOT)}.")
    except KeyboardInterrupt:
        print("\nStopping application processes...", flush=True)
    finally:
        stop_processes(processes)
        BEAT_LOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Development setup cancelled.", file=sys.stderr)
        sys.exit(130)
    except SetupError as error:
        if VERBOSE:
            raise
        print(f"[ERROR] {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        if "--verbose" in sys.argv:
            raise
        print(f"[ERROR] Setup failed: {type(error).__name__}. Rerun with --verbose for details.", file=sys.stderr)
        sys.exit(1)
