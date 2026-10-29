#!/usr/bin/env python3
"""Explicit, reproducible local greenfield development stack. Never targets A/B/D/E/F."""

from __future__ import annotations

import argparse
import base64
import errno
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STATE = Path.home() / ".sbom-greenfield-uuid"
LOCAL_SOCKET = Path.home() / ".docker/run/docker.sock"
if not LOCAL_SOCKET.exists():
    LOCAL_SOCKET = Path("/var/run/docker.sock")
DOCKER = [shutil.which("docker") or "/usr/local/bin/docker", "--host", "unix://" + str(LOCAL_SOCKET)]
DB = "sbom_greenfield_uuid"


def current_revision():
    from scripts.greenfield_migration_graph import discover

    return discover(ROOT).head


def __getattr__(name):
    # Existing callers can keep importing REVISION; its value is discovered,
    # rather than copied into another launcher constant for every migration.
    if name == "REVISION":
        return current_revision()
    raise AttributeError(name)


def read_private(name):
    path = STATE / name
    parent = STATE.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise RuntimeError("Unsafe greenfield private directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeError("Unsafe greenfield private file")
        return stream.read()


def private_file(name, content):
    STATE.mkdir(mode=0o700, exist_ok=True)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("Unsafe greenfield private directory")
    path = STATE / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    return path


def settings():
    path = STATE / "environment.json"
    if not path.exists():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_file("setup-password", secrets.token_urlsafe(36))
        private_file("runtime-password", secrets.token_urlsafe(36))
        private_file(
            "environment.json",
            json.dumps(
                {
                    "NATIVE_JWT_PRIVATE_KEY": key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                    ).decode(),
                    "NATIVE_JWT_PUBLIC_KEY": key.public_key()
                    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    .decode(),
                    "AUTH_SESSION_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
                    "AI_CONFIG_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
                }
            ),
        )
    env = {k: v for k, v in os.environ.items() if k in ("HOME", "PATH", "TMPDIR", "LANG", "TERM")}
    env.update(json.loads(read_private("environment.json")))
    if "NATIVE_SECURITY_OUTBOX_KEY" not in env:
        if not (STATE / "security-mail-key").exists():
            private_file("security-mail-key", base64.b64encode(os.urandom(32)).decode())
        env["NATIVE_SECURITY_OUTBOX_KEY"] = read_private("security-mail-key")
    # Separate generated storage key; never replace a previously configured key.
    if "AI_CONFIG_ENCRYPTION_KEY" not in env:
        if not (STATE / "provider-storage-key").exists():
            private_file("provider-storage-key", base64.b64encode(os.urandom(32)).decode())
        env["AI_CONFIG_ENCRYPTION_KEY"] = base64.b64encode(
            base64.urlsafe_b64decode(read_private("provider-storage-key"))
        ).decode()
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "GREENFIELD_STATE": str(STATE),
            "PYTHONPATH": str(ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "DATABASE_URL": url("greenfield_app", "runtime-password"),
            "AUTH_ENABLED": "true",
            "HCL_AUTH_ENABLED": "false",
            "NATIVE_AUTH_ENABLED": "true",
            "ENTRA_ENABLED": "false",
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
            "REPORT_ARTIFACT_STORAGE_PATH": str(STATE / "reports"),
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": "1026",
            "SMTP_USE_STARTTLS": "false",
            "NVD_ENABLED": "false",
            "ANALYSIS_SOURCES": "OSV",
            "SBOM_WORKSPACE_STORAGE_DIR": str(STATE / "workspaces"),
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
    )
    return env


def url(user, filename, database=DB):
    from sqlalchemy.engine import URL

    if database not in {DB, "postgres", DB + "_repro_test", DB + "_integrity_test", DB + "_regression_test"}:
        raise RuntimeError("Database outside the greenfield task scope")
    if (user, filename) not in {("greenfield_app", "runtime-password"), ("greenfield_setup", "setup-password")}:
        raise RuntimeError("Unexpected greenfield credential selection")
    return URL.create(
        "postgresql+psycopg",
        username=user,
        password=read_private(filename),
        host="127.0.0.1",
        port=56044,
        database=database,
    ).render_as_string(hide_password=False)


def verify_resources():
    identities = json.loads(read_private("docker-identities.json"))
    names = {"sbom-greenfield-uuid-dev-" + service + "-1" for service in ("postgres", "redis", "mailpit")}
    if set(identities) != names:
        raise RuntimeError("Unexpected greenfield resource inventory")
    for name, expected in identities.items():
        actual = json.loads(subprocess.check_output(DOCKER + ["inspect", name], text=True))[0]
        labels = actual["Config"]["Labels"]
        if actual["Id"] != expected or labels.get("com.docker.compose.project") != "sbom-greenfield-uuid-dev":
            raise RuntimeError("Greenfield resource identity changed")
        if set(actual["NetworkSettings"]["Networks"]) != {"sbom-greenfield-uuid-dev_access"}:
            raise RuntimeError("Unexpected greenfield network attachment")
        if name.endswith("-postgres-1"):
            if actual["Image"] != "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54":
                raise RuntimeError("Unexpected PostgreSQL image")
            if actual["HostConfig"]["PortBindings"] != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56044"}]}:
                raise RuntimeError("Unexpected PostgreSQL publication")
            volumes = [m["Name"] for m in actual["Mounts"] if m["Type"] == "volume"]
            if volumes != ["sbom-greenfield-uuid-dev_pgdata"]:
                raise RuntimeError("Unexpected PostgreSQL storage")


def provision():
    # Refuse collisions before creating any new resources or secrets.
    projects = subprocess.check_output(
        DOCKER + ["ps", "-a", "--format", '{{.Label "com.docker.compose.project"}}'], text=True
    ).splitlines()
    existing = "sbom-greenfield-uuid-dev" in projects
    if existing:
        verify_resources()
    else:
        for port in (56044, 56381, 1026, 8026):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
        for kind, name in [
            ("volume", "sbom-greenfield-uuid-dev_pgdata"),
            ("volume", "sbom-greenfield-uuid-dev_redisdata"),
            ("network", "sbom-greenfield-uuid-dev_access"),
        ]:
            if (
                subprocess.run(
                    DOCKER + [kind, "inspect", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                ).returncode
                == 0
            ):
                raise RuntimeError("Unowned greenfield resource collision")
    env = settings()
    subprocess.run(
        DOCKER
        + [
            "compose",
            "-f",
            str(ROOT / "infra/greenfield-uuid/compose.yml"),
            "up",
            "-d",
            "--pull",
            "never",
            "--no-build",
            "--no-recreate",
        ],
        env=env,
        check=True,
    )
    for _ in range(30):
        result = subprocess.check_output(
            DOCKER + ["inspect", "sbom-greenfield-uuid-dev-postgres-1", "--format", "{{.State.Health.Status}}"],
            env=env,
            text=True,
        )
        if result.strip() == "healthy":
            if not existing:
                names = ["sbom-greenfield-uuid-dev-" + service + "-1" for service in ("postgres", "redis", "mailpit")]
                observations = json.loads(subprocess.check_output(DOCKER + ["inspect", *names], text=True))
                private_file(
                    "docker-identities.json",
                    json.dumps({x["Name"].lstrip("/"): x["Id"] for x in observations}, indent=2),
                )
            return
        time.sleep(2)
    raise RuntimeError("Greenfield PostgreSQL did not become healthy")


def bootstrap(database=DB):
    if database not in {DB, DB + "_repro_test"}:
        raise RuntimeError("Only this task's greenfield databases are permitted")
    verify_resources()
    env = settings()
    os.environ.clear()
    os.environ.update(env)
    os.chdir(STATE)
    from app.greenfield_schema import application_metadata
    from app.iam_schema import apply_user_uuid_revision
    from app.resource_schema import apply_resource_uuid_revision, revision100_metadata

    metadata = revision100_metadata(application_metadata())
    from app.public_identity import TABLES, install_guards
    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.pool import NullPool

    engine = create_engine(
        url("greenfield_setup", "setup-password", database), hide_parameters=True, poolclass=NullPool
    )
    try:
        with engine.begin() as connection:
            if inspect(connection).has_table("alembic_version"):
                marker = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                if marker != current_revision():
                    raise RuntimeError("Unexpected existing greenfield revision")
                print("Existing marker observed; structural verification follows without schema repair")
            else:
                if inspect(connection).get_table_names():
                    raise RuntimeError("Refusing partially initialized database")
                password = read_private("runtime-password")
                # psycopg safely quotes the password as a literal; never logs it.
                from psycopg import sql

                raw = connection.connection.driver_connection
                with raw.cursor() as cur:
                    for role, login in (("greenfield_owner", False), ("greenfield_app", True)):
                        cur.execute(
                            "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",
                            (role,),
                        )
                        existing = cur.fetchone()
                        if existing is not None:
                            if tuple(existing) != (login, False, False, False, False, False):
                                raise RuntimeError("Unexpected task-owned role privileges")
                            continue
                        query = sql.SQL(
                            "CREATE ROLE {} {} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                        ).format(sql.Identifier(role), sql.SQL("LOGIN" if login else "NOLOGIN"))
                        if login:
                            query += sql.SQL(" PASSWORD {}").format(sql.Literal(password))
                        cur.execute(query)
                connection.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
                connection.exec_driver_sql("ALTER SCHEMA public OWNER TO greenfield_owner")
                connection.exec_driver_sql("SET LOCAL ROLE greenfield_owner")
                metadata.create_all(connection)
                install_guards(connection)
                # Validate the full metadata structure before establishing its baseline.
                actual = inspect(connection)
                if set(actual.get_table_names()) != set(metadata.tables):
                    raise RuntimeError("Metadata/table parity failed")
                for table in metadata.tables.values():
                    if set(c["name"] for c in actual.get_columns(table.name)) != set(table.columns.keys()):
                        raise RuntimeError(f"Column parity failed: {table.name}")
                for name in TABLES:
                    col = next(c for c in actual.get_columns(name) if c["name"] == "public_id")
                    if col["nullable"] or str(col["type"]) != "UUID" or "gen_random_uuid" not in col["default"]:
                        raise RuntimeError("Final UUID definition mismatch")
                from sqlalchemy.orm import Session

                from scripts.greenfield_references import seed_catalog

                with Session(bind=connection) as seed_session:
                    seed_catalog(seed_session)
                connection.exec_driver_sql("CREATE TABLE public.alembic_version(version_num varchar(128) PRIMARY KEY)")
                connection.execute(
                    text("INSERT INTO public.alembic_version(version_num) VALUES(:revision)"),
                    {"revision": "100_greenfield_uuid_final"},
                )
                apply_user_uuid_revision(connection)
                apply_resource_uuid_revision(connection)
                from scripts.greenfield_auto_migrations import apply_fresh_tail

                apply_fresh_tail(connection)
                connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO greenfield_app")
                connection.exec_driver_sql(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO greenfield_app"
                )
                connection.exec_driver_sql("REVOKE ALL ON public.alembic_version FROM greenfield_app")
                connection.exec_driver_sql("GRANT SELECT ON public.alembic_version TO greenfield_app")
                connection.exec_driver_sql("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO greenfield_app")
                connection.exec_driver_sql("REVOKE ALL ON FUNCTION public.uuid_public_identity_guard_v1() FROM PUBLIC")
                connection.exec_driver_sql(
                    "GRANT EXECUTE ON FUNCTION public.uuid_public_identity_guard_v1() TO greenfield_app"
                )
        with engine.connect() as reader:
            reader.exec_driver_sql("SET TRANSACTION READ ONLY")
            from scripts.greenfield_auto_migrations import validate_current_tail

            validate_current_tail(reader)
            print("Committed revision:", reader.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one())
            print("Application tables:", len(metadata.tables))
            reader.rollback()
    finally:
        engine.dispose()
    from scripts.greenfield_schema_check import verify

    verify(database)


def frontend_workspace(name):
    if name not in {"frontend", "frontend-build"}:
        raise RuntimeError("Unexpected frontend workspace")
    ui = STATE / name
    ui.mkdir(exist_ok=True)
    for name in ("src", "public"):
        if not (ROOT / "frontend" / name).exists():
            continue
        destination = ui / name
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(ROOT / "frontend" / name, destination)
    for path in (ROOT / "frontend").iterdir():
        if (
            path.is_file()
            and not path.name.startswith(".env")
            and path.suffix in (".json", ".js", ".ts", ".mjs", ".cjs")
        ):
            shutil.copy2(path, ui / path.name)
    if not (ui / "node_modules").exists():
        (ui / "node_modules").symlink_to(ROOT / "frontend/node_modules", target_is_directory=True)
    return ui


def node_binary():
    bundled = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"
    return bundled if bundled.exists() else Path(shutil.which("node") or "node")


class ServicePortError(RuntimeError):
    """A required application port cannot be bound; no service was started."""


def check_service_ports(ports=(18000, 13000)):
    for port in ports:
        with socket.socket() as sock:
            # Match asyncio/Uvicorn's POSIX listener policy. A stopped service
            # can leave accepted connections in TIME_WAIT, which a plain bind
            # wrongly treats as a live conflict on macOS. Do not use this on
            # Windows, where SO_REUSEADDR can allow a second live listener.
            if sys.platform != "win32":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as error:
                if error.errno in (errno.EADDRINUSE, 10048):
                    raise ServicePortError(
                        f"Greenfield application port {port} on 127.0.0.1 is already in use. "
                        f"Inspect with: lsof -nP -iTCP:{port} -sTCP:LISTEN. "
                        "Stop a separately launched instance using its own launcher. No process was stopped."
                    ) from None
                raise ServicePortError(
                    f"Cannot bind Greenfield application port {port} on 127.0.0.1 "
                    f"(OS error {error.errno}). No service was started."
                ) from None


def start_services(runtime=None):
    from scripts import greenfield_https

    check_service_ports()
    cert, key, _, _ = greenfield_https.ensure_certificate(STATE, prepare=True)
    verify_resources()
    env = settings()
    node = node_binary()
    env["PATH"] = str(node.parent) + ":/usr/bin:/bin:/usr/local/bin"
    ui = frontend_workspace("frontend")
    commands = {
        "worker": (
            [
                sys.executable,
                "-B",
                "-m",
                "celery",
                "-A",
                "scripts.greenfield_worker:celery_app",
                "worker",
                "--loglevel=INFO",
                "--pool=solo",
                "--concurrency=1",
                "--queues=celery,reports",
                "--hostname=greenfield@%h",
                "--beat",
                "--schedule=" + str(STATE / "security-mail-schedule"),
            ],
            STATE,
        ),
        "backend": (
            [sys.executable, "-B", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18000"],
            STATE,
        ),
        "frontend": (
            [
                str(node),
                str(ROOT / "frontend/node_modules/next/dist/bin/next"),
                "dev",
                "--webpack",
                "--hostname",
                "127.0.0.1",
                "--port",
                "13000",
                "--experimental-https",
                "--experimental-https-key",
                str(key),
                "--experimental-https-cert",
                str(cert),
            ],
            ui,
        ),
    }
    processes = {}
    started = {}
    for name, (command, cwd) in commands.items():
        with (STATE / (name + ".log")).open("a") as log:
            process = subprocess.Popen(
                command, env=env, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
            )
        processes[name] = {"pid": process.pid, "command": command}
        started[name] = process
        if runtime is not None:
            runtime.processes[process.pid] = process
            runtime.register(
                {"worker": "Celery worker", "backend": "API", "frontend": "Frontend"}[name],
                process.pid,
                {"backend": 18000, "frontend": 13000}.get(name),
            )
    path = STATE / "processes.json"
    path.write_text(json.dumps(processes, indent=2))
    path.chmod(0o600)
    import httpx

    deadline = time.monotonic() + 60
    with httpx.Client(verify=greenfield_https.client_context(STATE), timeout=2, trust_env=False) as client:
        while True:
            if runtime is not None:
                runtime.refresh()
            if any(process.poll() is not None for process in started.values()):
                raise RuntimeError("A greenfield service exited; inspect its private log")
            try:
                ready = client.get("http://127.0.0.1:18000/health").status_code == 200
                ready = ready and client.get("http://127.0.0.1:18000/ready/iam").json().get("ready") is True
                ready = ready and client.get("https://localhost:13000/native-sign-in").status_code == 200
                if ready:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("Greenfield service readiness timed out; no automatic teardown")
            time.sleep(0.5)
    greenfield_https.verify_endpoint()
    print("Backend http://127.0.0.1:18000; frontend https://localhost:13000 (system HTTPS trust verified)")
    return started


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["setup", "provision", "bootstrap", "env", "backend", "start", "restart", "build"]
    )
    args = parser.parse_args()
    from scripts.greenfield_https import require_supported_platform

    require_supported_platform()
    if args.action == "setup":
        from scripts.greenfield_https import ensure_certificate

        ensure_certificate(STATE, prepare=True)
        provision()
        bootstrap()
        subprocess.run([sys.executable, "-B", "-m", "scripts.greenfield_seed"], cwd=ROOT, check=True)
        start_services()
    elif args.action == "build":
        env = settings()
        env["NODE_ENV"] = "production"
        subprocess.run(
            [str(node_binary()), str(ROOT / "frontend/node_modules/next/dist/bin/next"), "build", "--webpack"],
            cwd=frontend_workspace("frontend-build"),
            env=env,
            check=True,
        )
    elif args.action == "provision":
        provision()
    elif args.action == "bootstrap":
        bootstrap()
    elif args.action in ("start", "restart"):
        if args.action == "restart":
            import signal

            for item in json.loads((STATE / "processes.json").read_text()).values():
                observed = subprocess.run(
                    ["ps", "-p", str(item["pid"]), "-o", "command="], capture_output=True, text=True
                ).stdout
                if observed and (
                    ("app.main:app" in observed)
                    or ("next/dist/bin/next" in observed and "13000" in observed)
                    or ("celery" in observed and "greenfield@" in observed)
                ):
                    os.killpg(item["pid"], signal.SIGTERM)
            time.sleep(1)
        start_services()
    elif args.action == "backend":
        subprocess.run(
            [sys.executable, "-B", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18000"],
            env=settings(),
            cwd=STATE,
            check=True,
        )
    else:
        print("Environment is private; use the backend command or import settings() for child processes.")


if __name__ == "__main__":
    from scripts.greenfield_https import HttpsTrustError

    try:
        main()
    except HttpsTrustError as exc:
        raise SystemExit(str(exc)) from None
