"""Disposable Public resource UUID browser/API environment; never starts the populated app."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STATE = Path.home() / ".sbom-public-resource-uuid"
DATABASE = "sbom_public_resource_uuid_browser_test"
ROLE = "resource_uuid_browser_app"
OWNER = "resource_uuid_browser_owner"
API_PORT = 18400
UI_PORT = 13400
REDIS_PORT = 56392


def write_private(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def environment():
    from sqlalchemy.engine import URL

    from scripts.dev import GreenfieldStack

    settings = GreenfieldStack.settings

    env = settings()
    # Tokens and BFF sessions from this task must never authenticate to the main app.
    keyfile = STATE / "identity-keys.json"
    if not keyfile.exists():
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        write_private(
            keyfile,
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
    env.update(json.loads(keyfile.read_text()))
    env["NATIVE_JWT_ISSUER"] = "https://public-resource-uuid-test.local"
    password = (STATE / "runtime-password").read_text()
    env.update(
        DATABASE_URL=URL.create(
            "postgresql+psycopg", username=ROLE, password=password, host="127.0.0.1", port=56044, database=DATABASE
        ).render_as_string(hide_password=False),
        APP_ORIGIN=f"https://localhost:{UI_PORT}",
        CORS_ORIGINS=f"https://localhost:{UI_PORT}",
        NEXT_PUBLIC_API_URL=f"http://127.0.0.1:{API_PORT}",
        SBOM_API_URL=f"http://127.0.0.1:{API_PORT}",
        AUTH_SESSION_REDIS_URL=f"redis://127.0.0.1:{REDIS_PORT}/1",
        REDIS_URL=f"redis://127.0.0.1:{REDIS_PORT}/0",
        CELERY_BROKER_URL=f"redis://127.0.0.1:{REDIS_PORT}/0",
        CELERY_RESULT_BACKEND=f"redis://127.0.0.1:{REDIS_PORT}/2",
        NATIVE_AUTH_RATE_LIMIT_STORAGE_URI=f"redis://127.0.0.1:{REDIS_PORT}/3",
        OSV_API_BASE_URL="http://127.0.0.1:19400/osv",
        SOURCE_CACHE_ENABLED="false",
        NATIVE_SECURITY_OUTBOX_ENABLED="false",
        EMAIL_DELIVERY_ENABLED="false",
        NATIVE_ACTIVATION_FRONTEND_URL=f"https://localhost:{UI_PORT}/activate-account",
        NATIVE_PASSWORD_RESET_FRONTEND_URL=f"https://localhost:{UI_PORT}/reset-password",
        SBOM_WORKSPACE_STORAGE_DIR=str(STATE / "workspaces"),
        REPORT_ARTIFACT_STORAGE_PATH=str(STATE / "reports"),
        NODE_EXTRA_CA_CERTS=str(Path.home() / "Library/Application Support/mkcert/rootCA.pem"),
    )
    env["PATH"] = (
        str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin")
        + os.pathsep
        + env.get("PATH", "/usr/bin:/bin")
    )
    return env


def prepare():
    from psycopg import sql
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from scripts.dev import GreenfieldStack

    url = GreenfieldStack.url

    verify_resources = GreenfieldStack.verify_resources

    verify_resources()
    STATE.mkdir(mode=0o700, exist_ok=True)
    if (STATE / "browser-created.json").exists():
        raise RuntimeError("Browser resources already initialized; use existing owned environment")
    for port in (API_PORT, UI_PORT, REDIS_PORT):
        with socket.socket() as s:
            s.bind(("127.0.0.1", port))
    if not (STATE / "runtime-password").exists():
        write_private(STATE / "runtime-password", secrets.token_urlsafe(36))
    env = environment()
    admin = make_url(url("greenfield_setup", "setup-password", "postgres"))
    control = create_engine(admin, isolation_level="AUTOCOMMIT", hide_parameters=True)
    with control.connect() as c:
        if c.execute(
            text("SELECT EXISTS(SELECT FROM pg_database WHERE datname=:name)"), {"name": DATABASE}
        ).scalar_one():
            raise RuntimeError("Unexpected existing browser database")
        for role in (OWNER, ROLE):
            if c.execute(text("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=:name)"), {"name": role}).scalar_one():
                raise RuntimeError("Unexpected existing browser role")
        raw = c.connection.driver_connection
        with raw.cursor() as cursor:
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(OWNER))
            )
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(ROLE), sql.Literal((STATE / "runtime-password").read_text()))
            )
        c.exec_driver_sql("CREATE DATABASE " + DATABASE)
    control.dispose()
    os.environ.update(env)
    from app.greenfield_schema import application_metadata
    from app.iam_schema import apply_user_uuid_revision
    from app.public_identity import install_guards
    from app.resource_schema import apply_resource_uuid_revision, revision100_metadata
    from sqlalchemy.orm import Session

    from scripts.greenfield_references import seed_catalog

    engine = create_engine(admin.set(database=DATABASE), hide_parameters=True)
    with engine.begin() as c:
        c.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        c.exec_driver_sql("ALTER SCHEMA public OWNER TO " + OWNER)
        c.exec_driver_sql("SET LOCAL ROLE " + OWNER)
        revision100_metadata(application_metadata()).create_all(c)
        install_guards(c)
        with Session(bind=c) as db:
            seed_catalog(db)
        c.exec_driver_sql("CREATE TABLE alembic_version(version_num varchar(128) PRIMARY KEY)")
        c.exec_driver_sql("INSERT INTO alembic_version VALUES('100_greenfield_uuid_final')")
        apply_user_uuid_revision(c)
        apply_resource_uuid_revision(c)
        c.exec_driver_sql("GRANT USAGE ON SCHEMA public TO " + ROLE)
        c.exec_driver_sql("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO " + ROLE)
        c.exec_driver_sql("REVOKE ALL ON alembic_version FROM " + ROLE)
        c.exec_driver_sql("GRANT SELECT ON alembic_version TO " + ROLE)
        c.exec_driver_sql("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO " + ROLE)
    engine.dispose()
    seed()
    write_private(
        STATE / "browser-created.json",
        json.dumps(
            {
                "database": DATABASE,
                "owner": OWNER,
                "runtime_role": ROLE,
                "api_port": API_PORT,
                "ui_port": UI_PORT,
                "redis_port": REDIS_PORT,
            }
        ),
    )
    print("Task-owned browser database installed at revision 102; existing users unchanged")


def seed():
    from datetime import UTC, datetime

    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import IAMUser, NativeUserCredential, PlatformUserRole, Tenant, TenantUser, UserIdentity
    from app.services.password_service import hash_password
    from app.services.tenant_role_assignment_service import create_initial_assignment

    now = datetime.now(UTC)
    users = {}
    with SessionLocal() as db:
        tenants = []
        for name in ("UUID Test Olympus", "UUID Test Foreign"):
            tenant = Tenant(
                name=name, slug=name.lower().replace(" ", "-"), status="ACTIVE", created_at=now, updated_at=now
            )
            db.add(tenant)
            db.flush()
            tenants.append(tenant)
        for label, role in [
            ("admin", "TENANT_ADMIN"),
            ("analyst", "SECURITY_ANALYST"),
            ("developer", "DEVELOPER"),
            ("viewer", "VIEWER"),
            ("foreign", "TENANT_ADMIN"),
            ("platform", None),
            ("candidate", None),
        ]:
            email = f"uuid-{label}@synthetic.example.test"
            password = secrets.token_urlsafe(24) + "!Aa9"
            user = IAMUser(
                email=email,
                display_name=f"UUID Test {label}",
                status="ACTIVE",
                email_verified=True,
                email_verified_at=now,
                verification_required=False,
                created_at=now,
                updated_at=now,
            )
            db.add(user)
            db.flush()
            db.add(
                UserIdentity(
                    user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now
                )
            )
            db.add(
                NativeUserCredential(
                    user_id=user.id,
                    password_hash=hash_password(password),
                    password_changed_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            tenant = tenants[1 if label == "foreign" else 0]
            if role:
                with tenant_scope(minimal_background_context(tenant.id)):
                    member = TenantUser(
                        tenant_id=tenant.id, user_id=user.id, role=role, status="ACTIVE", created_at=now, updated_at=now
                    )
                    db.add(member)
                    db.flush()
                    create_initial_assignment(db, member, role_code=role, actor_user_id=user.id, source="SYSTEM")
            if label == "platform":
                db.add(
                    PlatformUserRole(
                        user_id=user.id, role="PLATFORM_ADMIN", status="ACTIVE", created_at=now, updated_at=now
                    )
                )
            users[label] = {
                "email": email,
                "password": password,
                "public_id": str(user.public_id),
                "tenant_id": str(tenant.public_id),
            }
        db.commit()
    write_private(STATE / "users.json", json.dumps(users, indent=2))


def start():
    env = environment()
    if (STATE / "processes.json").exists():
        raise RuntimeError("Process inventory exists; inspect before starting again")
    for port in (API_PORT, UI_PORT, REDIS_PORT):
        with socket.socket() as s:
            s.bind(("127.0.0.1", port))
    frontend = STATE / "frontend"
    shutil.copytree(
        ROOT / "frontend",
        frontend,
        ignore=shutil.ignore_patterns(
            "node_modules", ".next", "test-results", "playwright-report", ".git", ".env*", "certificates"
        ),
        dirs_exist_ok=False,
    )
    (frontend / "node_modules").symlink_to(ROOT / "frontend/node_modules", target_is_directory=True)
    commands = {
        "redis": [
            "/opt/homebrew/bin/redis-server",
            "--bind",
            "127.0.0.1",
            "--port",
            str(REDIS_PORT),
            "--save",
            "",
            "--appendonly",
            "no",
        ],
        "api": [
            str(ROOT / ".venv/bin/python"),
            "-B",
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(API_PORT),
        ],
        "frontend": [
            str(Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"),
            str(ROOT / "frontend/node_modules/next/dist/bin/next"),
            "dev",
            "--webpack",
            "--hostname",
            "localhost",
            "--port",
            str(UI_PORT),
            "--experimental-https",
            "--experimental-https-key",
            str(Path.home() / ".sbom-greenfield-uuid/cert-key.pem"),
            "--experimental-https-cert",
            str(Path.home() / ".sbom-greenfield-uuid/cert.pem"),
        ],
    }
    pids = {}
    for name, command in commands.items():
        log = STATE / (name + ".log")
        fd = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as output:
            process = subprocess.Popen(
                command,
                cwd=frontend if name == "frontend" else ROOT,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        pids[name] = process.pid
    write_private(STATE / "processes.json", json.dumps(pids))
    print(json.dumps({"pids": pids, "api": f"http://127.0.0.1:{API_PORT}", "frontend": f"https://localhost:{UI_PORT}"}))


if __name__ == "__main__":
    {"prepare": prepare, "start": start}[sys.argv[1]]()
