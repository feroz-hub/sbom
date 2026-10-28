#!/usr/bin/env python3
"""Run real native-login/browser acceptance on a disposable PostgreSQL database.

Never loads frontend .env files or reuses an application database. All fixtures,
JWT keys, passwords, Redis state and file artifacts stay inside the temp folder.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def setup(directory):
    # Same verified test-DB selection as the application test fixture, without
    # importing conftest (which also configures application-wide test globals).
    from dotenv import dotenv_values

    configured = os.getenv("TEST_DATABASE_URL") or os.getenv("TEST_POSTGRES_DATABASE_URL")
    if not configured:
        configured = "postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_test"
    template = make_url(configured)
    if template.get_backend_name() != "postgresql" or "_test" not in (template.database or ""):
        raise RuntimeError("E2E requires a dedicated PostgreSQL test connection")
    name = "sbom_analyser_test_repair_e2e_" + uuid.uuid4().hex[:10]
    url = template.set(database=name)
    control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with control.connect() as connection:
        connection.exec_driver_sql("CREATE DATABASE " + connection.dialect.identifier_preparer.quote(name))
    control.dispose()
    marker = directory / "database.json"
    marker.write_text(json.dumps({"database_url": configured, "name": name}))
    marker.chmod(0o600)
    env = dict(os.environ)
    # Clear every inherited app setting sourced from the repo .env before
    # supplying this test instance's explicit configuration.
    for key in dotenv_values(ROOT / ".env"):
        env[key] = ""
    api_port, ui_port, redis_port = port(), port(), port()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env.update(
        DATABASE_URL=url.render_as_string(hide_password=False),
        AUTH_ENABLED="true",
        HCL_AUTH_ENABLED="false",
        NATIVE_AUTH_ENABLED="true",
        DEV_DEFAULT_TENANT="false",
        NATIVE_IAM_PRODUCTION="false",
        NATIVE_SECURITY_OUTBOX_ENABLED="false",
        ENTRA_ENABLED="false",
        API_AUTH_MODE="none",
        API_RATE_LIMIT_ENABLED="false",
        NATIVE_USER_CREATION_ENABLED="true",
        NATIVE_JWT_ISSUER="https://repair-e2e.test",
        NATIVE_JWT_AUDIENCE="sbom-analyser-api",
        NATIVE_JWT_PRIVATE_KEY=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        NATIVE_JWT_PUBLIC_KEY=key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        NATIVE_JWT_ACCESS_TOKEN_TTL_SECONDS="3600",
        AUTHORIZATION_CATALOG_MODE="DATABASE",
        AUTHORIZATION_CATALOG_FAIL_CLOSED="true",
        TENANT_ROLE_ASSIGNMENT_MODE="DATABASE",
        TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED="true",
        NVD_ENABLED="false",
        NVD_API_KEY="",
        GITHUB_TOKEN="",
        VULNDB_API_KEY="",
        NEXT_PUBLIC_AUTH_ENABLED="true",
        NEXT_PUBLIC_NATIVE_AUTH_ENABLED="true",
        NEXT_PUBLIC_HCL_AUTH_ENABLED="false",
        NEXT_PUBLIC_ENTRA_ENABLED="false",
        NEXT_PUBLIC_HCL_IAM_ISSUER="",
        NEXT_PUBLIC_HCL_IAM_CLIENT_ID="",
        NEXT_PUBLIC_API_URL=f"http://127.0.0.1:{api_port}",
        SBOM_API_URL=f"http://127.0.0.1:{api_port}",
        APP_ORIGIN=f"https://localhost:{ui_port}",
        CORS_ORIGINS=f"https://localhost:{ui_port}",
        AUTH_SESSION_STORE="redis",
        AUTH_SESSION_REDIS_URL=f"redis://127.0.0.1:{redis_port}/1",
        AUTH_SESSION_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode(),
        SBOM_WORKSPACE_STORAGE_DIR=str(directory / "workspaces"),
        SBOM_AUTO_REPAIR_ENABLED="true",
        SBOM_REPAIR_MAX_PASSES="3",
        SBOM_REPAIR_MAX_SECONDS="30",
        SBOM_REPAIR_AUTO_APPLY_CONFIDENCE="1.0",
        SBOM_REPAIR_MAX_BYTES="5242880",
        LOG_CONSOLE_FORMAT="json",
        LOG_FILE="",
        NODE_ENV="development",
    )
    # Remove empty configuration values so non-optional settings use their
    # model defaults. These processes start outside the repository .env cwd.
    env = {key: value for key, value in env.items() if value != ""}
    env["PYTHONPATH"] = str(ROOT)
    bootstrap_log = (directory / "bootstrap.log").open("w")
    env["REPAIR_E2E_DB_NAME"] = name
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import os; from scripts.bootstrap_fresh_database import bootstrap; "
            "bootstrap(os.environ['DATABASE_URL'], os.environ['REPAIR_E2E_DB_NAME'])",
        ],
        env=env,
        cwd=ROOT,
        stdout=bootstrap_log,
        stderr=subprocess.STDOUT,
        check=True,
    )
    bootstrap_log.close()
    # Settings must be loaded only after installing this isolated environment.
    os.environ.update(env)
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import IAMUser, NativeUserCredential, Product, Projects, Tenant, TenantUser, UserIdentity
    from app.services.password_service import hash_password
    from app.services.tenant_role_assignment_service import create_initial_assignment

    now = datetime.now(UTC)
    password = "Repair-E2E-" + uuid.uuid4().hex + "!"
    users = {}
    with SessionLocal() as db:
        first = db.get(Tenant, 1)
        if first is None:
            first = Tenant(
                id=1,
                name="Repair Tenant A",
                slug="repair-e2e-a",
                external_iam_tenant_id="repair-e2e-a",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(first)
        else:
            first.name = "Repair Tenant A"
        second = Tenant(
            id=2,
            name="Repair Tenant B",
            slug="repair-e2e-b",
            external_iam_tenant_id="repair-e2e-b",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(second)
        db.flush()
        for label, role, tenant_ids in [
            ("admin", "TENANT_ADMIN", [1, second.id]),
            ("analyst", "SECURITY_ANALYST", [1]),
            ("developer", "DEVELOPER", [1]),
            ("viewer", "VIEWER", [1]),
            ("foreign", "TENANT_ADMIN", [second.id]),
        ]:
            email = f"repair-{label}@example.test"
            user = IAMUser(
                email=email,
                display_name=f"Repair {label}",
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
            for tid in tenant_ids:
                with tenant_scope(minimal_background_context(tid)):
                    member = TenantUser(
                        tenant_id=tid, user_id=user.id, role=role, status="ACTIVE", created_at=now, updated_at=now
                    )
                    db.add(member)
                    db.flush()
                    create_initial_assignment(
                        db, member, role_code=role, actor_user_id=user.id, source="PLATFORM_ADMIN"
                    )
            users[label] = {"email": email, "password": password, "user_id": user.id}
        with tenant_scope(minimal_background_context(1)):
            project = Projects(
                tenant_id=1, project_name="Repair Release Project", project_status=1, created_on=now.isoformat()
            )
            db.add(project)
            db.flush()
            product = Product(
                tenant_id=1,
                project_id=project.id,
                name="Repair Release Product",
                normalized_name="repair release product",
                slug="repair-release-product",
                created_at=now.isoformat(),
            )
            db.add(product)
            db.flush()
            ids = {"project_id": project.id, "product_id": product.id, "tenant_a": 1, "tenant_b": second.id}
        db.commit()
    manifest = {
        "origin": env["APP_ORIGIN"],
        "api_url": env["SBOM_API_URL"],
        "database_url": env["DATABASE_URL"],
        "users": users,
        **ids,
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o600)
    ui = directory / "frontend"
    shutil.copytree(
        ROOT / "frontend", ui, ignore=shutil.ignore_patterns("node_modules", ".next", ".env*", "*.tsbuildinfo", "e2e")
    )
    (ui / "node_modules").symlink_to(ROOT / "frontend/node_modules", target_is_directory=True)
    certificate, private_key = directory / "cert.pem", directory / "cert-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    private_key.chmod(0o600)
    (directory / "alembic").symlink_to(ROOT / "alembic", target_is_directory=True)
    node = os.getenv("REPAIR_E2E_NODE") or shutil.which("node")
    env["PATH"] = str(Path(node).parent) + os.pathsep + env["PATH"]
    commands = [
        (
            ["redis-server", "--bind", "127.0.0.1", "--port", str(redis_port), "--save", "", "--appendonly", "no"],
            directory,
            "redis",
        ),
        (
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
            directory,
            "api",
        ),
        (
            [
                node,
                str(ROOT / "frontend/node_modules/next/dist/bin/next"),
                "dev",
                "--webpack",
                "-p",
                str(ui_port),
                "--hostname",
                "localhost",
                "--experimental-https",
                "--experimental-https-key",
                str(private_key),
                "--experimental-https-cert",
                str(certificate),
            ],
            ui,
            "ui",
        ),
    ]
    return env, manifest_path, commands, template, name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--serve", action="store_true", help="Keep isolated instance available for interactive diagnostics"
    )
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="sbom-repair-release-", dir="/tmp"))
    processes, files = [], []
    template = name = None
    try:
        env, manifest, commands, template, name = setup(directory)
        for command, cwd, label in commands:
            output = (directory / f"{label}.log").open("w")
            files.append(output)
            processes.append(subprocess.Popen(command, env=env, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, start_new_session=True))
        info = json.loads(manifest.read_text())
        deadline = time.monotonic() + 150
        with httpx.Client(verify=False) as client:
            for endpoint in [info["api_url"] + "/health", info["origin"] + "/native-sign-in"]:
                while True:
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError(f"A test server stopped; inspect {directory}")
                    try:
                        if client.get(endpoint, timeout=5).status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"Test server readiness timeout; inspect {directory}")
                    time.sleep(0.25)
        # Compile real auth/proxy/workspace routes before the browser's existing
        # 15-second auth bootstrap timer starts. WASM Webpack cold builds can be
        # slower than that timer; this changes no application timeout or auth.
        with httpx.Client(verify=False) as warmup:
            viewer = info["users"]["viewer"]
            response = warmup.post(info["origin"] + "/api/auth/native/login", headers={"Origin": info["origin"]}, json={"email": viewer["email"], "password": viewer["password"]}, timeout=90)
            if response.status_code != 200:
                raise RuntimeError(f"E2E warm-up sign-in failed ({response.status_code}); inspect {directory}")
            for route in ["/", "/sboms", "/sboms/0", "/repair/e2e-warmup", "/api/auth/session", "/api/backend/api/auth/me"]:
                response = warmup.get(info["origin"] + route, timeout=90)
                if response.status_code >= 500 or response.status_code == 307:
                    raise RuntimeError(f"E2E route warm-up failed ({response.status_code}); inspect {directory}")
        print(f"Isolated E2E instance ready; manifest: {manifest}", flush=True)
        if args.serve:
            while True:
                time.sleep(1)
        node = env.get("REPAIR_E2E_NODE") or shutil.which("node", path=env["PATH"])
        result = subprocess.run(
            [node, str(ROOT / "frontend/e2e/node_modules/playwright/cli.js"), "test"],
            cwd=ROOT / "frontend/e2e",
            env={**env, "REPAIR_E2E_MANIFEST": str(manifest)},
            check=False,
        )
        return result.returncode
    except KeyboardInterrupt:
        return 0
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        for output in files:
            output.close()
        if not name and (directory / "database.json").exists():
            marker = json.loads((directory / "database.json").read_text())
            template, name = make_url(marker["database_url"]), marker["name"]
        if name and template:
            control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT")
            with control.connect() as connection:
                connection.exec_driver_sql(
                    "DROP DATABASE " + connection.dialect.identifier_preparer.quote(name) + " WITH (FORCE)"
                )
            control.dispose()
        print(f"E2E diagnostic artifacts retained at {directory}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
