"""Opt-in completely empty PostgreSQL + existing loopback Mailpit acceptance."""
import base64
import os
import socket
import subprocess
import sys
import time
import uuid

import pytest
from app.settings import get_settings
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from tests.test_native_iam_phase2 import native_config as native_config

pytestmark = pytest.mark.skipif(os.getenv("SBOM_RUN_GREENFIELD_ACCEPTANCE") != "1", reason="explicit empty DB/Mailpit acceptance")


def test_empty_database_to_native_population(tmp_path):
    url = make_url(os.environ["TEST_POSTGRES_DATABASE_URL"])
    name = "sbom_greenfield_test_" + uuid.uuid4().hex[:10]
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True)
    with admin.connect() as conn:
        conn.execute(text("CREATE DATABASE " + name))
    s = get_settings()
    env = dict(os.environ, DATABASE_URL=url.set(database=name).render_as_string(hide_password=False),
        AUTH_ENABLED="true", HCL_AUTH_ENABLED="false", HCL_IAM_ISSUER="", HCL_IAM_CLIENT_ID="", HCL_IAM_AUDIENCE="",
        DEV_DEFAULT_TENANT="false", NATIVE_AUTH_ENABLED="true", NATIVE_USER_CREATION_ENABLED="true",
        NATIVE_PLATFORM_BOOTSTRAP_ENABLED="true", NATIVE_SECURITY_OUTBOX_ENABLED="true", NATIVE_IAM_PRODUCTION="false",
        NATIVE_SECURITY_OUTBOX_KEY=base64.b64encode(os.urandom(32)).decode(),
        NATIVE_JWT_PRIVATE_KEY=s.native_jwt_private_key, NATIVE_JWT_PUBLIC_KEY=s.native_jwt_public_key,
        NATIVE_JWT_ISSUER=s.native_jwt_issuer, NATIVE_JWT_AUDIENCE=s.native_jwt_audience,
        EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS="30", EMAIL_PROVIDER="smtp", EMAIL_DELIVERY_ENABLED="true", SMTP_HOST="127.0.0.1", SMTP_PORT="1025",
        SMTP_USE_TLS="false", SMTP_USE_STARTTLS="false", SMTP_USERNAME="", SMTP_PASSWORD="",
        EMAIL_FROM_ADDRESS="support@greenfield.test", AUTHORIZATION_CATALOG_MODE="DATABASE",
        AUTHORIZATION_CATALOG_FAIL_CLOSED="true", TENANT_ROLE_ASSIGNMENT_MODE="DATABASE", TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED="true")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        redis_port = sock.getsockname()[1]
    env.update(CELERY_USE_DATABASE_BROKER="false", CELERY_BROKER_URL=f"redis://127.0.0.1:{redis_port}/0",
               CELERY_RESULT_BACKEND=f"redis://127.0.0.1:{redis_port}/0",
               NATIVE_AUTH_RATE_LIMIT_STORAGE_URI=f"redis://127.0.0.1:{redis_port}/2")
    processes = []
    worker_log = (tmp_path / "worker.log").open("w")
    try:
        processes.append(subprocess.Popen(["redis-server", "--bind", "127.0.0.1", "--port", str(redis_port), "--save", "", "--dir", str(tmp_path)], stdout=worker_log, stderr=subprocess.STDOUT))
        time.sleep(0.3)
        check = subprocess.run([sys.executable, "-m", "alembic", "current"], env=env, capture_output=True, text=True, timeout=30)
        assert check.returncode == 0
        empty = create_engine(url.set(database=name))
        try:
            assert inspect(empty).get_table_names() == [], "Read-only revision inspection must not bootstrap"
        finally:
            empty.dispose()
        for command in ([sys.executable, "-m", "alembic", "upgrade", "head"], [sys.executable, "-m", "tests.native_greenfield_scenario"]):
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180)
            # Logs remain local; the scenario never prints credentials/tokens.
            log = tmp_path / ("migration.log" if "alembic" in command else "scenario.log")
            log.write_text(result.stdout + result.stderr)
            log.chmod(0o600)
            assert result.returncode == 0, f"Acceptance failed; safe diagnostics: {log}"
            if "alembic" in command:
                processes.append(subprocess.Popen([sys.executable, "-m", "celery", "-A", "app.workers.celery_app", "worker", "--pool=solo", "--concurrency=1", "--loglevel=WARNING", "--without-gossip", "--without-mingle"], env=env, stdout=worker_log, stderr=subprocess.STDOUT))
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        worker_log.close()
        with admin.connect() as conn:
            conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        admin.dispose()
