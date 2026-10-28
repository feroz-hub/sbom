"""Task-owned IAM UUID test databases. Never upgrade the populated application DB."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DATABASE = "sbom_iam_public_uuid_test"
UPGRADE_DATABASE = "sbom_iam_public_uuid_upgrade_test"
STATE = Path.home() / ".sbom-iam-public-uuid"


def environment(database=DATABASE):
    from sqlalchemy.engine import make_url

    from scripts.greenfield_uuid import settings, url

    if database not in {DATABASE, UPGRADE_DATABASE}:
        raise RuntimeError("Not an IAM task-owned test database")
    env = settings()
    address = make_url(url("greenfield_setup", "setup-password", "postgres")).set(database=database)
    selected = address.render_as_string(hide_password=False)
    env.update(
        NATIVE_AUTH_ENABLED="false",
        HCL_AUTH_ENABLED="true",
        API_RATE_LIMIT_ENABLED="false",
        NATIVE_SECURITY_OUTBOX_ENABLED="false",
        DATABASE_URL=selected,
        TEST_DATABASE_URL=selected,
        TEST_POSTGRES_DATABASE_URL=selected,
        IAM_UUID_UPGRADE_DATABASE_URL=address.set(database=UPGRADE_DATABASE).render_as_string(hide_password=False),
    )
    return env


def prepare():
    from sqlalchemy import create_engine, inspect, text

    from scripts.greenfield_uuid import url, verify_resources

    verify_resources()
    env = environment()
    os.environ.update(env)
    from app.greenfield_schema import application_metadata
    from app.iam_schema import apply_user_uuid_revision, revision100_metadata
    from app.public_identity import install_guards

    metadata = revision100_metadata(application_metadata())
    control = create_engine(
        url("greenfield_setup", "setup-password", "postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True
    )
    with control.connect() as c:
        assert (
            c.exec_driver_sql("SELECT system_identifier::text FROM pg_control_system()").scalar_one()
            == "7698349709013049382"
        )
        for name in (DATABASE, UPGRADE_DATABASE):
            if not c.execute(
                text("SELECT EXISTS(SELECT FROM pg_database WHERE datname=:name)"), {"name": name}
            ).scalar_one():
                c.exec_driver_sql("CREATE DATABASE " + name)
    control.dispose()
    engine = create_engine(env["DATABASE_URL"], hide_parameters=True)
    with engine.begin() as c:
        if not inspect(c).has_table("alembic_version"):
            if inspect(c).get_table_names():
                raise RuntimeError("Unexpected partial IAM test schema")
            metadata.create_all(c)
            install_guards(c)
            c.exec_driver_sql("CREATE TABLE alembic_version(version_num varchar(128) PRIMARY KEY)")
            c.exec_driver_sql("INSERT INTO alembic_version VALUES ('100_greenfield_uuid_final')")
            apply_user_uuid_revision(c)
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() == [
            "101_iam_user_public_uuid"
        ]
    engine.dispose()
    return env


def main():
    STATE.mkdir(mode=0o700, exist_ok=True)
    lock = open(STATE / "test.lock", "a")
    os.chmod(STATE / "test.lock", 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    env = prepare()
    if sys.argv[1:] == ["--prepare"]:
        print(
            json.dumps(
                {
                    "database": DATABASE,
                    "revision": "101_iam_user_public_uuid",
                    "populated_application_database_migrated": False,
                }
            )
        )
        return 0
    args = sys.argv[1:] or ["tests/test_iam_user_public_uuid.py"]
    # Match the established regression isolation: never inherit the running
    # application's broker, SMTP, keys, or session configuration.
    clean = {k: v for k, v in os.environ.items() if k in ("HOME", "PATH", "TMPDIR", "LANG")}
    for key in ("DATABASE_URL", "TEST_DATABASE_URL", "TEST_POSTGRES_DATABASE_URL", "IAM_UUID_UPGRADE_DATABASE_URL"):
        clean[key] = env[key]
    clean.update(PYTHONPATH=str(ROOT), PYTHON_DOTENV_DISABLED="1", PYTHONDONTWRITEBYTECODE="1")
    clean.update(
        AI_TEST_REDIS_URL="redis://127.0.0.1:56391/7",
        PYTEST_PLUGINS="tests.iam_uuid_routing_guard",
        CELERY_USE_DATABASE_BROKER="false",
        CELERY_BROKER_URL="redis://127.0.0.1:63391/0",
        CELERY_RESULT_BACKEND="redis://127.0.0.1:63391/0",
        REDIS_URL="redis://127.0.0.1:63391/0",
        EMAIL_DELIVERY_ENABLED="false",
        NATIVE_SECURITY_OUTBOX_ENABLED="false",
        NATIVE_AUTH_ENABLED="false",
        APP_ENVIRONMENT="test",
        SBOM_RUN_BACKUP_ACCEPTANCE="1",
        SBOM_ACCEPTANCE_PG_CONTAINER="sbom-greenfield-uuid-dev-postgres-1",
        LIFECYCLE_LIVE_SMOKE="1",
    )
    import socket

    with socket.socket() as isolated_broker:
        isolated_broker.bind(("127.0.0.1", 63391))
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "--tb=short", *args], cwd=ROOT, env=clean
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
