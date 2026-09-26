"""Opt-in local backup/restore to a new disposable database, never staging."""

import base64
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
from app.db import SessionLocal
from app.models import SecurityMailOutbox
from app.services import native_auth_service as auth
from app.services import native_enrollment_service as enrollment
from app.services import native_password_service as passwords
from app.settings import get_settings
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url

from tests.test_native_iam_phase2 import PASSWORD, context, payload
from tests.test_native_iam_phase2 import native_config as native_config

pytestmark = pytest.mark.skipif(os.getenv("SBOM_RUN_BACKUP_ACCEPTANCE") != "1", reason="opt-in isolated backup/restore")


def test_backup_restore_preserves_iam_and_ciphertext(tmp_path, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "native_security_outbox_enabled", True)
    monkeypatch.setattr(s, "native_security_outbox_key", base64.b64encode(os.urandom(32)).decode())
    with SessionLocal() as db:
        user, token = enrollment.create_user(db, context(db), payload())
        db.commit()
        uid = user.id
        auth.activate(db, token.raw_token, PASSWORD)
        db.commit()
        _, token = passwords.request_reset(db, user.email)
        db.commit()
        row = db.scalar(select(SecurityMailOutbox).where(SecurityMailOutbox.token_id == token.id))
        ciphertext = row.payload
        assert token.raw_token.encode() not in ciphertext
    url = make_url(os.environ["TEST_POSTGRES_DATABASE_URL"])
    assert "test" in url.database
    dump = tmp_path / "iam-backup.dump"
    env = dict(
        os.environ,
        PGHOST=url.host,
        PGPORT=str(url.port or 5432),
        PGUSER=url.username,
        PGPASSWORD=url.password,
        PGDATABASE=url.database,
    )
    pg_dump = shutil.which("pg_dump") or "/Library/PostgreSQL/18/bin/pg_dump"
    pg_restore = str(Path(pg_dump).with_name("pg_restore"))
    prefix = []
    container = os.getenv("SBOM_ACCEPTANCE_PG_CONTAINER")
    if container:
        # Explicit opt-in to the matching client in the local test DB container.
        env["PGHOST"], env["PGPORT"] = "127.0.0.1", "5432"
        prefix = [
            "docker",
            "exec",
            "-i",
            "-e",
            "PGHOST",
            "-e",
            "PGPORT",
            "-e",
            "PGUSER",
            "-e",
            "PGPASSWORD",
            "-e",
            "PGDATABASE",
            container,
        ]
        pg_dump, pg_restore = "pg_dump", "pg_restore"
    with os.fdopen(os.open(dump, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
        result = subprocess.run([*prefix, pg_dump, "-Fc"], env=env, stdout=output, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, "pg_dump failed; diagnostics withheld"
    dump.chmod(0o600)
    name = "sbom_restore_test_" + uuid.uuid4().hex[:10]
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True)
    with admin.connect() as conn:
        conn.execute(text("CREATE DATABASE " + name))
    restored = None
    try:
        env["PGDATABASE"] = name
        with dump.open("rb") as source:
            result = subprocess.run(
                [*prefix, pg_restore, "--no-owner", "--no-acl", "-d", name],
                env=env,
                stdin=source,
                capture_output=True,
                timeout=60,
            )
        assert result.returncode == 0, "pg_restore failed; diagnostics withheld"
        restored = create_engine(url.set(database=name), hide_parameters=True)
        with restored.connect() as conn:
            assert conn.scalar(text("SELECT version_num FROM alembic_version")) == "062_native_platform_bootstrap"
            assert conn.scalar(text("SELECT count(*) FROM tenant_users WHERE user_id=:id"), {"id": uid}) == 1
            assert (
                conn.scalar(text("SELECT payload FROM security_mail_outbox WHERE token_id=:id"), {"id": token.id})
                == ciphertext
            )
            assert conn.scalar(text("SELECT count(*) FROM native_user_credentials WHERE user_id=:id"), {"id": uid}) == 1
            assert conn.scalar(text("SELECT count(*) FROM authorization_audit_log")) > 0
            assert inspect(conn).get_indexes("security_mail_outbox")
            assert inspect(conn).get_check_constraints("security_mail_outbox")
            assert (
                conn.scalar(
                    text(
                        "SELECT count(*) FROM tenant_user_role_assignments WHERE tenant_user_id IN (SELECT id FROM tenant_users WHERE user_id=:id)"
                    ),
                    {"id": uid},
                )
                == 2
            )
    finally:
        if restored:
            restored.dispose()
        with admin.connect() as conn:
            conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        admin.dispose()
