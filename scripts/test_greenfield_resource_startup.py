"""Opt-in real backup/upgrade acceptance on NEW synthetic databases only.

Run explicitly with SBOM_RUN_STARTUP102_ACCEPTANCE=1. Never connects to the
populated application database; retained rehearsal databases are recovery proof.
"""

from __future__ import annotations

import json
import os
import secrets
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SBOM_RUN_STARTUP102_ACCEPTANCE") != "1", reason="opt-in NEW disposable startup102 databases"
)


@pytest.fixture
def synthetic(monkeypatch, tmp_path, request):
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    from scripts import greenfield_migrations as common

    stack = common.stack
    stack.verify_resources()  # read-only metadata, no container lifecycle
    password = stack.read_private("setup-password")
    identities = stack.read_private("docker-identities.json")
    control_url = make_url(stack.url("greenfield_setup", "setup-password", "postgres"))
    assert (control_url.host, control_url.port, control_url.username, control_url.database) == (
        "127.0.0.1",
        56044,
        "greenfield_setup",
        "postgres",
    )
    name = "sbom_startup102_" + uuid.uuid4().hex[:12] + "_test"
    control = create_engine(control_url, isolation_level="AUTOCOMMIT", hide_parameters=True, poolclass=NullPool)
    with control.connect() as c:
        assert (
            c.exec_driver_sql("SELECT system_identifier::text FROM pg_control_system()").scalar_one()
            == "7698349709013049382"
        )
        assert not c.execute(
            text("SELECT EXISTS(SELECT FROM pg_database WHERE datname=:name)"), {"name": name}
        ).scalar_one()
        c.exec_driver_sql("CREATE DATABASE " + name + " TEMPLATE template0")
    control.dispose()
    # Only these in-memory credential/identity values are reused. No secret
    # copies or app settings are written to the test's evidence directory.
    monkeypatch.setattr(stack, "DB", name)
    monkeypatch.setattr(stack, "STATE", tmp_path)
    monkeypatch.setattr(
        stack, "read_private", {"setup-password": password, "docker-identities.json": identities}.__getitem__
    )
    tmp_path.chmod(0o700)
    log = Path(os.environ["SBOM_STARTUP102_EVIDENCE"])
    fd = os.open(
        log / "new-test-databases.private.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "a") as out:
        out.write(json.dumps({"database": name}) + "\n")

    from app.greenfield_schema import application_metadata
    from app.iam_schema import apply_user_uuid_revision
    from app.public_identity import install_guards
    from app.resource_schema import revision100_metadata
    from app.services.password_service import hash_password

    prepare = create_engine(control_url.set(database=name), hide_parameters=True, poolclass=NullPool)
    with prepare.begin() as c:
        c.exec_driver_sql("SET TRANSACTION READ WRITE")
        c.exec_driver_sql("ALTER SCHEMA public OWNER TO greenfield_owner")
        c.exec_driver_sql("SET LOCAL ROLE greenfield_owner")
        metadata = revision100_metadata(application_metadata())
        metadata.create_all(c)
        install_guards(c)
        c.exec_driver_sql("CREATE TABLE public.alembic_version(version_num varchar(128) PRIMARY KEY)")
        c.exec_driver_sql("INSERT INTO alembic_version VALUES('100_greenfield_uuid_final')")
        c.exec_driver_sql(
            "INSERT INTO tenants(id,name,slug,status,created_at,updated_at) VALUES(1,'Startup synthetic','startup-synthetic','ACTIVE',now(),now())"
        )
        for uid in (101, 102):
            c.execute(
                text(
                    "INSERT INTO iam_users(id,email,status,email_verified,email_verified_at,verification_required,created_at,updated_at) VALUES(:id,:email,'ACTIVE',true,now(),false,now(),now())"
                ),
                {"id": uid, "email": f"startup-{uid}@synthetic.example.test"},
            )
            c.execute(
                text(
                    "INSERT INTO user_identities(user_id,provider_type,provider_identifier,created_at,updated_at) VALUES(:id,'NATIVE',:email,now(),now())"
                ),
                {"id": uid, "email": f"startup-{uid}@synthetic.example.test"},
            )
            c.execute(
                text(
                    "INSERT INTO native_user_credentials(user_id,password_hash,password_hash_scheme,password_changed_at,created_at,updated_at) VALUES(:id,:hash,'argon2id',now(),now(),now())"
                ),
                {"id": uid, "hash": hash_password(secrets.token_urlsafe(32) + "!Aa9")},
            )
            c.execute(
                text(
                    "INSERT INTO tenant_users(tenant_id,user_id,role,status,created_at,updated_at) VALUES(1,:id,'VIEWER','ACTIVE',now(),now())"
                ),
                {"id": uid},
            )
        c.exec_driver_sql(
            "INSERT INTO platform_user_roles(user_id,role,status,created_at,updated_at) VALUES(101,'PLATFORM_ADMIN','ACTIVE',now(),now())"
        )
        c.exec_driver_sql(
            "INSERT INTO authorization_roles(id,code,name,scope,created_at,updated_at) VALUES(1,'VIEWER','Synthetic Viewer','TENANT',now(),now())"
        )
        c.exec_driver_sql(
            "INSERT INTO tenant_user_role_assignments(tenant_id,tenant_user_id,role_id,assignment_source,assigned_at,created_at,updated_at) SELECT 1,id,1,'SYSTEM',now(),now(),now() FROM tenant_users"
        )
        logical = c.exec_driver_sql(
            "INSERT INTO logical_sbom(tenant_id,name,created_at,updated_at) "
            "VALUES(1,'Synthetic startup history','2026-10-22','2026-10-22') RETURNING id"
        ).scalar_one()
        source = c.execute(
            text(
                "INSERT INTO sbom_source(tenant_id,logical_sbom_id,sbom_name,sbom_data) "
                "VALUES(1,:logical,'Synthetic startup history','{}') RETURNING id"
            ),
            {"logical": logical},
        ).scalar_one()
        runs = metadata.tables["analysis_run"]
        run = c.execute(
            runs.insert()
            .values(
                tenant_id=1,
                sbom_id=source,
                run_status="OK",
                source="OSV",
                started_on="2026-10-22",
                completed_on="2026-10-22",
            )
            .returning(runs.c.id)
        ).scalar_one()
        c.execute(
            metadata.tables["analysis_finding"]
            .insert()
            .values(tenant_id=1, analysis_run_id=run, vuln_id="CVE-2026-12345")
        )
        c.exec_driver_sql(
            "INSERT INTO authorization_audit_log(actor_user_id,target_user_id,target_membership_id,tenant_id,action,outcome,created_at) SELECT 101,102,id,1,'SYNTHETIC_STARTUP102','SUCCESS',now() FROM tenant_users LIMIT 1"
        )
        if getattr(request, "param", "101") == "101":
            apply_user_uuid_revision(c)
    prepare.dispose()
    engine = common.engine()
    try:
        yield engine, tmp_path
    finally:
        engine.dispose()  # all new test/rehearsal databases retained, no cleanup


def test_real_101_102_backup_restore_data_parity_and_already_current_start(synthetic, monkeypatch):
    from scripts import greenfield_migrations as common
    from scripts import greenfield_resource_migrations as unit

    engine, state = synthetic
    before = unit.before_upgrade(engine)
    common.ensure_current(confirm=lambda: unit.CONFIRMATION)
    with engine.connect() as c:
        unit.validate_after(c, before)
        assert common.snapshot(c, omit_public_id_tables=unit.TABLES)["data"] == before["data"]
        c.rollback()
    folders = list((state / "upgrade-backups").iterdir())
    assert len(folders) == 1
    assert (folders[0] / "database.dump.fernet").stat().st_mode & 0o777 == 0o600
    assert json.loads((folders[0] / "backup-verified.json").read_text())["restored_revision"] == unit.PREVIOUS
    assert json.loads((folders[0] / "upgrade-accepted.json").read_text())["revision"] == unit.CURRENT
    assert not (state / "pending-schema-upgrade.json").exists()
    monkeypatch.setattr(unit, "apply_revision", lambda c: pytest.fail("must not replay 102"))
    common.ensure_current(confirm=lambda: pytest.fail("must not prompt on valid 102"))


def test_real_precommit_failure_preserves101_and_all_data(synthetic, monkeypatch):
    from scripts import greenfield_migrations as common
    from scripts import greenfield_resource_migrations as unit

    engine, state = synthetic
    before = unit.before_upgrade(engine)
    actual = unit.apply_revision

    def fail(c):
        actual(c)
        raise RuntimeError("synthetic failure after real 102 body and marker")

    monkeypatch.setattr(unit, "apply_revision", fail)
    with pytest.raises(common.SchemaUpgradeError, match="precommit migration"):
        common.ensure_current(confirm=lambda: unit.CONFIRMATION)
    with engine.connect() as c:
        assert unit.snapshot(c) == before
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() == [unit.PREVIOUS]
        assert (
            c.exec_driver_sql("SELECT to_regprocedure('public.resource_public_identity_guard_v1()')").scalar_one()
            is None
        )
        c.rollback()
    assert (state / "pending-schema-upgrade.json").exists()
    with pytest.raises(common.SchemaUpgradeError, match="manual reconciliation"):
        common.ensure_current(confirm=lambda: pytest.fail("consumed attempt must not prompt"))


@pytest.mark.parametrize("synthetic", ["100"], indirect=True)
def test_real_legacy100_101_backup_and_upgrade_remains_supported(synthetic, monkeypatch):
    from scripts import greenfield_migrations as common

    monkeypatch.setattr(common.stack, "REVISION", common.CURRENT)
    engine, state = synthetic
    before = common.before_upgrade(engine)
    common._ensure_unit(common, confirm=lambda: common.CONFIRMATION)
    with engine.connect() as c:
        common.validate_after(c, before)
        c.rollback()
    assert not (state / "pending-schema-upgrade.json").exists()


def test_future103_discovered_and_validated_without_launcher_edit(synthetic, monkeypatch, tmp_path):
    import shutil

    from scripts import greenfield_auto_migrations as automatic
    from scripts import greenfield_migrations as common
    from scripts import greenfield_resource_migrations as unit

    engine, state = synthetic
    root = tmp_path / "future-checkout"
    for directory in ("alembic/versions", "app", "scripts"):
        shutil.copytree(
            common.stack.ROOT / directory, root / directory, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
    code = """
from __future__ import annotations
revision = "103_synthetic_startup_probe"
down_revision = "102_public_membership_grant_analysis_uuid"
branch_labels = None
depends_on = None
startup = {"version": 1, "tables": ("tenant_users",), "advisory_key": 7160085103,
           "description": "Add a nullable synthetic test column; preserve all existing rows and privileges."}
def startup_preflight(c):
    return not c.exec_driver_sql("SELECT EXISTS(SELECT FROM pg_attribute WHERE attrelid='public.tenant_users'::regclass AND attname='startup_probe' AND NOT attisdropped)").scalar_one()
def upgrade():
    from alembic import op
    op.get_bind().exec_driver_sql("ALTER TABLE public.tenant_users ADD COLUMN startup_probe text")
def startup_validate(c, before):
    from scripts import greenfield_migrations as common
    import hashlib
    column = c.exec_driver_sql("SELECT format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid='public.tenant_users'::regclass AND attname='startup_probe' AND NOT attisdropped").all()
    if [tuple(r) for r in column] != [('text', False)]:
        raise RuntimeError('Synthetic column mismatch')
    after = common.snapshot(c, omit_public_id_tables=())
    if before is not None:
        kept = [r for r in after['catalog']['columns'] if r[:2] != ['tenant_users','startup_probe']]
        if kept != before['catalog']['columns'] or len(after['catalog']['columns']) != len(kept)+1:
            raise RuntimeError('Unreviewed column delta')
        for key in before['catalog']:
            if key != 'columns' and after['catalog'][key] != before['catalog'][key]:
                raise RuntimeError('Unexpected catalog/security change')
        digest = hashlib.sha256()
        count = 0
        for row in c.exec_driver_sql("SELECT (to_jsonb(t)-'startup_probe')::text FROM tenant_users t ORDER BY (to_jsonb(t)-'startup_probe')::text"):
            count += 1
            digest.update(row[0].encode()+b'\\n')
        after['data']['tenant_users'] = [count,digest.hexdigest()]
        if after['data'] != before['data']:
            raise RuntimeError('Existing UUID/row data changed')
    return True
"""
    (root / "alembic/versions/103_synthetic_startup_probe.py").write_text(code)
    monkeypatch.setattr(common.stack, "ROOT", root)
    answers = iter([unit.CONFIRMATION, "UPGRADE " + common.stack.DB + " 102 TO 103"])
    common.ensure_current(confirm=lambda: next(answers))
    with engine.connect() as c:
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() == [
            "103_synthetic_startup_probe"
        ]
        c.rollback()
    common.ensure_current(confirm=lambda: pytest.fail("no approval on already validated current revision"))
    backups = list((state / "upgrade-backups").iterdir())
    assert len(backups) == 2
    assert all((p / "approved-source-snapshot.json").exists() for p in backups)
    assert automatic.discover(root).head == "103_synthetic_startup_probe"
