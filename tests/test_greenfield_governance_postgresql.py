"""Opt-in revision-103 hooks on an EMPTY task-owned disposable PostgreSQL DB.

STARTUP103_TEST_DATABASE_URL must explicitly select sbom_startup103_test on a
loopback test server. This test never reads Greenfield credentials or contacts
the fixed Greenfield database. Its caller owns disposal of the test server.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import greenfield_auto_migrations as automatic
from scripts.greenfield_migration_graph import SourceLock, discover
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


def test_disposable_postgresql_103_rollback_upgrade_and_readonly_acceptance():
    address = os.environ.get("STARTUP103_TEST_DATABASE_URL")
    if not address:
        pytest.skip("requires an explicitly provided EMPTY task-owned PostgreSQL test database")
    url = make_url(address)
    assert url.get_backend_name() == "postgresql"
    assert url.host == "127.0.0.1" and url.port not in {5432, 55439, 56044}
    assert url.database == "sbom_startup103_test"
    assert url.username == "postgres"
    root = Path(__file__).resolve().parents[1]
    unit = automatic.MigrationUnit(discover(root).revisions[-1], SourceLock.capture(root))
    module = unit.module()
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.begin() as c:
            assert not inspect(c).get_table_names(schema="public"), "refusing any non-empty database"
            assert c.exec_driver_sql("SHOW server_version_num").scalar_one().startswith("16")
            # These roles and all application objects live only on the supplied
            # disposable test server; no existing cluster is accepted.
            assert not c.exec_driver_sql("SELECT 1 FROM pg_roles WHERE rolname='greenfield_owner'").first()
            c.exec_driver_sql("CREATE ROLE greenfield_owner NOLOGIN")
            c.exec_driver_sql("CREATE ROLE greenfield_app LOGIN")
            c.exec_driver_sql("ALTER SCHEMA public OWNER TO greenfield_owner")
            c.exec_driver_sql("SET LOCAL ROLE greenfield_owner")
            from app.greenfield_schema import application_metadata
            from app.iam_public_identity import install_iam_guards
            from app.resource_public_identity import install_resource_guards

            metadata = application_metadata()
            metadata.create_all(c)
            install_iam_guards(c)
            install_resource_guards(c)
            c.exec_driver_sql("CREATE TABLE public.alembic_version(version_num varchar(128) PRIMARY KEY)")
            c.execute(text("INSERT INTO alembic_version VALUES(:version)"), {"version": unit.PREVIOUS})
            now = datetime.now(UTC)
            c.execute(
                metadata.tables["iam_users"]
                .insert()
                .values(
                    id=1,
                    email="startup103@synthetic.example.test",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            )
            c.execute(
                metadata.tables["authorization_roles"]
                .insert()
                .values(
                    id=1,
                    code="PLATFORM_ADMIN",
                    name="Platform Admin",
                    scope="PLATFORM",
                    created_at=now,
                    updated_at=now,
                )
            )
            c.execute(
                metadata.tables["authorization_roles"]
                .insert()
                .values(
                    id=2,
                    code="VIEWER",
                    name="Viewer",
                    scope="TENANT",
                    created_at=now,
                    updated_at=now,
                )
            )
            c.execute(
                metadata.tables["authorization_permissions"]
                .insert()
                .values(
                    code="tenant:read",
                    name="Read tenant",
                    scope="TENANT",
                    resource="tenant",
                    action="read",
                    created_at=now,
                    updated_at=now,
                )
            )
            c.execute(
                metadata.tables["platform_user_roles"]
                .insert()
                .values(
                    user_id=1,
                    role="PLATFORM_ADMIN",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            )
            assert module.startup_preflight(c) is True
            before = unit.snapshot(c)
            # A failed acceptance rolls the permission, role version and marker
            # back together with the caller-owned protected transaction.
            with pytest.raises(RuntimeError, match="identity, assignment, history or business"):
                with c.begin_nested():
                    unit.apply_revision(c)
                    c.execute(text("UPDATE iam_users SET display_name='Unapproved change' WHERE id=1"))
                    unit.validate_after(c, before)
            assert c.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == unit.PREVIOUS
            assert (
                c.execute(
                    text("SELECT count(*) FROM authorization_permissions WHERE code=:code"), {"code": module.PERMISSION}
                ).scalar_one()
                == 0
            )
            before = unit.snapshot(c)
            unit.apply_revision(c)
            unit.validate_after(c, before)
            assert c.execute(text("SELECT version FROM authorization_roles WHERE id=1")).scalar_one() == 2
            accepted = unit.snapshot(c)
            module._seed(c)
            assert unit.snapshot(c) == accepted
        # Independent physical read-only connection: validates existing 103,
        # including inherited UUID guards, without replaying the seed.
        with engine.connect() as reader:
            reader.exec_driver_sql("SET TRANSACTION READ ONLY")
            assert module.startup_validate(reader, None) is True
            unit.validate_after(reader, before)
            assert reader.exec_driver_sql("SHOW transaction_read_only").scalar_one() == "on"
            reader.rollback()
    finally:
        engine.dispose()
