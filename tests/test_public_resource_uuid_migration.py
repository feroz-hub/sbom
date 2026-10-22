"""Synthetic populated 100→101→102, atomic rollback and integer-graph parity."""

from uuid import UUID

import pytest
from app.iam_schema import apply_user_uuid_revision
from app.resource_schema import apply_resource_uuid_revision
from sqlalchemy import inspect

from tests.test_iam_user_uuid_migration import legacy as legacy
from tests.test_iam_user_uuid_migration import snapshot


def seed_history(connection):
    from app.models import SBOMSource
    from sqlalchemy.orm import Session

    from tests.tenant_fixture_scope import verified_fixture_tenant

    with Session(bind=connection) as db, verified_fixture_tenant(db, 1):
        row = SBOMSource(tenant_id=1, sbom_name="Synthetic history", sbom_data="{}")
        db.add(row)
        db.flush()
        source = row.id
        db.commit()
    from app.greenfield_schema import application_metadata
    from app.resource_schema import revision100_metadata

    tables = revision100_metadata(application_metadata()).tables
    run = connection.execute(
        tables["analysis_run"]
        .insert()
        .values(
            tenant_id=1,
            sbom_id=source,
            run_status="OK",
            source="OSV",
            started_on="2026-10-21",
            completed_on="2026-10-21",
        )
        .returning(tables["analysis_run"].c.id)
    ).scalar_one()
    connection.execute(
        tables["analysis_finding"].insert().values(tenant_id=1, analysis_run_id=run, vuln_id="CVE-2026-12345")
    )
    member = connection.exec_driver_sql("SELECT id FROM tenant_users ORDER BY id LIMIT 1").scalar_one()
    connection.exec_driver_sql(
        f"INSERT INTO authorization_audit_log(actor_user_id,target_user_id,target_membership_id,tenant_id,action,outcome,created_at) VALUES(101,102,{member},1,'SYNTHETIC_UUID_REVIEW','SUCCESS',now())"
    )


def full_snapshot(c):
    result = snapshot(c)
    for name in ("analysis_run", "analysis_finding", "authorization_audit_log"):
        result[name] = c.exec_driver_sql(f"SELECT to_jsonb(t)-'public_id' FROM {name} t ORDER BY id").scalars().all()
    return result


def test_populated_100_101_102_preserves_every_existing_value_and_foreign_key(legacy):
    with legacy.begin() as c:
        seed_history(c)
    with legacy.connect() as c:
        before = full_snapshot(c)
    with legacy.begin() as c:
        apply_user_uuid_revision(c)
    with legacy.begin() as c:
        apply_resource_uuid_revision(c)
    with legacy.connect() as c:
        assert full_snapshot(c) == before
        assert (
            c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "102_public_membership_grant_analysis_uuid"
        )
        for name in ("tenant_users", "platform_user_roles", "analysis_run"):
            rows = c.exec_driver_sql(f"SELECT id,public_id FROM {name}").all()
            assert rows and len({r.public_id for r in rows}) == len(rows)
            assert all(type(r.id) is int and isinstance(r.public_id, UUID) and r.public_id.version == 4 for r in rows)
            assert not next(col for col in inspect(c).get_columns(name) if col["name"] == "public_id")["nullable"]


def test_revision102_precommit_failure_rolls_back_columns_backfill_guards_and_marker(legacy):
    with legacy.begin() as c:
        seed_history(c)
        apply_user_uuid_revision(c)
    with legacy.connect() as c:
        before = full_snapshot(c)
    with pytest.raises(RuntimeError, match="synthetic"):
        with legacy.begin() as c:
            apply_resource_uuid_revision(c)
            raise RuntimeError("synthetic precommit failure")
    with legacy.connect() as c:
        assert full_snapshot(c) == before
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "101_iam_user_public_uuid"
        assert (
            c.exec_driver_sql("SELECT to_regprocedure('public.resource_public_identity_guard_v1()')").scalar_one()
            is None
        )
        for name in ("tenant_users", "platform_user_roles", "analysis_run"):
            assert "public_id" not in {col["name"] for col in inspect(c).get_columns(name)}


def test_revision102_refuses_skipped_101(legacy):
    with pytest.raises(RuntimeError, match="exactly revision 101"):
        with legacy.begin() as c:
            apply_resource_uuid_revision(c)
    with legacy.connect() as c:
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "100_greenfield_uuid_final"


def test_revision102_refuses_sqlalchemy_transaction_over_dbapi_autocommit(legacy):
    with legacy.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        with pytest.raises(RuntimeError, match="DBAPI autocommit"):
            with c.begin():
                apply_resource_uuid_revision(c)
    with legacy.connect() as c:
        assert "public_id" not in {col["name"] for col in inspect(c).get_columns("analysis_run")}
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "100_greenfield_uuid_final"
