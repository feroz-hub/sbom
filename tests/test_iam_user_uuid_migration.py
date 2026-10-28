"""Synthetic populated revision-100 upgrades on a separate task-owned database."""

import os
from uuid import UUID

import pytest
from app.greenfield_schema import application_metadata
from app.iam_schema import apply_user_uuid_revision
from app.public_identity import install_guards
from app.resource_schema import revision100_metadata
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from tests.test_native_iam_phase2 import PASSWORD
from tests.test_native_iam_phase2 import native_config as native_config


@pytest.fixture
def legacy():
    from app.services.password_service import hash_password

    target = os.environ["IAM_UUID_UPGRADE_DATABASE_URL"]
    assert make_url(target).database in {
        "sbom_iam_public_uuid_upgrade_test",
        "sbom_public_resource_uuid_upgrade_test",
        "sbom_public_resource_uuid_focused_upgrade_test",
        # Explicitly owned by the UI display-ID regression environment.
        "sbom_ui_integer_display_upgrade_test_20261023",
        "sbom_ui_integer_display_failures_upgrade_test_20261023",
    }
    engine = create_engine(target, hide_parameters=True)
    with engine.begin() as c:
        # This exact, task-created database is reserved for upgrade fixtures only.
        c.exec_driver_sql("DROP SCHEMA public CASCADE")
        c.exec_driver_sql("CREATE SCHEMA public")
        revision100_metadata(application_metadata()).create_all(c)
        install_guards(c)
        c.exec_driver_sql("CREATE TABLE alembic_version(version_num varchar(128) PRIMARY KEY)")
        c.exec_driver_sql("INSERT INTO alembic_version VALUES('100_greenfield_uuid_final')")
        c.exec_driver_sql(
            "INSERT INTO tenants(id,name,slug,status,created_at,updated_at) VALUES(1,'Synthetic upgrade','synthetic-upgrade','ACTIVE',now(),now())"
        )
        for uid in (101, 102):
            c.execute(
                text(
                    "INSERT INTO iam_users(id,email,status,email_verified,email_verified_at,verification_required,created_at,updated_at) VALUES(:id,:email,'ACTIVE',true,now(),false,now(),now())"
                ),
                {"id": uid, "email": f"upgrade-{uid}@example.test"},
            )
            c.execute(
                text(
                    "INSERT INTO user_identities(user_id,provider_type,provider_identifier,created_at,updated_at) VALUES(:id,'NATIVE',:email,now(),now())"
                ),
                {"id": uid, "email": f"upgrade-{uid}@example.test"},
            )
            c.execute(
                text(
                    "INSERT INTO native_user_credentials(user_id,password_hash,password_hash_scheme,password_changed_at,created_at,updated_at) VALUES(:id,:hash,'argon2id',now(),now(),now())"
                ),
                {"id": uid, "hash": hash_password(PASSWORD)},
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
    try:
        yield engine
    finally:
        engine.dispose()


def snapshot(c):
    result = {}
    for name in ("iam_users", "user_identities", "native_user_credentials", "tenant_users", "platform_user_roles"):
        result[name] = (
            c.exec_driver_sql(f"SELECT to_jsonb(t) - 'public_id' FROM public.{name} t ORDER BY id").scalars().all()
        )
    result["foreign_keys"] = c.exec_driver_sql(
        "SELECT conrelid::regclass::text,conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE contype='f' ORDER BY 1,2"
    ).all()
    return result


def test_populated_upgrade_preserves_accounts_credentials_links_keys_and_grants(legacy, native_config):
    with legacy.connect() as c:
        before = snapshot(c)
    with legacy.begin() as c:
        apply_user_uuid_revision(c)
    with legacy.connect() as c:
        assert snapshot(c) == before
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "101_iam_user_public_uuid"
        identities = c.exec_driver_sql("SELECT id,public_id FROM iam_users ORDER BY id").all()
        assert [r.id for r in identities] == [101, 102]
        assert len({r.public_id for r in identities}) == 2
        assert all(isinstance(r.public_id, UUID) and r.public_id.version == 4 for r in identities)
        assert not next(x for x in inspect(c).get_columns("iam_users") if x["name"] == "public_id")["nullable"]
        assert ("public_id",) in {tuple(x["column_names"]) for x in inspect(c).get_unique_constraints("iam_users")}
        assert c.exec_driver_sql(
            "SELECT convalidated FROM pg_constraint WHERE conname='ck_iam_users_public_id_v4'"
        ).scalar_one()
    from app.models import IAMUser
    from app.services import native_auth_service, native_jwt_service

    with Session(legacy) as db:
        user = db.get(IAMUser, 101)
        public = user.public_id
        token = native_auth_service.login(db, user.email, PASSWORD)
        assert token is not None
        assert native_jwt_service.validate_token(token)["sub"] == "101"
        db.commit()
    with Session(legacy) as db:
        user = db.get(IAMUser, 101)
        assert user.public_id == public
        assert native_auth_service.login(db, user.email, PASSWORD) is not None
        assert user.id == 101 and user.public_id == public
        db.commit()


def test_precommit_failure_rolls_back_column_guard_backfill_and_marker(legacy):
    with legacy.connect() as c:
        before = snapshot(c)
    with pytest.raises(RuntimeError, match="synthetic precommit"):
        with legacy.begin() as c:
            apply_user_uuid_revision(c)
            raise RuntimeError("synthetic precommit failure")
    with legacy.connect() as c:
        assert snapshot(c) == before
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "100_greenfield_uuid_final"
        assert "public_id" not in {x["name"] for x in inspect(c).get_columns("iam_users")}
        assert (
            c.exec_driver_sql("SELECT to_regprocedure('public.iam_user_public_identity_guard_v1()')").scalar_one()
            is None
        )


def test_wrong_revision_refuses_before_schema_change(legacy):
    with legacy.begin() as c:
        c.exec_driver_sql("UPDATE alembic_version SET version_num='079_lifecycle_provider_verification'")
    with pytest.raises(RuntimeError, match="exactly revision 100"):
        with legacy.begin() as c:
            apply_user_uuid_revision(c)
    with legacy.connect() as c:
        assert "public_id" not in {x["name"] for x in inspect(c).get_columns("iam_users")}
