"""Exercise the additive migration on the disposable PostgreSQL test database."""

from tests.historical_migration_fixture import historical_database as _historical_database

historical_database = _historical_database
import pytest
from alembic import command
from alembic.config import Config
from app.db import SessionLocal
from app.models import UserIdentity
from sqlalchemy import MetaData, Table, func, select

from tests.phase6_helpers import now


def seed_user(db, *, status="ACTIVE"):
    """Use the actual pre-101 table, never today's ORM against revision 063."""
    from types import SimpleNamespace
    from uuid import uuid4

    users = Table("iam_users", MetaData(), autoload_with=db.get_bind())
    assert "public_id" not in users.c
    suffix = uuid4().hex
    values = {
        "external_iam_user_id": "historical-" + suffix,
        "external_issuer": "https://hcl-cs.test",
        "external_subject": "subject-" + suffix,
        "email": suffix + "@example.test",
        "display_name": "Synthetic historical account",
        "status": status,
        "email_verified": True,
        "email_verified_at": now(),
        "verification_required": False,
        "created_at": now(),
        "updated_at": now(),
    }
    identity = db.execute(users.insert().values(**values).returning(users.c.id)).scalar_one()
    return SimpleNamespace(id=identity, **values)


@pytest.fixture(autouse=True)
def preserve_test_logging(monkeypatch):
    # In-process migrations must not disable loggers used by later tests.
    monkeypatch.setattr("logging.config.fileConfig", lambda *args, **kwargs: None)


def test_upgrade_preserves_existing_providers_and_downgrade_protects_entra(historical_database):
    config = Config("alembic.ini")
    with SessionLocal() as db:
        hcl = seed_user(db)
        native = seed_user(db)
        db.add_all([
            UserIdentity(user_id=hcl.id, provider_type="HCL_CS", issuer=hcl.external_issuer,
                         subject=hcl.external_subject, created_at=now(), updated_at=now()),
            UserIdentity(user_id=native.id, provider_type="NATIVE", provider_identifier=native.email,
                         created_at=now(), updated_at=now()),
        ])
        db.commit()
    try:
        command.downgrade(config, "062_native_platform_bootstrap")
        command.upgrade(config, "head")
        with SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(UserIdentity)) == 2
            user = seed_user(db, status="PENDING")
            db.add(UserIdentity(user_id=user.id, provider_type="MICROSOFT_ENTRA",
                issuer="https://login.microsoftonline.com/test/v2.0", subject="immutable-object-id",
                created_at=now(), updated_at=now()))
            db.commit()
        with pytest.raises(RuntimeError, match="Cannot downgrade"):
            command.downgrade(config, "062_native_platform_bootstrap")
        with SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(UserIdentity)) == 3
    finally:
        command.upgrade(config, "head")


def test_downgrade_preserves_suspended_accounts(historical_database):
    with SessionLocal() as db:
        seed_user(db, status="SUSPENDED")
        db.commit()
    with pytest.raises(RuntimeError, match="Cannot downgrade"):
        command.downgrade(Config("alembic.ini"), "062_native_platform_bootstrap")
