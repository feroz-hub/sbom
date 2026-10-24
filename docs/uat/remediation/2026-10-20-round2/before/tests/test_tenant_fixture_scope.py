"""The opt-in fixture scope must preserve the production security boundary."""

from datetime import UTC, datetime

import pytest
from app.core.context import get_bound_context, tenant_scope
from app.db import SessionLocal, TenantContextRequired
from app.models import Projects, Tenant
from sqlalchemy import select

from tests.tenant_fixture_scope import verified_fixture_tenant

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("tenant_id", [None, True, 0, -1, 987654])
def test_fixture_scope_rejects_unknown_or_invalid_tenant(tenant_id):
    with SessionLocal() as db, tenant_scope(None):
        with pytest.raises(ValueError):
            with verified_fixture_tenant(db, tenant_id):
                pytest.fail("unverified tenant accepted")
        assert get_bound_context() is None


def test_fixture_scope_rejects_inactive_tenant():
    with SessionLocal() as db:
        now = datetime.now(UTC)
        row = Tenant(name="Inactive", slug="fixture-inactive", status="DISABLED", created_at=now, updated_at=now)
        db.add(row)
        db.commit()
        with pytest.raises(ValueError, match="active"):
            with verified_fixture_tenant(db, row.id):
                pytest.fail("inactive tenant accepted")


def test_fixture_scope_restores_context_after_success_failure_and_nested_scope():
    with SessionLocal() as db, tenant_scope(None):
        with verified_fixture_tenant(db, 1):
            original = get_bound_context()
            assert original.tenant_id == 1
            assert not original.has_permission("platform:user:manage_status")
            with pytest.raises(RuntimeError, match="simulated"):
                with verified_fixture_tenant(db, 1):
                    raise RuntimeError("simulated")
            assert get_bound_context() is original
            db.add(Projects(project_name="fixture-owned"))
            db.commit()
            assert db.scalar(select(Projects.id)) is not None
        assert get_bound_context() is None
        with pytest.raises(TenantContextRequired):
            db.scalars(select(Projects)).all()


def test_fixture_scope_does_not_allow_foreign_tenant_writes():
    with SessionLocal() as db, tenant_scope(None):
        with verified_fixture_tenant(db, 1):
            db.add(Projects(project_name="fixture-foreign", tenant_id=987654))
            with pytest.raises(RuntimeError, match="Cross-tenant insert blocked"):
                db.flush()
            db.rollback()
            assert db.scalar(select(Projects.id)) is None
        assert get_bound_context() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_auth_override_restores_context_without_changing_actor(fail):

    from tests.tenant_fixture_scope import scoped_context_override

    with SessionLocal() as db, tenant_scope(None):
        with verified_fixture_tenant(db, 1):
            actor = get_bound_context()
        dependency = scoped_context_override(lambda: actor)
        generator = dependency()
        assert await anext(generator) is actor
        assert get_bound_context() is actor
        assert not actor.has_permission("platform:user:manage_status")
        if fail:
            with pytest.raises(RuntimeError, match="simulated"):
                await generator.athrow(RuntimeError("simulated"))
        else:
            await generator.aclose()
        assert get_bound_context() is None
        with pytest.raises(TenantContextRequired):
            db.scalars(select(Projects)).all()
