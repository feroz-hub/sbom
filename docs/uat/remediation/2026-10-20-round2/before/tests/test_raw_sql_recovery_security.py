"""Batch B recovery must not create an operator path for tenant SQL."""

import pytest
from app.core.context import get_bound_context, tenant_scope
from app.db import SessionLocal, TenantContextRequired
from app.models import Projects
from sqlalchemy import select, text, update

from tests.tenant_fixture_scope import declare_fixture_tenant, fixture_business_snapshot, verified_fixture_tenant


@pytest.fixture()
def owned_rows():
    with SessionLocal() as db, tenant_scope(None):
        declare_fixture_tenant(db, 2)
        db.commit()
        identifiers = {}
        for owner in (1, 2):
            with verified_fixture_tenant(db, owner):
                row = Projects(tenant_id=owner, project_name=f"batch-b-owner-{owner}")
                db.add(row)
                db.commit()
                identifiers[owner] = row.id
        yield db, identifiers
        assert get_bound_context() is None


def test_exact_fixture_snapshots_preserve_both_owners_and_restore_context(owned_rows):
    db, identifiers = owned_rows
    rows = fixture_business_snapshot(db, (Projects,), (1, 2))
    assert len(rows[1, "projects"]) == len(rows[2, "projects"]) == 1
    assert rows[1, "projects"] != rows[2, "projects"]
    assert get_bound_context() is None
    with pytest.raises(TenantContextRequired):
        db.scalar(select(Projects.id))
    with verified_fixture_tenant(db, 1):
        assert db.scalar(select(Projects.id).where(Projects.id == identifiers[2])) is None
        original = get_bound_context()
        with pytest.raises(ValueError):
            fixture_business_snapshot(db, (Projects,), (987654,))
        assert get_bound_context() is original


@pytest.mark.parametrize("sql", ["SELECT * FROM projects", "UPDATE projects SET project_name='pwned'", "DELETE FROM projects"])
def test_operator_named_execution_options_cannot_enable_raw_sql(owned_rows, sql):
    db, _ = owned_rows
    before = fixture_business_snapshot(db, (Projects,), (1, 2))
    with verified_fixture_tenant(db, 1):
        with pytest.raises(RuntimeError, match="Raw SQL"):
            db.execute(text(sql).execution_options(bypass_tenant_filter=True, operator=True))
        db.rollback()
    assert fixture_business_snapshot(db, (Projects,), (1, 2)) == before


def test_core_bound_injection_input_cannot_select_or_mutate_foreign_records(owned_rows):
    db, identifiers = owned_rows
    before = fixture_business_snapshot(db, (Projects,), (1, 2))
    malicious = "' OR 1=1; DROP TABLE projects; --"
    with verified_fixture_tenant(db, 1):
        assert db.scalars(select(Projects.id).where(Projects.project_name == malicious)).all() == []
        result = db.execute(update(Projects).where(Projects.project_name == malicious).values(project_name="changed"))
        assert result.rowcount == 0
        # Even an explicit foreign key and an operator-like input flag cannot change its owner.
        result = db.execute(update(Projects).where(Projects.id == identifiers[2]).values(project_name=malicious)
                            .execution_options(bypass_tenant_filter=True))
        assert result.rowcount == 0
        db.commit()
    assert fixture_business_snapshot(db, (Projects,), (1, 2)) == before


def test_fixture_declaration_does_not_reactivate_disabled_tenant():
    with SessionLocal() as db, tenant_scope(None):
        declare_fixture_tenant(db, 2, status="DISABLED")
        db.commit()
        with pytest.raises(ValueError, match="status"):
            declare_fixture_tenant(db, 2)
        with pytest.raises(ValueError, match="active"):
            with verified_fixture_tenant(db, 2):
                pytest.fail("disabled owner accepted")
        assert get_bound_context() is None
