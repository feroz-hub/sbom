import time

import pytest


def test_db_session_closes_on_success_and_error(app):
    from app.db import get_db

    # Verify that get_db closes connection correctly
    generator = get_db()
    db = next(generator)
    assert db.is_active

    # Successful request simulation
    closed_called = False
    orig_close = db.close

    def mock_close():
        nonlocal closed_called
        closed_called = True
        orig_close()

    db.close = mock_close

    try:
        next(generator)
    except StopIteration:
        pass
    assert closed_called is True

    # Exception request simulation
    generator2 = get_db()
    db2 = next(generator2)
    assert db2.is_active

    closed_called2 = False
    orig_close2 = db2.close

    def mock_close2():
        nonlocal closed_called2
        closed_called2 = True
        orig_close2()

    db2.close = mock_close2

    with pytest.raises(RuntimeError):
        generator2.throw(RuntimeError("Test error"))
    assert closed_called2 is True


def test_upsert_user_no_dirty_commits(app):
    """Current provisioning API reports real profile changes and owns no commit."""
    from unittest.mock import patch

    from app.db import SessionLocal
    from app.services.identity_service import provision_local_identity

    claims = {
        "iss": "https://hcl-cs.test", "sub": "test-user-concurrency-1",
        "email": "test-concurrency-1@example.test", "name": "Test Concurrency 1",
        "preferred_username": "test-concurrency-1@example.test", "employee_id": "POOL-1",
    }
    with SessionLocal() as db, patch.object(db, "commit", wraps=db.commit) as commit:
        first = provision_local_identity(db, claims)
        assert first.created and first.changed
        assert commit.call_count == 0
        db.commit()
        second = provision_local_identity(db, claims)
        assert second.user.id == first.user.id
        assert not second.created and not second.changed
        assert commit.call_count == 1
        changed = provision_local_identity(db, claims | {"email": "changed@example.test"})
        assert changed.user.id == first.user.id
        assert changed.email_changed and "email" in changed.changed_fields
        assert commit.call_count == 1
        db.commit()
        assert commit.call_count == 2


def test_auth_context_is_re_resolved_for_immediate_revocation(app):
    import asyncio

    from app.core.context import get_bound_context
    from app.core.security import _resolve_context, get_current_tenant_context
    from app.db import SessionLocal
    from fastapi import HTTPException

    from tests.phase6_helpers import identity_claims, seed_membership, seed_user
    from tests.tenant_fixture_scope import verified_fixture_tenant

    prior_context = get_bound_context()
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        user = seed_user(db)
        membership = seed_membership(db, user, role="TENANT_ADMIN")
        db.commit()
        claims = identity_claims(user, exp=time.time() + 300, iat=int(time.time()))
        context = _resolve_context(db, claims, "1")

        async def resolve_context():
            generator = get_current_tenant_context(request=None, claims=claims, x_tenant_id="1", db=db)
            try:
                return await anext(generator)
            finally:
                await generator.aclose()

        resolved_context = asyncio.run(resolve_context())
        assert resolved_context.user_id == context.user_id
        assert resolved_context.tenant_id == 1
        assert resolved_context.has_permission("project:read")
        membership.status = "DISABLED"
        db.commit()
        with pytest.raises(HTTPException) as denied:
            asyncio.run(resolve_context())
        assert denied.value.status_code == 403
    assert get_bound_context() is prior_context


def test_dashboard_summary_endpoint(app):
    from fastapi.testclient import TestClient

    # Verify dashboard summary API endpoint returns the expected keys
    with TestClient(app) as tc:
        response = tc.get("/dashboard/summary")
        assert response.status_code == 200
        data = response.json()
        for key in [
            "posture",
            "lifecycle",
            "health",
            "vex",
            "vulnerability_age",
            "trend",
            "forecast",
            "exploitation",
            "remediation",
            "remediation_stats",
            "risk_map",
            "risk_matrix",
            "recent_sboms",
            "lifetime",
        ]:
            assert key in data, f"Key {key} not found in summary payload"


def test_concurrency_small_pool(app):
    import concurrent.futures

    from app.db import engine, engine_options
    from app.settings import get_settings
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine

    settings = get_settings()
    orig_size = settings.db_pool_size
    orig_overflow = settings.db_max_overflow

    settings.db_pool_size = 2
    settings.db_max_overflow = 0

    small_engine = create_engine(engine.url, **engine_options(str(engine.url), settings))

    import app.db as app_db
    import app.main as app_main

    orig_db_engine = app_db.engine
    orig_main_engine = app_main.engine

    app_db.engine = small_engine
    app_main.engine = small_engine

    try:
        with TestClient(app) as tc:

            def make_request():
                resp = tc.get("/dashboard/summary")
                return resp.status_code

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                results = [f.result() for f in futures]

            for code in results:
                assert code == 200

            pool = small_engine.pool
            assert pool.checkedout() == 0
    finally:
        settings.db_pool_size = orig_size
        settings.db_max_overflow = orig_overflow
        app_db.engine = orig_db_engine
        app_main.engine = orig_main_engine
        small_engine.dispose()
