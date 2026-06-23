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
    from app.core.security import _upsert_user
    from app.db import Base, SessionLocal, engine
    from sqlalchemy import text

    # Ensure tables are created in the test database
    Base.metadata.create_all(bind=engine)

    # Verify that _upsert_user only marks needs_commit if fields actually changed
    claims = {
        "sub": "test-user-concurrency-1",
        "email": "test-concurrency-1@example.com",
        "name": "Test Concurrency 1",
    }

    db = SessionLocal()
    try:
        # Clear existing test user if any
        db.execute(text("DELETE FROM iam_users WHERE external_iam_user_id = :id"), {"id": claims["sub"]})
        db.commit()

        # 1st upsert: User is created, needs_commit should be True
        user1, needs_commit1 = _upsert_user(db, claims)
        assert needs_commit1 is True
        db.commit()

        # 2nd upsert: User is identical, needs_commit should be False
        user2, needs_commit2 = _upsert_user(db, claims)
        assert needs_commit2 is False

        # 3rd upsert: Email changed, needs_commit should be True
        claims["email"] = "test-concurrency-changed@example.com"
        user3, needs_commit3 = _upsert_user(db, claims)
        assert needs_commit3 is True
        db.commit()
    finally:
        db.close()


def test_auth_context_caching(app):
    from datetime import UTC, datetime

    from app.core.security import _resolve_context, _upsert_user, get_current_tenant_context
    from app.db import Base, SessionLocal, engine
    from app.models import Tenant, TenantUser
    from sqlalchemy import select

    # Ensure tables are created in the test database
    Base.metadata.create_all(bind=engine)

    # Verify context caching and direct early DB close
    claims = {
        "sub": "test-user-cache-1",
        "email": "test-cache-1@example.com",
        "name": "Test Cache 1",
        "exp": time.time() + 300,
        "iat": 123456,
    }

    db = SessionLocal()
    try:
        # Seed default tenant and membership for the test user to allow tenant validation to pass
        now = datetime.now(UTC)
        tenant = db.execute(select(Tenant).where(Tenant.slug == "default")).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(
                name="Default Tenant",
                slug="default",
                external_iam_tenant_id="local-default",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(tenant)
            db.flush()

        user, _ = _upsert_user(db, claims)
        membership = db.execute(
            select(TenantUser).where(TenantUser.tenant_id == tenant.id, TenantUser.user_id == user.id)
        ).scalar_one_or_none()
        if membership is None:
            membership = TenantUser(
                tenant_id=tenant.id,
                user_id=user.id,
                role="PLATFORM_ADMIN",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(membership)
            db.flush()
        db.commit()

        # Resolve once to set cache
        context = _resolve_context(db, claims, None)

        # Verify get_current_tenant_context retrieves from cache

        # 1. First iteration (cache miss, resolves and caches)
        generator = get_current_tenant_context(request=None, claims=claims, x_tenant_id=None, db=db)
        resolved_context = next(generator)
        assert resolved_context.user_id == context.user_id

        # 2. Second iteration (cache hit, closes db and yields cached context)
        class MockSession:
            def __init__(self):
                self.is_active = True

            def close(self):
                self.is_active = False

        mock_db = MockSession()
        generator_cached = get_current_tenant_context(request=None, claims=claims, x_tenant_id=None, db=mock_db)  # type: ignore
        cached_context = next(generator_cached)

        assert cached_context.user_id == context.user_id
        assert mock_db.is_active is False
    finally:
        db.close()


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
