from __future__ import annotations

from app.db import SessionLocal, engine
from app.models import AuthorizationAuditLog, PlatformUserRole
from app.services import platform_service
from sqlalchemy import event, select

from tests.phase6_helpers import (
    seed_dev_platform_admin,
    seed_membership,
    seed_platform_grant,
    seed_user,
)


def test_platform_user_listing_is_bounded_stable_and_redacted(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        seed_user(db, display_name="Customer account")
        db.commit()
    for query in ("?page=1&page_size=2", "?page_size=101", "?created_from=not-a-date"):
        response = client.get("/api/platform/users" + query)
        assert response.status_code == 403, response.text
        assert "Customer account" not in response.text


def test_platform_user_search_and_filters(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
    for query in ("?search=customer", "?tenant_id=1", "?provider=NATIVE", "?local_status=ACTIVE"):
        assert client.get("/api/platform/users" + query).status_code == 403


def test_platform_user_detail_contains_only_safe_membership_summary(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        target = seed_user(db)
        seed_membership(db, target)
        target_id = target.id
        db.commit()
    for user_id in (target_id, 999999):
        assert client.get(f"/api/platform/users/{user_id}").status_code == 403


def test_platform_user_listing_uses_bounded_query_count():
    with SessionLocal() as db:
        admin = seed_user(db)
        seed_platform_grant(db, admin)
        for _ in range(8):
            seed_user(db)
        db.commit()

    statements: list[str] = []

    def record_statement(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with SessionLocal() as db:
            result = platform_service.list_platform_users(
                db,
                page=1,
                page_size=10,
            )
            assert len(result.items) == 9
    finally:
        event.remove(engine, "before_cursor_execute", record_statement)
    assert len(statements) == 2


def test_platform_user_list_audit_is_one_request_level_record(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
    assert client.get("/api/platform/users?search=Customer").status_code == 403
    with SessionLocal() as db:
        records = list(db.scalars(select(AuthorizationAuditLog).where(
            AuthorizationAuditLog.action == "PLATFORM_PERMISSION_DENIED"
        )))
        assert len(records) == 1
        assert records[0].tenant_id is None
        assert "Customer" not in str(records[0].new_value)


def test_platform_user_views_require_database_platform_authority(client):
    with SessionLocal() as db:
        user = seed_user(db)
        seed_membership(db, user, role="TENANT_ADMIN")
        db.commit()

    assert client.get("/api/platform/users").status_code == 403
    assert client.get("/api/platform/administrators").status_code == 403
    with SessionLocal() as db:
        assert db.scalar(select(PlatformUserRole)) is None
