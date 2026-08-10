from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import SessionLocal, engine
from app.models import AuthorizationAuditLog, PlatformUserRole, TenantUser
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
        older = seed_user(db, display_name="Older Searchable")
        newer = seed_user(db, display_name="Newer Searchable")
        newer_id = newer.id
        older.created_at = datetime.now(UTC) - timedelta(days=1)
        db.commit()

    response = client.get("/api/platform/users?page=1&page_size=2")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["total"] >= 3
    assert len(body["items"]) == 2
    assert [item["id"] for item in body["items"]] == sorted(
        [item["id"] for item in body["items"]], reverse=True
    )
    serialized = response.text
    for forbidden in (
        "external_subject",
        "external_issuer",
        "external_iam_user_id",
        "token_hash",
        "email_verification_tokens",
    ):
        assert forbidden not in serialized
    assert newer_id in {item["id"] for item in body["items"]}

    assert client.get("/api/platform/users?page_size=101").status_code == 422
    assert client.get("/api/platform/users?created_from=not-a-date").status_code == 422


def test_platform_user_search_and_filters(client):
    with SessionLocal() as db:
        admin, _ = seed_dev_platform_admin(db)
        target = seed_user(
            db,
            status="ACTIVE",
            verified=True,
            email="unique.phase6@example.test",
            display_name="Unique Platform Search",
            employee_id="EMP-SEARCH-600",
        )
        target.user_principal_name = "unique.upn@example.test"
        seed_membership(db, target)
        seed_platform_grant(db, target, creator_id=admin.id)
        pending = seed_user(db, status="PENDING", verified=False)
        db.commit()
        target_id = target.id
        pending_id = pending.id

    for search in (
        "unique.phase6@",
        "Platform Search",
        "unique.upn@",
        "EMP-SEARCH-600",
    ):
        result = client.get("/api/platform/users", params={"search": search})
        assert result.status_code == 200
        assert [item["id"] for item in result.json()["items"]] == [target_id]

    assert client.get(
        "/api/platform/users",
        params={"local_status": "PENDING"},
    ).json()["items"][0]["id"] == pending_id
    verified = client.get(
        "/api/platform/users",
        params={"email_verified": "true", "is_platform_admin": "true"},
    ).json()
    assert target_id in {item["id"] for item in verified["items"]}
    by_tenant = client.get(
        "/api/platform/users",
        params={"tenant_id": 1},
    ).json()
    assert target_id in {item["id"] for item in by_tenant["items"]}

    # Wildcards are literals, not caller-controlled LIKE metacharacters.
    wildcard = client.get("/api/platform/users", params={"search": "%_"})
    assert wildcard.status_code == 200
    assert wildcard.json()["total"] == 0


def test_platform_user_detail_contains_only_safe_membership_summary(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        user = seed_user(db)
        membership = seed_membership(db, user, role="SECURITY_ANALYST")
        db.commit()
        user_id = user.id
        membership_id = membership.id

    response = client.get(f"/api/platform/users/{user_id}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == user_id
    assert body["tenant_memberships"] == [
        {
            "tenant_id": 1,
            "tenant_name": "Default Test Tenant",
            "tenant_slug": "default",
            "membership_status": "ACTIVE",
            "current_role": "SECURITY_ANALYST",
            "tenant_status": "ACTIVE",
        }
    ]
    assert "external_subject" not in body
    assert "token_hash" not in response.text
    with SessionLocal() as db:
        assert db.get(TenantUser, membership_id) is not None
        audit = db.scalar(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action == "PLATFORM_USER_DETAIL_VIEWED",
                AuthorizationAuditLog.target_user_id == user_id,
            )
        )
        assert audit is not None
        assert audit.tenant_id is None

    missing = client.get("/api/platform/users/999999")
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "IAM_USER_NOT_FOUND"


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
        for _ in range(3):
            seed_user(db)
        db.commit()

    assert client.get("/api/platform/users?search=Phase").status_code == 200
    with SessionLocal() as db:
        records = list(
            db.scalars(
                select(AuthorizationAuditLog).where(
                    AuthorizationAuditLog.action == "PLATFORM_USER_LIST_VIEWED"
                )
            )
        )
        assert len(records) == 1
        assert records[0].tenant_id is None
        assert records[0].new_value["search_applied"] is True
        assert "Phase" not in str(records[0].new_value)


def test_platform_user_views_require_database_platform_authority(client):
    with SessionLocal() as db:
        user = seed_user(db)
        seed_membership(db, user, role="TENANT_ADMIN")
        db.commit()

    assert client.get("/api/platform/users").status_code == 403
    assert client.get("/api/platform/administrators").status_code == 403
    with SessionLocal() as db:
        assert db.scalar(select(PlatformUserRole)) is None
