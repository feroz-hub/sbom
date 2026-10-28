"""Current V5 HTTP denial plus legacy search-projection unit coverage.

Ordinary Platform Admin lacks platform:user:read. Positive HTTP directory
access is intentionally unavailable; keep query/projection assertions as
explicit direct-handler unit tests, without granting a principal permissions.
SBO-73 tenant candidate discovery is a separate, unchanged policy.
"""

from __future__ import annotations

from app.core.security import get_current_user
from app.db import SessionLocal
from app.models import IAMUser

from tests.phase6_helpers import (
    identity_claims,
    seed_dev_platform_admin,
    seed_membership,
    seed_user,
)

FEROZE_EMAIL = "ferozebasha.s@hcltech.com"


def _seed_feroze(db) -> IAMUser:
    return seed_user(
        db,
        email=FEROZE_EMAIL,
        display_name="Feroze Basha",
        department="Engineering",
    )


def _search(client, query: str):
    return client.get("/api/platform/users/search", params={"q": query})


def _projection(query):
    # Direct function invocation is unit coverage of retained query code, not
    # positive HTTP authorization or a provisioned administrative capability.
    from app.routers.platform import search_platform_users

    from tests.tenant_fixture_scope import verified_fixture_tenant
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        return search_platform_users(q=query, tenant_id=None, page=1, page_size=20,
                                     context=None, db=db).model_dump(mode="json")


def _assert_denied(response):
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "IAM_PLATFORM_PERMISSION_DENIED"


def test_platform_search_finds_exact_email_case_insensitively(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        user = _seed_feroze(db)
        user.user_principal_name = "ferozebasha"
        user_id = user.id
        db.commit()

    response = _search(client, "FEROZEBASHA.S@HCLTECH.COM")

    _assert_denied(response)
    item = _projection("FEROZEBASHA.S@HCLTECH.COM")["items"][0]
    assert item["id"] == user_id
    assert item["email"] == FEROZE_EMAIL
    assert item["display_name"] == "Feroze Basha"
    assert item["username"] == "ferozebasha"
    assert item["status"] == "ACTIVE"
    assert item["email_verified"] is True
    assert item["verification_required"] is False
    assert item["external_issuer"] == "https://hcl-cs.test"
    assert item["external_subject"]
    assert item["is_platform_admin"] is False
    assert item["tenant_membership"] is None
    assert item["tenant_memberships"] == []


def test_platform_search_matches_partial_email_display_name_and_username(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        user = _seed_feroze(db)
        user.user_principal_name = "ferozebasha"
        user_id = user.id
        db.commit()

    for query in ("basha.s@hcl", "Feroze Basha", "ferozebasha"):
        response = _search(client, query)
        _assert_denied(response)
        assert [item["id"] for item in _projection(query)["items"]] == [user_id]


def test_active_verified_user_without_tenant_claim_or_membership_is_returned(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        user = _seed_feroze(db)
        user_id = user.id
        db.commit()

    response = _search(client, FEROZE_EMAIL)

    _assert_denied(response)
    item = _projection(FEROZE_EMAIL)["items"][0]
    assert item["id"] == user_id
    assert item["status"] == "ACTIVE"
    assert item["email_verified"] is True
    assert item["verification_required"] is False
    assert item["tenant_memberships"] == []


def test_existing_tenant_membership_does_not_hide_global_search_result(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        user = _seed_feroze(db)
        membership = seed_membership(db, user, role="VIEWER")
        user_id = user.id
        membership_status = membership.status
        db.commit()

    response = _search(client, "feroze")

    _assert_denied(response)
    item = _projection("feroze")["items"][0]
    assert item["id"] == user_id
    assert item["tenant_memberships"][0]["tenant_id"] == 1
    assert item["tenant_memberships"][0]["status"] == membership_status
    assert item["tenant_memberships"][0]["roles"] == ["VIEWER"]


def test_inactive_and_unverified_users_are_returned_with_ineligible_state(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        inactive = seed_user(
            db,
            status="DISABLED",
            email="search-inactive@example.test",
            display_name="Search Inactive",
        )
        unverified = seed_user(
            db,
            verified=False,
            email="search-unverified@example.test",
            display_name="Search Unverified",
        )
        inactive_id = inactive.id
        unverified_id = unverified.id
        db.commit()

    inactive_response = _search(client, "search-inactive")
    unverified_response = _search(client, "search-unverified")

    _assert_denied(inactive_response)
    assert _projection("search-inactive")["items"][0]["id"] == inactive_id
    assert _projection("search-inactive")["items"][0]["status"] == "DISABLED"
    _assert_denied(unverified_response)
    assert _projection("search-unverified")["items"][0]["id"] == unverified_id
    assert _projection("search-unverified")["items"][0]["email_verified"] is False
    assert _projection("search-unverified")["items"][0]["verification_required"] is True


def test_non_platform_administrator_is_denied_global_user_search(client, app):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
        tenant_admin = seed_user(db, display_name="Tenant Only Administrator")
        seed_membership(db, tenant_admin, role="TENANT_ADMIN")
        claims = identity_claims(tenant_admin)
        db.commit()

    app.dependency_overrides[get_current_user] = lambda: claims
    try:
        response = _search(client, "feroze")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "IAM_PLATFORM_PERMISSION_DENIED"
