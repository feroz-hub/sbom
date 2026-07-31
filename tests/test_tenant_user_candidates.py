"""Comprehensive tests for tenant-scoped user candidate search endpoint GET /api/tenants/{tenant_id}/user-candidates."""

from __future__ import annotations

from app.core.security import get_current_user
from app.db import SessionLocal
from app.models import Tenant
from tests.phase6_helpers import identity_claims, seed_membership, seed_user


def _seed_tenant(db, name: str, slug: str) -> Tenant:
    tenant = Tenant(name=name, slug=slug, status="ACTIVE")
    db.add(tenant)
    db.flush()
    return tenant


def _override_user(app, claims):
    app.dependency_overrides[get_current_user] = lambda: claims


def _clear_override(app):
    app.dependency_overrides.pop(get_current_user, None)


def test_tenant_admin_can_search_eligible_users_in_active_tenant(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis")
        tenant_admin = seed_user(db, email="admin@wellysis.test", display_name="Wellysis Admin")
        seed_membership(db, tenant_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        candidate = seed_user(db, email="eligible.candidate@hcltech.com", display_name="Eligible Candidate")
        candidate_id = candidate.id
        claims = identity_claims(tenant_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "eligible"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    data = res.json()["items"]
    assert len(data) == 1
    assert data[0]["id"] == candidate_id
    assert data[0]["email"] == "eligible.candidate@hcltech.com"


def test_user_in_another_tenant_is_returned(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-2")
        medtronics = _seed_tenant(db, name="Medtronics", slug="medtronics")

        wellysis_admin = seed_user(db, email="wadmin@wellysis.test", display_name="Wellysis Admin 2")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        feroze = seed_user(db, email="ferozebasha.s@hcltech.com", display_name="Feroze Basha")
        seed_membership(db, feroze, tenant_id=medtronics.id, role="DEVELOPER")
        feroze_id = feroze.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "feroze"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert any(item["id"] == feroze_id for item in items)


def test_user_already_in_selected_tenant_is_excluded(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-3")
        wellysis_admin = seed_user(db, email="wadmin3@wellysis.test", display_name="Wellysis Admin 3")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        existing_member = seed_user(db, email="existing.member@hcltech.com", display_name="Existing Member")
        seed_membership(db, existing_member, tenant_id=wellysis.id, role="VIEWER")
        existing_id = existing_member.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "existing.member"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert not any(item["id"] == existing_id for item in items)


def test_disabled_membership_in_selected_tenant_is_excluded(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-4")
        wellysis_admin = seed_user(db, email="wadmin4@wellysis.test", display_name="Wellysis Admin 4")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        disabled_member = seed_user(db, email="disabled.member@hcltech.com", display_name="Disabled Member")
        m = seed_membership(db, disabled_member, tenant_id=wellysis.id, role="VIEWER")
        m.status = "DISABLED"
        disabled_id = disabled_member.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "disabled.member"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert not any(item["id"] == disabled_id for item in items)


def test_active_verified_user_is_returned(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-5")
        wellysis_admin = seed_user(db, email="wadmin5@wellysis.test", display_name="Wellysis Admin 5")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        active_verified = seed_user(
            db,
            email="active.verified@hcltech.com",
            display_name="Active Verified",
            verified=True,
            status="ACTIVE",
        )
        active_id = active_verified.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "active.verified"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert any(item["id"] == active_id for item in items)


def test_unverified_user_is_excluded(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-6")
        wellysis_admin = seed_user(db, email="wadmin6@wellysis.test", display_name="Wellysis Admin 6")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        unverified = seed_user(
            db,
            email="unverified.user@hcltech.com",
            display_name="Unverified User",
            verified=False,
        )
        unverified_id = unverified.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "unverified"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert not any(item["id"] == unverified_id for item in items)


def test_verification_required_user_is_excluded(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-7")
        wellysis_admin = seed_user(db, email="wadmin7@wellysis.test", display_name="Wellysis Admin 7")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        req_verif = seed_user(
            db,
            email="verif.req@hcltech.com",
            display_name="Verif Required User",
            verified=True,
        )
        req_verif.verification_required = True
        req_id = req_verif.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "verif.req"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert not any(item["id"] == req_id for item in items)


def test_disabled_user_is_excluded(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-8")
        wellysis_admin = seed_user(db, email="wadmin8@wellysis.test", display_name="Wellysis Admin 8")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        disabled_user = seed_user(
            db,
            email="disabled.account@hcltech.com",
            display_name="Disabled Account User",
            status="DISABLED",
        )
        disabled_id = disabled_user.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "disabled.account"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert not any(item["id"] == disabled_id for item in items)


def test_search_matches_email(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-9")
        wellysis_admin = seed_user(db, email="wadmin9@wellysis.test", display_name="Wellysis Admin 9")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        target = seed_user(db, email="unique.email.match@hcltech.com", display_name="Random Name")
        target_id = target.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "unique.email.match"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200
    assert any(item["id"] == target_id for item in res.json()["items"])


def test_search_matches_display_name(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-10")
        wellysis_admin = seed_user(db, email="wadmin10@wellysis.test", display_name="Wellysis Admin 10")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        target = seed_user(db, email="random.email@hcltech.com", display_name="Unique Display Name")
        target_id = target.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "Unique Display Name"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200
    assert any(item["id"] == target_id for item in res.json()["items"])


def test_search_matches_username_user_principal_name(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-11")
        wellysis_admin = seed_user(db, email="wadmin11@wellysis.test", display_name="Wellysis Admin 11")
        seed_membership(db, wellysis_admin, tenant_id=wellysis.id, role="TENANT_ADMIN")

        target = seed_user(db, email="principal.user@hcltech.com", display_name="Principal Person")
        target.user_principal_name = "unique_principal_username"
        target_id = target.id

        claims = identity_claims(wellysis_admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "unique_principal_username"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200
    assert any(item["id"] == target_id for item in res.json()["items"])


def test_unauthorized_user_receives_403(app, client):
    with SessionLocal() as db:
        wellysis = _seed_tenant(db, name="Wellysis", slug="wellysis-12")
        viewer = seed_user(db, email="viewer@wellysis.test", display_name="Wellysis Viewer")
        seed_membership(db, viewer, tenant_id=wellysis.id, role="VIEWER")

        claims = identity_claims(viewer)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{wellysis.id}/user-candidates",
            params={"q": "search"},
            headers={"X-Tenant-ID": str(wellysis.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 403


def test_cross_tenant_unauthorized_request_receives_403(app, client):
    with SessionLocal() as db:
        tenant_a = _seed_tenant(db, name="Tenant A", slug="tenant-a")
        tenant_b = _seed_tenant(db, name="Tenant B", slug="tenant-b")

        admin_a = seed_user(db, email="admin@tenant-a.test", display_name="Admin A")
        seed_membership(db, admin_a, tenant_id=tenant_a.id, role="TENANT_ADMIN")

        claims = identity_claims(admin_a)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{tenant_b.id}/user-candidates",
            params={"q": "search"},
            headers={"X-Tenant-ID": str(tenant_a.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 403


def test_unknown_tenant_receives_404(app, client):
    with SessionLocal() as db:
        tenant = _seed_tenant(db, name="Real Tenant", slug="real-tenant")
        admin = seed_user(db, email="admin@real.test", display_name="Real Admin")
        seed_membership(db, admin, tenant_id=tenant.id, role="TENANT_ADMIN")

        claims = identity_claims(admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            "/api/tenants/999999/user-candidates",
            params={"q": "search"},
            headers={"X-Tenant-ID": str(tenant.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 404


def test_query_length_validation_works(app, client):
    with SessionLocal() as db:
        tenant = _seed_tenant(db, name="Tenant Q", slug="tenant-q")
        admin = seed_user(db, email="admin@q.test", display_name="Admin Q")
        seed_membership(db, admin, tenant_id=tenant.id, role="TENANT_ADMIN")

        claims = identity_claims(admin)
        db.commit()

    _override_user(app, claims)
    try:
        res_empty = client.get(
            f"/api/tenants/{tenant.id}/user-candidates",
            params={"q": ""},
            headers={"X-Tenant-ID": str(tenant.id)},
        )
        res_long = client.get(
            f"/api/tenants/{tenant.id}/user-candidates",
            params={"q": "a" * 201},
            headers={"X-Tenant-ID": str(tenant.id)},
        )
    finally:
        _clear_override(app)

    assert res_empty.status_code == 422
    assert res_long.status_code == 422


def test_wildcard_characters_are_escaped_safely(app, client):
    with SessionLocal() as db:
        tenant = _seed_tenant(db, name="Tenant Wildcard", slug="tenant-wildcard")
        admin = seed_user(db, email="admin@wild.test", display_name="Admin Wildcard")
        seed_membership(db, admin, tenant_id=tenant.id, role="TENANT_ADMIN")

        seed_user(db, email="normaluser@hcltech.com", display_name="Normal User")
        special_user = seed_user(db, email="special_user%test@hcltech.com", display_name="Special % User")
        special_id = special_user.id

        claims = identity_claims(admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{tenant.id}/user-candidates",
            params={"q": "special_user%test"},
            headers={"X-Tenant-ID": str(tenant.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == special_id


def test_results_are_limited_and_deterministically_ordered(app, client):
    with SessionLocal() as db:
        tenant = _seed_tenant(db, name="Tenant Limit", slug="tenant-limit")
        admin = seed_user(db, email="admin@limit.test", display_name="Admin Limit")
        seed_membership(db, admin, tenant_id=tenant.id, role="TENANT_ADMIN")

        for i in range(30):
            seed_user(
                db,
                email=f"candidate{i:02d}@limit.test",
                display_name=f"Candidate {i:02d}",
            )

        claims = identity_claims(admin)
        db.commit()

    _override_user(app, claims)
    try:
        res = client.get(
            f"/api/tenants/{tenant.id}/user-candidates",
            params={"q": "candidate"},
            headers={"X-Tenant-ID": str(tenant.id)},
        )
    finally:
        _clear_override(app)

    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 20
    display_names = [item["display_name"] for item in items]
    assert display_names == sorted(display_names)
