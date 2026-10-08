"""HTTP authorization matrices against real active database memberships."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.models import IAMUser, Tenant, TenantUser, TenantUserRoleAssignment
from app.services.tenant_role_assignment_service import create_initial_assignments
from app.services.vex.authorization import membership_key
from sqlalchemy import select

from tests import test_vex_investigations_api as investigation_fixtures
from tests.test_vex_investigations_api import BASE, context_for

db = investigation_fixtures.db
seeded = investigation_fixtures.seeded


def make_member(db, role, *, tenant_id=1, status="ACTIVE", roles=None):
    now = datetime.now(UTC)
    user = IAMUser(
        display_name=f"{role} person",
        status="ACTIVE",
        verification_required=False,
        email_verified=True,
        email_verified_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    member = TenantUser(tenant_id=tenant_id, user_id=user.id, role=role, status=status, created_at=now, updated_at=now)
    db.add(member)
    db.flush()
    create_initial_assignments(
        db, member, role_codes=roles or [role], primary_role_code=role, actor_user_id=None, source="PLATFORM_ADMIN"
    )
    db.commit()
    return member


def actor(member):
    return CurrentContext(
        user_id=member.user_id,
        external_user_id=str(member.user_id),
        email=None,
        display_name=member.user.display_name,
        tenant_id=member.tenant_id,
        external_tenant_id=str(member.tenant_id),
        roles=frozenset({member.role}),
        permissions=ROLE_PERMISSIONS[member.role],
    )


@pytest.fixture
def people(client, db):
    return {role: make_member(db, role) for role in ("TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER")}


def as_actor(client, member):
    client.app.dependency_overrides[get_current_tenant_context] = lambda: actor(member)


def test_assignment_matrix_http(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    try:
        for actor_role, member in people.items():
            as_actor(client, member)
            for target_role, target in people.items():
                version = client.get(f"{BASE}/{investigation.id}").json()["row_version"]
                result = client.put(
                    f"{BASE}/{investigation.id}/assignment",
                    json={"assigned_to": membership_key(target), "row_version": version, "reason": "delegation"},
                )
                allowed = (actor_role == "TENANT_ADMIN" and target_role in {"SECURITY_ANALYST", "DEVELOPER"}) or (
                    actor_role == "SECURITY_ANALYST" and target_role == "DEVELOPER"
                )
                assert result.status_code == (200 if allowed else 403), (actor_role, target_role, result.text)
                if allowed:
                    assert result.json()["effective_status"] == "UNDER_INVESTIGATION"
            if actor_role in {"DEVELOPER", "VIEWER"}:
                assert (
                    client.put(
                        f"{BASE}/{investigation.id}/assignment",
                        json={"assigned_to": None, "row_version": version, "reason": "remove"},
                    ).status_code
                    == 403
                )
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_decision_matrix_and_revocation_http(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    second = make_member(db, "DEVELOPER")
    try:
        for actor_role, member in people.items():
            as_actor(client, member)
            for target in [None, people["DEVELOPER"], second, people["SECURITY_ANALYST"]]:
                db.refresh(investigation)
                investigation.assigned_to = membership_key(target) if target else None
                db.commit()
                detail = client.get(f"{BASE}/{investigation.id}").json()
                allowed = actor_role in {"TENANT_ADMIN", "SECURITY_ANALYST"} or (
                    actor_role == "DEVELOPER" and target is member
                )
                assert detail["capabilities"]["can_update"] is allowed
                result = client.put(
                    f"{BASE}/{investigation.id}/decision",
                    json={"status": "AFFECTED", "reason": "review", "row_version": detail["row_version"]},
                )
                assert result.status_code == (200 if allowed else 403), (actor_role, target, result.text)
        # Same authenticated session immediately loses permission after unassignment.
        member = people["DEVELOPER"]
        as_actor(client, member)
        db.refresh(investigation)
        investigation.assigned_to = membership_key(member)
        db.commit()
        detail = client.get(f"{BASE}/{investigation.id}").json()
        assert detail["capabilities"]["can_update"]
        for state in ["unassign", "membership", "account", "role"]:
            investigation.assigned_to = membership_key(member)
            member.status = "ACTIVE"
            member.user.status = "ACTIVE"
            if state == "unassign":
                investigation.assigned_to = None
            if state == "membership":
                member.status = "DISABLED"
            if state == "account":
                member.user.status = "LOCKED"
            if state == "role":
                for assignment in db.scalars(
                    select(TenantUserRoleAssignment).where(TenantUserRoleAssignment.tenant_user_id == member.id)
                ):
                    assignment.status = "REVOKED"
                    assignment.is_primary = False
                    assignment.revoked_at = datetime.now(UTC)
            db.commit()
            assert (
                client.put(
                    f"{BASE}/{investigation.id}/decision",
                    json={"status": "AFFECTED", "reason": "stale session", "row_version": detail["row_version"]},
                ).status_code
                == 403
            )
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_candidates_invalid_targets_and_payload_bypass(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    now = datetime.now(UTC)
    tenant = Tenant(name="Other", slug="vex-other", status="ACTIVE", created_at=now, updated_at=now)
    db.add(tenant)
    db.commit()
    outside = make_member(db, "DEVELOPER", tenant_id=tenant.id)
    inactive = make_member(db, "DEVELOPER")
    inactive.status = "DISABLED"
    locked = make_member(db, "DEVELOPER")
    locked.user.status = "LOCKED"
    multi = make_member(db, "SECURITY_ANALYST", roles=["SECURITY_ANALYST", "DEVELOPER"])
    people["DEVELOPER"].user.email = "developer@assignment.example"
    db.commit()
    try:
        for role in ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]:
            as_actor(client, people[role])
            detail = client.get(f"{BASE}/{investigation.id}").json()
            candidates = {c["id"] for c in detail["capabilities"]["candidates"]}
            expected = {membership_key(people["DEVELOPER"])} if role in {"TENANT_ADMIN", "SECURITY_ANALYST"} else set()
            if role == "TENANT_ADMIN":
                expected |= {membership_key(people["SECURITY_ANALYST"]), membership_key(multi)}
            assert candidates == expected
            for candidate in detail["capabilities"]["candidates"]:
                if candidate["id"] == membership_key(people["DEVELOPER"]):
                    assert candidate["email"] == "developer@assignment.example"
            for target in [outside, inactive, locked]:
                result = client.put(
                    f"{BASE}/{investigation.id}/assignment",
                    json={"assigned_to": membership_key(target), "row_version": 1, "reason": "bad"},
                )
                assert result.status_code == 403
            assert (
                client.put(
                    f"{BASE}/{investigation.id}/decision",
                    json={
                        "status": "AFFECTED",
                        "reason": "bypass",
                        "row_version": 1,
                        "assigned_to": membership_key(people["DEVELOPER"]),
                    },
                ).status_code
                == 422
            )
        as_actor(client, people["SECURITY_ANALYST"])
        assert (
            client.put(
                f"{BASE}/{investigation.id}/assignment",
                json={"assigned_to": membership_key(multi), "row_version": 1, "reason": "bad"},
            ).status_code
            == 403
        )
        for member in people.values():
            client.app.dependency_overrides[get_current_tenant_context] = lambda m=member: replace(
                actor(m), tenant_id=tenant.id
            )
            for operation in ["assignment", "decision"]:
                payload = (
                    {"row_version": 1, "reason": "cross tenant", "assigned_to": None}
                    if operation == "assignment"
                    else {"row_version": 1, "reason": "cross tenant", "status": "AFFECTED"}
                )
                assert client.put(f"{BASE}/{investigation.id}/{operation}", json=payload).status_code in {403, 404}
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_assignment_history_unassignment_and_separate_decision(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    try:
        as_actor(client, people["TENANT_ADMIN"])
        version = 1
        for target in [people["SECURITY_ANALYST"], people["DEVELOPER"], None]:
            result = client.put(
                f"{BASE}/{investigation.id}/assignment",
                json={
                    "assigned_to": membership_key(target) if target else None,
                    "row_version": version,
                    "reason": "delegation",
                },
            )
            assert result.status_code == 200, result.text
            data = result.json()
            version = data["row_version"]
            assert data["effective_status"] == "UNDER_INVESTIGATION"
            assert data["reconciliation_status"] == "ANALYZER_ONLY"
        assert len([h for h in data["history"] if h["kind"] == "assignment"]) == 3
        assert all("membership:" not in h["summary"] for h in data["history"])
        assert "vex:write" not in ROLE_PERMISSIONS["DEVELOPER"]
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_no_broad_developer_bypass_or_legacy_owner_authority(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    developer = people["DEVELOPER"]
    try:
        as_actor(client, developer)
        investigation.assigned_to = membership_key(developer)
        db.commit()
        # The assigned exception is limited to decisions, not import/override/mapping.
        for path, payload in [
            (
                f"/api/components/{seeded['openssl'].id}/vulnerabilities/CVE-2026-5001/vex-override",
                {"status": "affected", "reason": "bypass"},
            ),
            (
                f"{BASE}/{investigation.id}/component",
                {"component_id": seeded["openssl"].id, "row_version": 1, "reason": "bypass"},
            ),
        ]:
            assert client.request("PATCH" if "vex-override" in path else "PUT", path, json=payload).status_code == 403
        for old_owner in [str(developer.user_id), developer.user.display_name, "dev@example.com"]:
            investigation.assigned_to = old_owner
            db.commit()
            assert (
                client.put(
                    f"{BASE}/{investigation.id}/decision",
                    json={"status": "AFFECTED", "row_version": 1, "reason": "legacy"},
                ).status_code
                == 403
            )
        # Frontend/token role claims and broad permission claims never replace live roles.
        viewer = people["VIEWER"]
        client.app.dependency_overrides[get_current_tenant_context] = lambda: replace(
            actor(viewer), roles=frozenset({"TENANT_ADMIN"}), permissions=ROLE_PERMISSIONS["TENANT_ADMIN"]
        )
        investigation.assigned_to = membership_key(viewer)
        db.commit()
        assert (
            client.put(
                f"{BASE}/{investigation.id}/decision", json={"status": "AFFECTED", "row_version": 1, "reason": "forged"}
            ).status_code
            == 403
        )
        assert (
            client.put(
                f"{BASE}/{investigation.id}/assignment",
                json={"assigned_to": membership_key(developer), "row_version": 1, "reason": "forged"},
            ).status_code
            == 403
        )
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_platform_override_stays_tenant_bound(client, db, seeded, people):
    from app.models import PlatformUserRole

    now = datetime.now(UTC)
    user = IAMUser(
        display_name="Platform administrator",
        status="ACTIVE",
        verification_required=False,
        email_verified=True,
        email_verified_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    db.add(PlatformUserRole(user_id=user.id, role="PLATFORM_ADMIN", status="ACTIVE", created_at=now, updated_at=now))
    db.commit()
    investigation = context_for(db, "CVE-2026-5001")
    ctx = replace(
        actor(people["TENANT_ADMIN"]),
        user_id=user.id,
        is_platform_admin=True,
        permissions=ROLE_PERMISSIONS["PLATFORM_ADMIN"] | ROLE_PERMISSIONS["TENANT_ADMIN"],
    )
    try:
        client.app.dependency_overrides[get_current_tenant_context] = lambda: ctx
        detail = client.get(f"{BASE}/{investigation.id}").json()
        assert detail["capabilities"]["can_assign"]
        assert all(c["label"] != user.display_name for c in detail["capabilities"]["candidates"])
        response = client.put(
            f"{BASE}/{investigation.id}/assignment",
            json={"assigned_to": membership_key(people["DEVELOPER"]), "row_version": 1, "reason": "platform review"},
        )
        assert response.status_code == 200, response.text
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_analyst_unassignment_and_removed_membership(client, db, seeded, people):
    investigation = context_for(db, "CVE-2026-5001")
    analyst = people["SECURITY_ANALYST"]
    developer = people["DEVELOPER"]
    try:
        as_actor(client, analyst)
        investigation.assigned_to = membership_key(analyst)
        db.commit()
        assert (
            client.put(
                f"{BASE}/{investigation.id}/assignment",
                json={"assigned_to": None, "row_version": 1, "reason": "remove"},
            ).status_code
            == 403
        )
        investigation.assigned_to = membership_key(developer)
        db.commit()
        response = client.put(
            f"{BASE}/{investigation.id}/assignment", json={"assigned_to": None, "row_version": 1, "reason": "remove"}
        )
        assert response.status_code == 200
        db.refresh(investigation)
        investigation.assigned_to = membership_key(developer)
        db.commit()
        developer_context = actor(developer)
        client.app.dependency_overrides[get_current_tenant_context] = lambda: developer_context
        db.delete(developer)
        db.commit()
        detail = client.get(f"{BASE}/{investigation.id}").json()
        assert not detail["capabilities"]["can_update"]
        assert detail["capabilities"]["owner"]["label"] == "Assigned user is no longer active"
        assert (
            client.put(
                f"{BASE}/{investigation.id}/decision",
                json={"status": "AFFECTED", "row_version": detail["row_version"], "reason": "stale"},
            ).status_code
            == 403
        )
        as_actor(client, analyst)
        assert (
            client.put(
                f"{BASE}/{investigation.id}/assignment",
                json={"assigned_to": None, "row_version": detail["row_version"], "reason": "clear inactive"},
            ).status_code
            == 200
        )
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_history_keeps_alias_decisions_without_other_vulnerabilities(client, db, seeded):
    import json

    from app.models import VexOverrideAudit

    investigation = context_for(db, "CVE-2026-5001")
    investigation.aliases_json = json.dumps(["GHSA-AAAA-BBBB-CCCC"])
    for vulnerability, reason in [("GHSA-AAAA-BBBB-CCCC", "alias decision"), ("CVE-2026-9999", "unrelated decision")]:
        db.add(
            VexOverrideAudit(
                tenant_id=1,
                sbom_id=investigation.sbom_id,
                component_id=investigation.component_id,
                vulnerability_id=vulnerability,
                action="DECISION",
                reason=reason,
                changed_at="2026-09-29T00:00:00Z",
            )
        )
    db.commit()
    detail = client.get(f"{BASE}/{investigation.id}").json()
    assert [entry["reason"] for entry in detail["history"]] == ["alias decision"]
