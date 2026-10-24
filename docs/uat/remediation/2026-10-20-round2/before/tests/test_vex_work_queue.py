"""Work-queue predicates execute before SQL pagination and keep tenant scope."""

from datetime import UTC, datetime

import pytest
from app.core.security import get_current_tenant_context
from app.models import AnalysisFinding, Product, Projects, Tenant
from app.services.vex.authorization import membership_key
from app.settings import get_settings
from sqlalchemy import select

from tests import test_vex_scoped_authorization as fixtures
from tests.test_vex_investigations_api import BASE, context_for, fetch
from tests.test_vex_scoped_authorization import as_actor, make_member

db = fixtures.db
people = fixtures.people
seeded = fixtures.seeded


@pytest.fixture
def queue(client, db, seeded, people):
    pending = context_for(db, "CVE-2026-5001")
    complete = context_for(db, "CVE-2026-5002")
    pending.assigned_to = membership_key(people["DEVELOPER"])
    complete.assigned_to = membership_key(people["SECURITY_ANALYST"])
    # Same labels must never conflate user identity in the self filter.
    people["DEVELOPER"].user.display_name = people["SECURITY_ANALYST"].user.display_name
    db.commit()
    as_actor(client, people["TENANT_ADMIN"])
    yield pending, complete
    client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_work_modes_combination_counts_and_pagination(client, db, people, queue):
    pending, complete = queue
    assert fetch(client, my_work="all")["total"] == 2
    assert fetch(client, my_work="assigned", limit=1)["total"] == 2
    assert len(fetch(client, my_work="assigned", limit=1)["items"]) == 1
    assert fetch(client, my_work="unassigned")["total"] == 0
    as_actor(client, people["DEVELOPER"])
    result = fetch(client, my_work="me")
    assert [row["id"] for row in result["items"]] == [pending.id]
    assert result["items"][0]["assigned_to_is_self"] is True
    assert fetch(client, my_work="me", severity="HIGH")["total"] == 1
    assert fetch(client, my_work="me", severity="CRITICAL")["total"] == 0
    assert fetch(client, my_work="me", effective_status="UNDER_INVESTIGATION")["total"] == 1
    assert fetch(client, assignee="me")["total"] == 1
    for member in [people["SECURITY_ANALYST"], people["DEVELOPER"]]:
        assert fetch(client, assignee=membership_key(member))["total"] == 1
    pending.assigned_to = None
    pending.reconciliation_status = "CONFLICT_REVIEW_REQUIRED"
    db.commit()
    assert fetch(client, my_work="unassigned", needs_review=True)["total"] == 1
    assert fetch(client, assignee="unassigned")["total"] == 1
    assert fetch(client, my_work="assigned")["total"] == 1
    as_actor(client, people["TENANT_ADMIN"])
    response = client.put(f"{BASE}/{pending.id}/assignment", json={
        "assigned_to": membership_key(people["DEVELOPER"]), "row_version": pending.row_version,
        "reason": "Allocate backlog",
    })
    assert response.status_code == 200
    assert fetch(client, my_work="unassigned", needs_review=True)["total"] == 0


def test_attention_is_role_aware_and_uses_supported_workflow_states(client, db, people, queue):
    pending, complete = queue
    for role in ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER"]:
        as_actor(client, people[role])
        assert [row["id"] for row in fetch(client, my_work="attention")["items"]] == [pending.id]
    as_actor(client, people["VIEWER"])
    assert client.get(BASE, params={"my_work": "attention"}).status_code == 403
    assert fetch(client)["total"] == 2  # Read access is unchanged.
    complete.effective_status = "AFFECTED"
    pending.effective_status = "FIXED"
    db.commit()
    as_actor(client, people["SECURITY_ANALYST"])
    assert [row["id"] for row in fetch(client, my_work="attention")["items"]] == [complete.id]
    as_actor(client, people["DEVELOPER"])
    assert fetch(client, my_work="attention")["total"] == 0
    pending.reconciliation_status = "UNRESOLVED_MAPPING"
    db.commit()
    assert fetch(client, my_work="attention")["total"] == 1
    pending.assigned_to = None
    db.commit()
    assert fetch(client, my_work="attention")["total"] == 0


@pytest.mark.parametrize("mode", ["DATABASE", "LEGACY", "COMPARE"])
def test_assignee_discovery_search_pagination_and_cross_tenant_guard(client, db, people, queue, monkeypatch, mode):
    monkeypatch.setattr(get_settings(), "tenant_role_assignment_mode", mode)
    now = datetime.now(UTC)
    tenant = Tenant(name="Other queue", slug="other-queue", status="ACTIVE", created_at=now, updated_at=now)
    db.add(tenant)
    db.commit()
    outside = make_member(db, "DEVELOPER", tenant_id=tenant.id)
    disabled = make_member(db, "DEVELOPER", status="DISABLED")
    locked = make_member(db, "DEVELOPER")
    locked.user.status = "LOCKED"
    unverified = make_member(db, "DEVELOPER")
    unverified.user.verification_required = True
    make_member(db, "TENANT_ADMIN", roles=["TENANT_ADMIN", "DEVELOPER"])
    people["DEVELOPER"].user.display_name = "AstraMed Developer"
    people["DEVELOPER"].user.email = "developer@astramed.example"
    db.commit()
    allowed = {membership_key(people["DEVELOPER"]), membership_key(people["SECURITY_ANALYST"])}
    for role in ["TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]:
        as_actor(client, people[role])
        result = client.get(f"{BASE}/assignees", params={"limit": 1}).json()
        assert result["total"] == 2
        assert len(result["items"]) == 1
        second = client.get(f"{BASE}/assignees", params={"limit": 1, "offset": 1}).json()
        assert {result["items"][0]["id"], second["items"][0]["id"]} == allowed
        assert client.get(BASE, params={"assignee": membership_key(outside)}).status_code == 404
        assert client.get(BASE, params={"assignee": "membership:invalid"}).status_code == 404
    for term in ["astramed", "DEVELOPER@"]:
        result = client.get(f"{BASE}/assignees", params={"q": term}).json()
        assert [row["id"] for row in result["items"]] == [membership_key(people["DEVELOPER"])]
    assert client.get(f"{BASE}/assignees", params={"limit": 101}).status_code == 422
    assert client.get(BASE, params={"my_work": "invalid"}).status_code == 422
    assert all(member.id not in {people["DEVELOPER"].id, people["SECURITY_ANALYST"].id} for member in [outside, disabled, locked, unverified])


def test_inactive_and_legacy_ownership_remains_readable_without_being_active_assignment(client, db, people, queue):
    pending, complete = queue
    people["DEVELOPER"].status = "DISABLED"
    complete.assigned_to = "legacy free text"
    db.commit()
    assert fetch(client, my_work="assigned")["total"] == 0
    assert fetch(client)["total"] == 2
    assert fetch(client, assignee=membership_key(people["DEVELOPER"]))["total"] == 1
    assert fetch(client, my_work="unassigned")["total"] == 0
    row = fetch(client, assignee=membership_key(people["DEVELOPER"]))["items"][0]
    assert row["assigned_to_active"] is False
    complete.assigned_to = ""  # Legacy blank values also render as Unassigned.
    db.commit()
    assert fetch(client, my_work="unassigned")["total"] == 1


def test_component_version_unresolved_and_unknown_severity_filters(client, db, seeded, people, queue):
    pending, complete = queue
    assert fetch(client, component="openssl 1.1.1")["total"] == 1
    assert fetch(client, component="1.2.11")["total"] == 1
    pending.component_id = None
    db.commit()
    assert fetch(client, unresolved_component=True, severity="UNKNOWN")["total"] == 1
    assert fetch(client, unresolved_component=True, component="openssl")["total"] == 0
    finding = db.scalar(select(AnalysisFinding).where(AnalysisFinding.component_id == complete.component_id))
    finding.severity = None
    db.commit()
    assert fetch(client, severity="UNKNOWN")["total"] == 2
    db.add(AnalysisFinding(
        analysis_run_id=seeded["run"].id, component_id=complete.component_id,
        tenant_id=1, source="NVD", vuln_id=complete.canonical_vulnerability_id,
        severity="CRITICAL",
    ))
    complete.reconciliation_status = "UNRESOLVED_MAPPING"
    db.commit()
    result = fetch(client, severity="CRITICAL", reconciliation_status="UNRESOLVED_MAPPING")
    assert result["total"] == 1
    assert result["items"][0]["severity"] == "CRITICAL"
    assert fetch(client, severity="LOW")["total"] == 0
    # Review is conflict/revalidation, not a duplicate of unresolved mapping.
    assert fetch(client, needs_review=True, reconciliation_status="UNRESOLVED_MAPPING")["total"] == 0


def test_scope_and_owner_filters_intersect_before_pagination(client, db, seeded, people, queue):
    project = Projects(project_name="Queue project", tenant_id=1)
    db.add(project)
    db.flush()
    application = Product(project_id=project.id, tenant_id=1, name="Queue app", normalized_name="queue app",
                          slug="queue-app", created_at="2026-09-30T00:00:00Z")
    db.add(application)
    db.flush()
    seeded["sbom"].projectid = project.id
    seeded["sbom"].product_id = application.id
    db.commit()
    params = {"project_id": project.id, "product_id": application.id, "sbom_id": seeded["sbom"].id,
              "assignee": membership_key(people["DEVELOPER"]), "q": "CVE-2026-5001", "component": "openssl 1.1.1"}
    result = fetch(client, **params, limit=1)
    assert result["total"] == 1
    assert result["items"][0]["project_name"] == "Queue project"
    assert result["items"][0]["product_name"] == "Queue app"
    assert fetch(client, **{**params, "project_id": project.id + 1})["total"] == 0
