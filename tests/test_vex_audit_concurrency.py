"""PR-6 tests — audit completeness, concurrency, RBAC and tenant isolation.

Spec sections 40-43 (VEX-AUD-001/002, VEX-SEC-001/002) plus the manual
resolution of an unresolved mapping (VEX-MAP-001).
"""

import pytest
from sqlalchemy import select, text

from app.core.permissions import ROLE_PERMISSIONS, Role
from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    SBOMComponent,
    SBOMSource,
    VexDocument,
    VexInvestigation,
    VexOverrideAudit,
    VexStatement,
)
from app.services.vex.reconciliation import recompute_for_sbom

NOW = "2026-09-24T00:00:00Z"
BASE = "/api/vex/investigations"


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def seeded(db):
    """One detected context plus one unresolved-mapping context."""
    sbom = SBOMSource(sbom_name="audit-test", sbom_data="{}", tenant_id=1, is_active=True)
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id, name="openssl", version="1.1.1", tenant_id=1
    )
    other = SBOMComponent(sbom_id=sbom.id, name="openssl", version="3.0.8", tenant_id=1)
    db.add_all([component, other])
    db.flush()

    run = AnalysisRun(
        sbom_id=sbom.id, tenant_id=1, run_status="OK", started_on=NOW, completed_on=NOW
    )
    db.add(run)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=run.id, component_id=component.id, vuln_id="CVE-2026-5001",
            tenant_id=1, source="NVD", severity="HIGH",
        )
    )

    # An assertion the matcher could not bind: two components share the name.
    document = VexDocument(
        sbom_id=sbom.id, tenant_id=1, source_type="uploaded", format="openvex",
        author="Supplier A", source_document_id="doc-unresolved", uploaded_at=NOW,
    )
    db.add(document)
    db.flush()
    db.add(
        VexStatement(
            vex_document_id=document.id, sbom_id=sbom.id, component_id=None,
            vulnerability_id="CVE-2026-9001", tenant_id=1, status="not_affected",
            normalized_status="NOT_AFFECTED", source_name="Supplier A", created_at=NOW,
        )
    )
    db.commit()
    recompute_for_sbom(db, tenant_id=1, sbom_id=sbom.id)
    db.commit()

    yield {"sbom": sbom, "component": component, "other": other}

    for model in (
        VexOverrideAudit, VexInvestigation, VexStatement, VexDocument,
        AnalysisFinding, AnalysisRun,
    ):
        db.query(model).delete()
    db.query(SBOMComponent).delete()
    db.query(SBOMSource).delete()
    db.commit()


def context_for(db, vuln_id):
    return db.scalar(
        select(VexInvestigation).where(
            VexInvestigation.canonical_vulnerability_id == vuln_id
        )
    )


def audits_for(db, investigation_id):
    return db.scalars(
        select(VexOverrideAudit)
        .where(VexOverrideAudit.investigation_id == investigation_id)
        .order_by(VexOverrideAudit.id)
    ).all()


# ---------------------------------------------------------------------------
# Audit completeness — VEX-AUD-001
# ---------------------------------------------------------------------------


def test_decision_writes_every_required_audit_field__VEX_AUD_001(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    before = context.effective_status
    response = client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "NOT_AFFECTED", "row_version": context.row_version,
            "reason": "code path unreachable", "justification": "vulnerable_code_not_present",
            "evidence_url": "https://example.test/evidence",
        },
    )
    assert response.status_code == 200, response.text

    entries = [a for a in audits_for(db, context.id) if a.action == "DECISION"]
    assert len(entries) == 1
    entry = entries[0]
    # Spec section 40's ten required fields.
    assert entry.tenant_id == 1
    assert entry.sbom_id == seeded["sbom"].id
    assert entry.component_id == seeded["component"].id
    assert entry.vulnerability_id == "CVE-2026-5001"
    assert entry.previous_status == before
    assert entry.new_status == "NOT_AFFECTED"
    assert entry.reason == "code path unreachable"
    assert entry.evidence_url == "https://example.test/evidence"
    assert entry.changed_at


def test_audit_records_the_reconciliation_transition__VEX_AUD_001(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    before = context.reconciliation_status
    client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "AFFECTED", "row_version": context.row_version,
            "reason": "confirmed exploitable",
        },
    )
    entry = [a for a in audits_for(db, context.id) if a.action == "DECISION"][0]
    assert entry.old_value_json["reconciliation_status"] == before
    assert "reconciliation_status" in entry.new_value_json


def test_audit_is_append_only__VEX_AUD_001(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    for status, reason in (("AFFECTED", "first"), ("UNDER_INVESTIGATION", "second")):
        db.refresh(context)
        response = client.put(
            f"{BASE}/{context.id}/decision",
            json={"status": status, "row_version": context.row_version, "reason": reason},
        )
        assert response.status_code == 200, response.text
    decisions = [a for a in audits_for(db, context.id) if a.action == "DECISION"]
    assert len(decisions) == 2, "each decision appends; none is overwritten"
    assert [a.reason for a in decisions] == ["first", "second"]


# ---------------------------------------------------------------------------
# Concurrency — VEX-AUD-002
# ---------------------------------------------------------------------------


def test_every_mutation_requires_row_version__VEX_AUD_002(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    for path, body in (
        ("decision", {"status": "AFFECTED", "reason": "x"}),
        ("assignment", {"assigned_to": "analyst", "reason": "x"}),
        ("component", {"component_id": seeded["component"].id, "reason": "x"}),
    ):
        response = client.put(f"{BASE}/{context.id}/{path}", json=body)
        assert response.status_code == 422, f"{path} must require row_version"


def test_assignment_conflicts_on_a_stale_version__VEX_AUD_002(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    first = client.put(
        f"{BASE}/{context.id}/assignment",
        json={"assigned_to": "alice", "row_version": context.row_version, "reason": "triage"},
    )
    assert first.status_code == 200, first.text
    stale = client.put(
        f"{BASE}/{context.id}/assignment",
        json={"assigned_to": "bob", "row_version": 1, "reason": "triage"},
    )
    assert stale.status_code == 409


def test_reconciliation_does_not_bump_version_when_nothing_changed__VEX_AUD_002(seeded, db):
    """An unchanged recompute must not invalidate an analyst's in-flight token."""
    context = context_for(db, "CVE-2026-5001")
    before = context.row_version
    recompute_for_sbom(db, tenant_id=1, sbom_id=seeded["sbom"].id)
    db.commit()
    db.refresh(context)
    assert context.row_version == before


def test_reconciliation_preserves_a_manual_decision__VEX_INV_004(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    assert client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "NOT_AFFECTED", "row_version": context.row_version,
            "reason": "reviewed", "justification": "not reachable",
        },
    ).status_code == 200

    recompute_for_sbom(db, tenant_id=1, sbom_id=seeded["sbom"].id)
    db.commit()
    db.refresh(context)
    assert context.effective_status == "NOT_AFFECTED"


# ---------------------------------------------------------------------------
# Assignment — spec section 27
# ---------------------------------------------------------------------------


def test_assignment_is_recorded_and_audited(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/assignment",
        json={"assigned_to": "alice", "row_version": context.row_version, "reason": "triage"},
    )
    assert response.status_code == 200, response.text
    db.refresh(context)
    assert context.assigned_to == "alice"

    entry = [a for a in audits_for(db, context.id) if a.action == "ASSIGNMENT"][0]
    assert entry.old_value_json == {"assigned_to": None}
    assert entry.new_value_json == {"assigned_to": "alice"}


def test_unassignment_is_audited(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    client.put(
        f"{BASE}/{context.id}/assignment",
        json={"assigned_to": "alice", "row_version": context.row_version, "reason": "triage"},
    )
    db.refresh(context)
    response = client.put(
        f"{BASE}/{context.id}/assignment",
        json={"assigned_to": None, "row_version": context.row_version, "reason": "handed back"},
    )
    assert response.status_code == 200, response.text
    db.refresh(context)
    assert context.assigned_to is None
    assert len([a for a in audits_for(db, context.id) if a.action == "ASSIGNMENT"]) == 2


# ---------------------------------------------------------------------------
# Manual resolution of an unresolved mapping — VEX-MAP-001
# ---------------------------------------------------------------------------


def test_analyst_can_bind_an_unresolved_assertion__VEX_MAP_001(client, seeded, db):
    context = context_for(db, "CVE-2026-9001")
    assert context.reconciliation_status == "UNRESOLVED_MAPPING"
    assert context.component_id is None

    response = client.put(
        f"{BASE}/{context.id}/component",
        json={
            "component_id": seeded["component"].id,
            "row_version": context.row_version,
            "reason": "supplier confirmed this is the 1.1.1 build",
        },
    )
    assert response.status_code == 200, response.text
    db.refresh(context)
    assert context.component_id == seeded["component"].id
    assert context.component_key == seeded["component"].id


def test_binding_is_audited_while_component_was_null__VEX_AUD_001(client, seeded, db):
    """The audit row that made component_id nullable in migration 057."""
    context = context_for(db, "CVE-2026-9001")
    client.put(
        f"{BASE}/{context.id}/component",
        json={
            "component_id": seeded["component"].id,
            "row_version": context.row_version,
            "reason": "confirmed",
        },
    )
    entry = [a for a in audits_for(db, context.id) if a.action == "MAPPING_RESOLUTION"][0]
    assert entry.old_value_json == {"component_id": None}
    assert entry.new_value_json == {"component_id": seeded["component"].id}
    assert entry.sbom_id == seeded["sbom"].id


def test_binding_a_resolved_context_is_refused(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/component",
        json={
            "component_id": seeded["other"].id,
            "row_version": context.row_version,
            "reason": "should not be allowed",
        },
    )
    assert response.status_code == 409


def test_binding_to_a_component_in_another_sbom_is_refused__VEX_CTX_001(client, seeded, db):
    other_sbom = SBOMSource(sbom_name="elsewhere", sbom_data="{}", tenant_id=1, is_active=True)
    db.add(other_sbom)
    db.flush()
    foreign = SBOMComponent(sbom_id=other_sbom.id, name="openssl", version="1.1.1", tenant_id=1)
    db.add(foreign)
    db.commit()

    context = context_for(db, "CVE-2026-9001")
    response = client.put(
        f"{BASE}/{context.id}/component",
        json={
            "component_id": foreign.id,
            "row_version": context.row_version,
            "reason": "wrong sbom",
        },
    )
    assert response.status_code == 404

    db.query(SBOMComponent).filter_by(id=foreign.id).delete()
    db.query(SBOMSource).filter_by(id=other_sbom.id).delete()
    db.commit()


# ---------------------------------------------------------------------------
# Tenant isolation — VEX-SEC-002
# ---------------------------------------------------------------------------


def test_reconciliation_never_crosses_tenants__VEX_SEC_002(seeded, db):
    """Identical PURL and CVE in another tenant must not merge or match."""
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, "
            "created_at, updated_at) VALUES (3, 'Tenant Three', 'three', 'three', "
            "'ACTIVE', :now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    db.commit()

    # A statement in tenant 3 naming the same CVE and component name.
    db.execute(
        text(
            "INSERT INTO sbom_source (sbom_name, sbom_data, tenant_id, is_active) "
            "VALUES ('t3', '{}', 3, true)"
        )
    )
    db.commit()
    t3_sbom = db.execute(
        text("SELECT id FROM sbom_source WHERE tenant_id = 3 ORDER BY id DESC LIMIT 1")
    ).scalar()

    recompute_for_sbom(db, tenant_id=1, sbom_id=seeded["sbom"].id)
    db.commit()

    crossed = db.execute(
        text(
            "SELECT COUNT(*) FROM vex_investigation WHERE tenant_id = 1 AND sbom_id = :sid"
        ),
        {"sid": t3_sbom},
    ).scalar()
    assert crossed == 0, "tenant 1 must never produce a context for another tenant's SBOM"

    db.execute(text("DELETE FROM sbom_source WHERE id = :sid"), {"sid": t3_sbom})
    db.commit()


def test_cross_tenant_mutations_are_rejected__VEX_SEC_002(client, seeded, db):
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, "
            "created_at, updated_at) VALUES (2, 'Other', 'other', 'other', 'ACTIVE', "
            ":now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    context = context_for(db, "CVE-2026-5001")
    db.execute(
        text("UPDATE vex_investigation SET tenant_id = 2 WHERE id = :id"), {"id": context.id}
    )
    db.commit()

    for path, body in (
        ("decision", {"status": "AFFECTED", "row_version": 1, "reason": "x"}),
        ("assignment", {"assigned_to": "mallory", "row_version": 1, "reason": "x"}),
        ("component", {"component_id": seeded["component"].id, "row_version": 1, "reason": "x"}),
    ):
        assert client.put(f"{BASE}/{context.id}/{path}", json=body).status_code == 404

    db.execute(
        text("UPDATE vex_investigation SET tenant_id = 1 WHERE id = :id"), {"id": context.id}
    )
    db.commit()


# ---------------------------------------------------------------------------
# RBAC — VEX-SEC-001
# ---------------------------------------------------------------------------


def test_role_permissions_match_the_spec__VEX_SEC_001():
    """SECURITY_ANALYST writes; DEVELOPER and VIEWER only read (section 42)."""
    analyst = ROLE_PERMISSIONS[Role.SECURITY_ANALYST]
    assert "vex:read" in analyst and "vex:write" in analyst
    for role in (Role.DEVELOPER, Role.VIEWER):
        permissions = ROLE_PERMISSIONS[role]
        assert "vex:read" in permissions
        assert "vex:write" not in permissions, f"{role} must not hold vex:write"
    assert "vex:write" in ROLE_PERMISSIONS[Role.TENANT_ADMIN]


def test_every_investigation_route_maps_to_a_vex_permission__VEX_SEC_001():
    from app.core.security import permission_for_request

    class _Request:
        def __init__(self, method, path):
            self.method = method
            self.url = type("U", (), {"path": path})()

    assert permission_for_request(_Request("GET", f"{BASE}")) == "vex:read"
    assert permission_for_request(_Request("GET", f"{BASE}/1")) == "vex:read"
    for path in ("decision", "assignment", "component"):
        assert permission_for_request(_Request("PUT", f"{BASE}/1/{path}")) == "vex:write"
