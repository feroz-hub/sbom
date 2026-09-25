"""PR-4 tests — the portfolio VEX investigation API.

Spec sections 27-29 and 40-44. Driven through HTTP so the response contracts,
filters, pagination and status codes are what a client actually receives.

Uses the shared ``client`` fixture rather than a bare ``TestClient``: the
fixture runs the app lifespan, without which requests are rejected by the
identity gate before reaching any VEX code.

Authorization runs with ``API_AUTH_MODE=none`` (the conftest default), so
these cover the contract and tenant scoping. Role-by-role permission
enforcement is PR-6's hardening pass.
"""

import pytest
from sqlalchemy import select, text

from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    SBOMComponent,
    SBOMSource,
    VexDocument,
    VexInvestigation,
    VexStatement,
)
from app.services.lifecycle.vex_provider import vex_dashboard_summary
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
    """One SBOM with an ANALYZER_ONLY context and a MATCHED NOT_AFFECTED one."""
    sbom = SBOMSource(sbom_name="api-test", sbom_data="{}", tenant_id=1, is_active=True)
    db.add(sbom)
    db.flush()

    openssl = SBOMComponent(
        sbom_id=sbom.id, name="openssl", version="1.1.1", tenant_id=1,
        purl="pkg:generic/openssl@1.1.1",
    )
    zlib = SBOMComponent(sbom_id=sbom.id, name="zlib", version="1.2.11", tenant_id=1)
    db.add_all([openssl, zlib])
    db.flush()

    run = AnalysisRun(
        sbom_id=sbom.id, tenant_id=1, run_status="OK", started_on=NOW, completed_on=NOW
    )
    db.add(run)
    db.flush()

    db.add(
        AnalysisFinding(
            analysis_run_id=run.id, component_id=openssl.id, vuln_id="CVE-2026-5001",
            tenant_id=1, source="NVD", severity="HIGH", description="analyser finding",
            reference_url="https://example.test/1",
        )
    )
    db.add(
        AnalysisFinding(
            analysis_run_id=run.id, component_id=zlib.id, vuln_id="CVE-2026-5002",
            tenant_id=1, source="OSV", severity="LOW",
        )
    )
    document = VexDocument(
        sbom_id=sbom.id, tenant_id=1, source_type="uploaded", format="openvex",
        author="Supplier A", source_document_id="doc-a", uploaded_at=NOW,
    )
    db.add(document)
    db.flush()
    db.add(
        VexStatement(
            vex_document_id=document.id, sbom_id=sbom.id, component_id=zlib.id,
            vulnerability_id="CVE-2026-5002", tenant_id=1, status="not_affected",
            normalized_status="NOT_AFFECTED", source_status="not_affected",
            source_format="openvex", justification="vulnerable_code_not_present",
            source_name="Supplier A", created_at=NOW,
        )
    )
    db.commit()
    recompute_for_sbom(db, tenant_id=1, sbom_id=sbom.id)
    db.commit()

    yield {"sbom": sbom, "openssl": openssl, "zlib": zlib, "run": run}

    for model in (VexInvestigation, VexStatement, VexDocument, AnalysisFinding, AnalysisRun):
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


def fetch(client, **params):
    response = client.get(BASE, params=params)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# List endpoint — VEX-UI-001 / VEX-UI-002
# ---------------------------------------------------------------------------


def test_returns_the_paginated_envelope__VEX_UI_001(client, seeded):
    payload = fetch(client)
    assert sorted(payload) == ["items", "limit", "offset", "total"]
    assert payload["total"] == 2
    assert len(payload["items"]) == 2


def test_rows_carry_the_section_27_columns__VEX_UI_001(client, seeded):
    row = fetch(client)["items"][0]
    for field in (
        "canonical_vulnerability_id", "aliases", "severity", "component_name",
        "component_version", "sbom_name", "analyzer_detection_state", "vex_source",
        "native_vex_status", "effective_status", "reconciliation_status",
        "assigned_to", "row_version", "needs_review",
    ):
        assert field in row


def test_filter_by_effective_status__VEX_UI_002(client, seeded):
    payload = fetch(client, effective_status="NOT_AFFECTED")
    assert payload["total"] == 1
    assert payload["items"][0]["canonical_vulnerability_id"] == "CVE-2026-5002"


def test_filter_by_reconciliation_status__VEX_UI_002(client, seeded):
    payload = fetch(client, reconciliation_status="ANALYZER_ONLY")
    assert payload["total"] == 1
    assert payload["items"][0]["canonical_vulnerability_id"] == "CVE-2026-5001"


def test_filter_by_component__VEX_UI_002(client, seeded):
    assert fetch(client, component="zlib")["total"] == 1
    assert fetch(client, component="nope")["total"] == 0


def test_filter_by_sbom__VEX_UI_002(client, seeded):
    assert fetch(client, sbom_id=seeded["sbom"].id)["total"] == 2
    assert fetch(client, sbom_id=seeded["sbom"].id + 9999)["total"] == 0


def test_search_by_vulnerability_id__VEX_UI_002(client, seeded):
    assert fetch(client, q="CVE-2026-5001")["total"] == 1


def test_filter_by_severity_uses_analyser_findings__VEX_UI_002(client, seeded):
    """Severity is the vulnerability's, resolved from analyser findings."""
    assert fetch(client, severity="HIGH")["total"] == 1
    assert fetch(client, severity="LOW")["total"] == 1
    assert fetch(client, severity="CRITICAL")["total"] == 0


def test_needs_review_toggle__VEX_UI_002(client, seeded):
    assert fetch(client, needs_review="true")["total"] == 0
    assert fetch(client, needs_review="false")["total"] == 2


def test_severity_sort_is_refused_rather_than_faked(client, seeded):
    """Severity has no context column; an arbitrary order would be a lie."""
    response = client.get(BASE, params={"sort_by": "severity"})
    assert response.status_code in (400, 422)


def test_pagination_does_not_repeat_a_row(client, seeded):
    first = fetch(client, limit=1, offset=0, sort_by="vulnerability_id", sort_order="asc")
    second = fetch(client, limit=1, offset=1, sort_by="vulnerability_id", sort_order="asc")
    assert first["total"] == 2
    assert len(first["items"]) == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]


def test_sort_order_is_honoured(client, seeded):
    asc = fetch(client, sort_by="vulnerability_id", sort_order="asc")["items"]
    desc = fetch(client, sort_by="vulnerability_id", sort_order="desc")["items"]
    assert [r["canonical_vulnerability_id"] for r in asc] == list(
        reversed([r["canonical_vulnerability_id"] for r in desc])
    )


def test_tile_counts_equal_row_counts_for_the_same_filters__VEX_DASH_004(client, seeded, db):
    summary = vex_dashboard_summary(db, tenant_id=1, sbom_ids=[seeded["sbom"].id])
    rows = fetch(client, sbom_id=seeded["sbom"].id)
    assert summary["total_contexts"] == rows["total"]


# ---------------------------------------------------------------------------
# Detail endpoint — VEX-UI-003
# ---------------------------------------------------------------------------


def detail(client, db, vuln_id="CVE-2026-5002"):
    context = context_for(db, vuln_id)
    response = client.get(f"{BASE}/{context.id}")
    assert response.status_code == 200, response.text
    return response.json()


def test_sections_are_present_and_separate__VEX_UI_003(client, seeded, db):
    payload = detail(client, db)
    for section in (
        "vulnerability", "component", "analyzer_evidence",
        "imported_vex", "internal_decision", "history",
    ):
        assert section in payload
    assert payload["reconciliation_status"] == "MATCHED"
    assert payload["effective_status"] == "NOT_AFFECTED"


def test_imported_assertions_keep_native_and_normalized_status__VEX_STAT_002(client, seeded, db):
    assertions = detail(client, db)["imported_vex"]
    assert len(assertions) == 1
    assert assertions[0]["source_status"] == "not_affected"
    assert assertions[0]["normalized_status"] == "NOT_AFFECTED"
    assert assertions[0]["source_format"] == "openvex"
    assert assertions[0]["author"] == "Supplier A"


def test_severity_comes_from_the_vulnerability__VEX_DATA_005(client, seeded, db):
    """NOT_AFFECTED must not rewrite or hide severity."""
    payload = detail(client, db)
    assert payload["effective_status"] == "NOT_AFFECTED"
    assert payload["vulnerability"]["severity"] == "LOW"


def test_analyzer_evidence_is_reported(client, seeded, db):
    evidence = detail(client, db, "CVE-2026-5001")["analyzer_evidence"]
    assert evidence["detection_state"] == "DETECTED"
    assert evidence["analysis_run_id"] == seeded["run"].id


def test_unknown_id_is_404(client, seeded):
    assert client.get(f"{BASE}/99999999").status_code == 404


def test_cross_tenant_detail_is_404_not_403__VEX_SEC_002(client, seeded, db):
    """404 rather than 403: 403 would confirm the row exists elsewhere."""
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
        text("UPDATE vex_investigation SET tenant_id = 2 WHERE id = :id"),
        {"id": context.id},
    )
    db.commit()
    assert client.get(f"{BASE}/{context.id}").status_code == 404
    db.execute(
        text("UPDATE vex_investigation SET tenant_id = 1 WHERE id = :id"),
        {"id": context.id},
    )
    db.commit()


# ---------------------------------------------------------------------------
# Decision endpoint — VEX-INV-003 / VEX-AUD-002 / VEX-VAL-001/002
# ---------------------------------------------------------------------------


def decide(client, context, **body):
    payload = {
        "status": "NOT_AFFECTED",
        "row_version": context.row_version,
        "reason": "reviewed by security",
        "justification": "vulnerable_code_not_present",
    }
    payload.update(body)
    return client.put(f"{BASE}/{context.id}/decision", json=payload)


def test_decision_is_recorded_and_bumps_the_version__VEX_INV_003(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    before = context.row_version
    response = decide(client, context)
    assert response.status_code == 200, response.text
    db.refresh(context)
    assert context.effective_status == "NOT_AFFECTED"
    assert context.row_version > before


def test_stale_row_version_conflicts__VEX_AUD_002(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    assert decide(client, context).status_code == 200
    stale = client.put(
        f"{BASE}/{context.id}/decision",
        json={"status": "AFFECTED", "row_version": 1, "reason": "disagree", "justification": "x"},
    )
    assert stale.status_code == 409
    assert "row_version" in stale.json()


def test_not_affected_without_evidence_is_rejected__VEX_VAL_001(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "NOT_AFFECTED", "row_version": context.row_version,
            "reason": "no evidence supplied",
        },
    )
    assert response.status_code == 422


def test_fixed_without_remediation_evidence_is_rejected__VEX_VAL_002(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "FIXED", "row_version": context.row_version,
            "reason": "trust me", "fixed_version": " ",
        },
    )
    assert response.status_code == 422


def test_reason_is_mandatory__VEX_AUD_001(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/decision",
        json={"status": "AFFECTED", "row_version": context.row_version, "reason": ""},
    )
    assert response.status_code == 422


def test_decision_survives_reconciliation__VEX_INV_004(client, seeded, db):
    context = context_for(db, "CVE-2026-5001")
    assert decide(client, context).status_code == 200
    recompute_for_sbom(db, tenant_id=1, sbom_id=seeded["sbom"].id)
    db.commit()
    db.refresh(context)
    assert context.effective_status == "NOT_AFFECTED"


# ---------------------------------------------------------------------------
# The existing component-scoped endpoints must keep working
# ---------------------------------------------------------------------------


def test_component_vulnerabilities_endpoint_still_responds(client, seeded):
    response = client.get(
        f"/api/sboms/{seeded['sbom'].id}/components/{seeded['zlib'].id}/vulnerabilities"
    )
    assert response.status_code == 200, response.text
    assert "vulnerabilities" in response.json()


def test_sbom_vex_list_endpoint_still_responds(client, seeded):
    response = client.get(f"/api/sboms/{seeded['sbom'].id}/vex")
    assert response.status_code == 200, response.text
    assert "statements" in response.json()


# ---------------------------------------------------------------------------
# Resolve by (sbom, component, vulnerability) — how the SBOM page reaches the
# same context the queue addresses by id
# ---------------------------------------------------------------------------

RESOLVE = f"{BASE}/resolve"


def resolve(client, seeded, vuln_id, component=None):
    return client.get(
        RESOLVE,
        params={
            "sbom_id": seeded["sbom"].id,
            "component_id": (component or seeded["zlib"]).id,
            "vulnerability_id": vuln_id,
        },
    )


def test_resolve_finds_the_context_for_a_pair(client, seeded, db):
    response = resolve(client, seeded, "CVE-2026-5002")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["vulnerability"]["canonical_vulnerability_id"] == "CVE-2026-5002"
    assert payload["component"]["component_id"] == seeded["zlib"].id
    # Carries the concurrency token the SBOM page previously had no way to get.
    assert payload["row_version"] >= 1


def test_resolve_returns_404_when_nothing_has_asserted_it(client, seeded):
    """An ordinary state, not an error: the editor falls back to the override."""
    assert resolve(client, seeded, "CVE-2026-0000").status_code == 404


def test_resolve_matches_an_alias__VEX_CTX_002(client, seeded, db):
    """A context canonicalised to its CVE is reachable by the GHSA reported."""
    context = context_for(db, "CVE-2026-5002")
    context.aliases_json = '["GHSA-ZZZZ-YYYY-XXXX"]'
    db.commit()
    response = resolve(client, seeded, "GHSA-zzzz-yyyy-xxxx")
    assert response.status_code == 200, response.text
    assert response.json()["id"] == context.id


def test_resolve_is_tenant_scoped__VEX_SEC_002(client, seeded, db):
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, "
            "created_at, updated_at) VALUES (2, 'Other', 'other', 'other', 'ACTIVE', "
            ":now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    context = context_for(db, "CVE-2026-5002")
    db.execute(
        text("UPDATE vex_investigation SET tenant_id = 2 WHERE id = :id"), {"id": context.id}
    )
    db.commit()
    assert resolve(client, seeded, "CVE-2026-5002").status_code == 404
    db.execute(
        text("UPDATE vex_investigation SET tenant_id = 1 WHERE id = :id"), {"id": context.id}
    )
    db.commit()


def test_resolve_does_not_create_a_context(client, seeded, db):
    """Read-only by design: a context the analyst has not committed to would
    be invented here and possibly retired by the next reconciliation."""
    before = db.query(VexInvestigation).count()
    resolve(client, seeded, "CVE-2026-0000")
    db.expire_all()
    assert db.query(VexInvestigation).count() == before


def test_mitigation_survives_the_decision_endpoint(client, seeded, db):
    """`mitigation` existed on the override path but not here, so the shared
    editor would have dropped it whenever an analyst worked from the queue."""
    context = context_for(db, "CVE-2026-5001")
    response = client.put(
        f"{BASE}/{context.id}/decision",
        json={
            "status": "AFFECTED",
            "row_version": context.row_version,
            "reason": "confirmed reachable",
            "mitigation": "Disable the legacy TLS listener until patched.",
        },
    )
    assert response.status_code == 200, response.text
    statement = db.scalars(
        select(VexStatement)
        .where(VexStatement.vulnerability_id == "CVE-2026-5001")
        .order_by(VexStatement.id.desc())
    ).first()
    assert statement.mitigation == "Disable the legacy TLS listener until patched."
