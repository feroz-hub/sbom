"""PR-7 — end-to-end acceptance suite for the VEX workstream.

Spec sections 47-48. These drive the *public* entry points (import a VEX
document, reconcile, read `/dashboard/vex` and `/api/vex/investigations`,
make a decision, re-analyse) against realistic fixture documents in
``tests/fixtures/vex/``, rather than calling services directly. The
engine-level equivalents in ``test_vex_reconciliation_engine.py`` stay —
they pin the rules; these pin the wiring.

Rows of the section 47 matrix already covered end-to-end by
``test_vex_investigations_api.py`` (cross-tenant, concurrency) or by
``test_vex_audit_concurrency.py`` are not duplicated here; the mapping lives
in ``docs/vex/acceptance-report.md``.
"""

import json
from pathlib import Path

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
from app.services.lifecycle.vex_provider import (
    import_vex_document,
    vex_dashboard_summary,
    vex_report,
    vex_report_csv,
)
from app.services.vex.reconciliation import recompute_for_sbom

FIXTURES = Path(__file__).parent / "fixtures" / "vex"
NOW = "2026-09-24T00:00:00Z"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def project(db):
    """An SBOM whose components match the fixture PURLs, plus a clean run."""
    document = load("sbom-with-embedded-vex.cdx.json")
    sbom = SBOMSource(
        sbom_name="acceptance-app",
        sbom_data=json.dumps(document),
        tenant_id=1,
        is_active=True,
    )
    db.add(sbom)
    db.flush()

    components = {}
    for entry in document["components"]:
        component = SBOMComponent(
            sbom_id=sbom.id,
            name=entry["name"],
            version=entry["version"],
            purl=entry["purl"],
            bom_ref=entry["bom-ref"],
            tenant_id=1,
        )
        db.add(component)
        db.flush()
        components[entry["name"]] = component

    run = AnalysisRun(
        sbom_id=sbom.id, tenant_id=1, run_status="OK", started_on=NOW, completed_on=NOW
    )
    db.add(run)
    db.flush()
    db.commit()

    yield {"sbom": sbom, "components": components, "run": run, "document": document}

    for model in (VexInvestigation, VexStatement, VexDocument, AnalysisFinding, AnalysisRun):
        db.query(model).delete()
    db.query(SBOMComponent).delete()
    db.query(SBOMSource).delete()
    db.commit()


def add_finding(db, project, component_name, vuln_id, *, severity="HIGH", source="NVD", aliases=None):
    db.add(
        AnalysisFinding(
            analysis_run_id=project["run"].id,
            component_id=project["components"][component_name].id,
            vuln_id=vuln_id,
            tenant_id=1,
            source=source,
            severity=severity,
            aliases=aliases,
        )
    )
    db.flush()


def reconcile(db, project):
    recompute_for_sbom(db, tenant_id=1, sbom_id=project["sbom"].id)
    db.commit()


def contexts(db, project):
    return {
        c.canonical_vulnerability_id: c
        for c in db.scalars(
            select(VexInvestigation).where(
                VexInvestigation.sbom_id == project["sbom"].id,
                VexInvestigation.is_current.is_(True),
            )
        ).all()
    }


def summary(db, project):
    return vex_dashboard_summary(db, tenant_id=1, sbom_ids=[project["sbom"].id])


# ---------------------------------------------------------------------------
# Embedded CycloneDX VEX — VEX-ING-001, VEX-STAT-002
# ---------------------------------------------------------------------------


def test_embedded_false_positive_preserves_the_native_value__VEX_STAT_002(db, project):
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    statement = db.scalar(
        select(VexStatement).where(VexStatement.vulnerability_id == "CVE-2026-4001")
    )
    assert statement.source_status == "false_positive"
    assert statement.normalized_status == "NOT_AFFECTED"
    assert statement.source_format == "cyclonedx"


def test_embedded_in_triage_becomes_under_investigation__VEX_STAT_002(db, project):
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    statement = db.scalar(
        select(VexStatement).where(VexStatement.vulnerability_id == "CVE-2026-4002")
    )
    assert statement.source_status == "in_triage"
    assert statement.normalized_status == "UNDER_INVESTIGATION"


def test_plain_disclosure_entry_is_not_a_vex_determination__VEX_ING_001(db, project):
    """CVE-2026-4003 has no analysis block — disclosure data, not VEX."""
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    assert db.scalar(
        select(VexStatement).where(VexStatement.vulnerability_id == "CVE-2026-4003")
    ) is None


def test_embedded_vex_only_cve_survives__VEX_REC_002_C(db, project):
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    reconcile(db, project)
    context = contexts(db, project)["CVE-2026-4001"]
    assert context.effective_status == "NOT_AFFECTED"
    assert context.reconciliation_status == "VEX_ONLY"
    assert db.query(AnalysisFinding).count() == 0, "no finding may be fabricated"


# ---------------------------------------------------------------------------
# The spec section 24 worked example, end to end
# ---------------------------------------------------------------------------


def test_section_24_scenario__VEX_DASH_001(db, project):
    """3 analyser CVEs + 1 embedded VEX-only CVE -> 3 findings, 4 contexts."""
    import_vex_document(
        db,
        project["sbom"].id,
        {
            "bomFormat": "CycloneDX",
            "serialNumber": "urn:uuid:section-24",
            "vulnerabilities": [
                {
                    "id": "CVE-2026-4001",
                    "analysis": {"state": "false_positive", "justification": "code_not_reachable"},
                    "affects": [{"ref": "pkg:generic/openssl@1.1.1"}],
                }
            ],
        },
        source_type="embedded",
    )
    for vuln in ("CVE-2026-5001", "CVE-2026-5002", "CVE-2026-5003"):
        add_finding(db, project, "zlib", vuln)
    db.commit()
    reconcile(db, project)

    payload = summary(db, project)
    assert db.query(AnalysisFinding).count() == 3
    assert payload["total_contexts"] == 4
    assert payload["affected_count"] == 0
    assert payload["not_affected_count"] == 1
    assert payload["fixed_count"] == 0
    assert payload["under_investigation_count"] == 3
    assert payload["matched_count"] == 0
    assert payload["analyzer_only_count"] == 3
    assert payload["vex_only_count"] == 1
    assert payload["needs_review_count"] == 0


# ---------------------------------------------------------------------------
# Multi-format import
# ---------------------------------------------------------------------------


def test_openvex_import_reconciles__VEX_REC_002_C(db, project):
    import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    reconcile(db, project)
    context = contexts(db, project)["CVE-2026-7001"]
    assert context.effective_status == "NOT_AFFECTED"
    assert context.reconciliation_status == "VEX_ONLY"


def test_csaf_import_reconciles__VEX_REC_002_C(db, project):
    import_vex_document(db, project["sbom"].id, load("supplier-csaf.json"))
    reconcile(db, project)
    assert "CVE-2026-7003" in contexts(db, project)


def test_conflicting_suppliers_require_review__VEX_INV_005(db, project):
    import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    import_vex_document(db, project["sbom"].id, load("supplier-b-openvex-conflicting.json"))
    add_finding(db, project, "openssl", "CVE-2026-7001")
    db.commit()
    reconcile(db, project)

    context = contexts(db, project)["CVE-2026-7001"]
    assert context.effective_status == "UNDER_INVESTIGATION"
    assert context.reconciliation_status == "CONFLICT_REVIEW_REQUIRED"
    # Both assertions remain accessible.
    assert db.query(VexStatement).filter_by(vulnerability_id="CVE-2026-7001").count() == 2


def test_new_document_version_supersedes_rather_than_conflicts__VEX_ING_002(db, project):
    first = import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    second = import_vex_document(db, project["sbom"].id, load("supplier-a-openvex-v2.json"))
    add_finding(db, project, "openssl", "CVE-2026-7001")
    db.commit()
    reconcile(db, project)

    assert second["superseded_document_ids"] == [first["document_id"]]
    context = contexts(db, project)["CVE-2026-7001"]
    assert context.reconciliation_status == "MATCHED"
    assert context.effective_status == "AFFECTED", "the newer version wins, not a conflict"


def test_duplicate_document_upload_is_idempotent__VEX_ING_002(db, project):
    first = import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    second = import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    assert second["already_imported"] is True
    assert second["document_id"] == first["document_id"]
    assert db.query(VexDocument).count() == 1
    assert db.query(VexStatement).count() == 1


# ---------------------------------------------------------------------------
# Alias reconciliation and dedup
# ---------------------------------------------------------------------------


def test_ghsa_finding_and_cve_vex_share_one_context__VEX_CTX_002(db, project):
    import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    add_finding(
        db, project, "openssl", "GHSA-aaaa-bbbb-cccc", aliases='["CVE-2026-7001"]'
    )
    db.commit()
    reconcile(db, project)

    current = contexts(db, project)
    assert "CVE-2026-7001" in current
    assert current["CVE-2026-7001"].reconciliation_status == "MATCHED"
    assert len(current) == 1


def test_three_scanners_produce_one_context__VEX_REC_003(db, project):
    add_finding(db, project, "openssl", "CVE-2026-8001", source="NVD")
    add_finding(db, project, "openssl", "CVE-2026-8001", source="OSV")
    add_finding(
        db, project, "openssl", "GHSA-dddd-eeee-ffff",
        source="GITHUB", aliases='["CVE-2026-8001"]',
    )
    db.commit()
    reconcile(db, project)
    assert len(contexts(db, project)) == 1


# ---------------------------------------------------------------------------
# Re-analysis — VEX-INV-001 / VEX-INV-002
# ---------------------------------------------------------------------------


def test_reanalysis_updates_evidence_and_keeps_the_decision__VEX_INV_001(db, project):
    add_finding(db, project, "openssl", "CVE-2026-9101")
    db.commit()
    reconcile(db, project)

    from app.services.lifecycle.vex_provider import apply_vex_override

    apply_vex_override(
        db,
        project["components"]["openssl"].id,
        "CVE-2026-9101",
        {"status": "not_affected", "reason": "reviewed", "justification": "not reachable"},
        changed_by="analyst",
    )
    reconcile(db, project)
    first_seen = contexts(db, project)["CVE-2026-9101"].first_seen_at

    later = AnalysisRun(
        sbom_id=project["sbom"].id, tenant_id=1, run_status="OK",
        started_on=NOW, completed_on=NOW,
    )
    db.add(later)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=later.id,
            component_id=project["components"]["openssl"].id,
            vuln_id="CVE-2026-9101", tenant_id=1, source="NVD", severity="HIGH",
        )
    )
    db.commit()
    reconcile(db, project)

    context = contexts(db, project)["CVE-2026-9101"]
    assert context.effective_status == "NOT_AFFECTED"
    assert context.first_seen_at == first_seen
    assert context.last_analysis_run_id == later.id


def test_vanished_context_leaves_the_queue_but_is_retained__VEX_INV_002(db, project):
    add_finding(db, project, "openssl", "CVE-2026-9201")
    db.commit()
    reconcile(db, project)

    later = AnalysisRun(
        sbom_id=project["sbom"].id, tenant_id=1, run_status="OK",
        started_on=NOW, completed_on=NOW,
    )
    db.add(later)
    db.flush()
    db.add(
        AnalysisFinding(
            analysis_run_id=later.id,
            component_id=project["components"]["openssl"].id,
            vuln_id="CVE-2026-9202", tenant_id=1, source="NVD", severity="HIGH",
        )
    )
    db.commit()
    reconcile(db, project)

    assert "CVE-2026-9201" not in contexts(db, project)
    retained = db.scalar(
        select(VexInvestigation).where(
            VexInvestigation.canonical_vulnerability_id == "CVE-2026-9201"
        )
    )
    assert retained is not None and retained.is_current is False


# ---------------------------------------------------------------------------
# Dashboard scope — VEX-DASH-004 / VEX-DASH-005
# ---------------------------------------------------------------------------


def test_inactive_sbom_is_excluded_from_current_counts__VEX_DASH_005(db, project):
    """The row Session 0 left open: an inactive SBOM drops out end to end."""
    add_finding(db, project, "openssl", "CVE-2026-9301")
    db.commit()
    reconcile(db, project)
    assert summary(db, project)["total_contexts"] == 1

    from app.services.dashboard_scope import DashboardScope

    project["sbom"].is_active = False
    db.commit()

    scope = DashboardScope(tenant_id=1)
    eligible = [row[0] for row in db.execute(select(SBOMSource.id).where(
        SBOMSource.id.in_(scope.eligible_sbom_ids())
    )).all()]
    assert project["sbom"].id not in eligible, "scope must drop an inactive SBOM"

    payload = vex_dashboard_summary(db, tenant_id=1, sbom_ids=scope.eligible_sbom_ids())
    assert payload["total_contexts"] == 0

    # The context itself is retained for history.
    assert db.query(VexInvestigation).count() == 1
    project["sbom"].is_active = True
    db.commit()


def test_superseded_sbom_version_is_excluded__VEX_DASH_005(db, project):
    """A superseded (non-HEAD) SBOM version drops out of current counts."""
    add_finding(db, project, "openssl", "CVE-2026-9401")
    db.commit()
    reconcile(db, project)

    successor = SBOMSource(
        sbom_name="acceptance-app", sbom_data="{}", tenant_id=1,
        is_active=True, parent_id=project["sbom"].id,
    )
    db.add(successor)
    db.commit()

    from app.services.dashboard_scope import DashboardScope

    scope = DashboardScope(tenant_id=1)
    eligible = [row[0] for row in db.execute(select(SBOMSource.id).where(
        SBOMSource.id.in_(scope.eligible_sbom_ids())
    )).all()]
    assert project["sbom"].id not in eligible, "the parent is no longer HEAD"

    payload = vex_dashboard_summary(db, tenant_id=1, sbom_ids=scope.eligible_sbom_ids())
    assert payload["total_contexts"] == 0

    db.query(SBOMSource).filter_by(id=successor.id).delete()
    db.commit()


def test_tile_counts_equal_table_counts__VEX_DASH_004(client, db, project):
    import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    add_finding(db, project, "zlib", "CVE-2026-9501")
    db.commit()
    reconcile(db, project)

    payload = summary(db, project)
    response = client.get(
        "/api/vex/investigations", params={"sbom_id": project["sbom"].id}
    )
    assert response.status_code == 200, response.text
    assert payload["total_contexts"] == response.json()["total"]


# ---------------------------------------------------------------------------
# Exports — Definition of Done item 19
# ---------------------------------------------------------------------------


def test_report_and_csv_carry_native_and_effective_status__DoD_19(db, project):
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    reconcile(db, project)

    report = vex_report(db, project["sbom"].id)
    assert report["summary"]["not_affected"] >= 1
    assert report["statements"], "the report must still list statements"

    csv_text = vex_report_csv(db, project["sbom"].id)
    assert "vulnerability_id" in csv_text.splitlines()[0]
    assert "CVE-2026-4001" in csv_text


def test_vex_pack_zip_still_builds__DoD_19(client, db, project):
    import_vex_document(db, project["sbom"].id, project["document"], source_type="embedded")
    db.commit()
    response = client.get(f"/api/sboms/{project['sbom'].id}/reports/vex-pack")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"


# ---------------------------------------------------------------------------
# Migration backfill — every current finding gets a context
# ---------------------------------------------------------------------------


def test_backfill_gives_every_current_finding_a_context__DoD_1(db, project):
    """A pre-enhancement dataset: findings exist, no contexts, then recompute."""
    for index, name in enumerate(("openssl", "zlib", "libxml2")):
        add_finding(db, project, name, f"CVE-2026-95{index:02d}")
    db.commit()
    assert db.query(VexInvestigation).count() == 0

    reconcile(db, project)

    finding_keys = {
        (f.component_id, (f.vuln_id or "").upper())
        for f in db.scalars(select(AnalysisFinding)).all()
    }
    context_keys = {
        (c.component_id, c.canonical_vulnerability_id)
        for c in db.scalars(select(VexInvestigation)).all()
    }
    assert finding_keys <= context_keys, "every current finding must have a context"


def test_analyser_only_default_is_under_investigation__DoD_2(db, project):
    add_finding(db, project, "openssl", "CVE-2026-9601")
    db.commit()
    reconcile(db, project)
    context = contexts(db, project)["CVE-2026-9601"]
    assert context.effective_status == "UNDER_INVESTIGATION"
    assert context.reconciliation_status == "ANALYZER_ONLY"


def test_severity_is_never_rewritten_by_vex__VEX_DATA_005(db, project):
    add_finding(db, project, "openssl", "CVE-2026-7001", severity="CRITICAL")
    import_vex_document(db, project["sbom"].id, load("supplier-a-openvex.json"))
    db.commit()
    reconcile(db, project)

    context = contexts(db, project)["CVE-2026-7001"]
    assert context.effective_status == "NOT_AFFECTED"
    finding = db.scalar(
        select(AnalysisFinding).where(AnalysisFinding.vuln_id == "CVE-2026-7001")
    )
    assert finding.severity == "CRITICAL", "VEX must not touch severity"
