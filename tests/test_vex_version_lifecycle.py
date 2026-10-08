"""VEX across SBOM versions and analysis runs — lifecycle audit (2026-10-08).

Covers the questions the version-lifecycle audit asked of the existing VEX
implementation, each named with the scenario and the requirement it pins:

* a new SBOM version must not merge its predecessor's contexts into the
  current queue (VEX-DASH-004/005, VEX-INV-002);
* tile counts and the queue must agree for the same filters (VEX-DASH-004);
* repeated runs never add up, and a failed run never wipes current posture
  (VEX-INV-002, VEX-REC-004);
* decisions and assignments are never silently carried onto a new version
  (VEX-CTX-001, VEX-INV-004, VEX-AUD-001).

Driven through HTTP where the defect is user-visible, through the engine
where it is not.
"""

import pytest
from sqlalchemy import select, text

from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    Product,
    Projects,
    SBOMComponent,
    SBOMSource,
    VexInvestigation,
    VexOverrideAudit,
    VexStatement,
)
from app.services.vex.reconciliation import MANUAL_SOURCE_NAME, recompute_for_sbom

NOW = "2026-10-08T00:00:00Z"
QUEUE = "/api/vex/investigations"


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def app_line(db):
    """Project → TestApp, with helpers to add SBOM versions and runs."""
    project = Projects(tenant_id=1, project_name="Connected Medical Devices", project_status=1)
    db.add(project)
    db.flush()
    product = Product(
        tenant_id=1, project_id=project.id, name="TestApp", normalized_name="testapp",
        slug="testapp", created_at=NOW,
    )
    db.add(product)
    db.commit()

    class Line:
        def version(self, label, *, parent=None, lifecycle_status="ACTIVE"):
            sbom = SBOMSource(
                sbom_name=f"testapp-{label}", sbom_data="{}", tenant_id=1, is_active=True,
                projectid=project.id, product_id=product.id, sbom_version=label,
                productver=label, parent_id=parent.id if parent else None,
                lifecycle_status=lifecycle_status,
            )
            db.add(sbom)
            db.commit()
            return sbom

        def component(self, sbom, name, version):
            component = SBOMComponent(
                sbom_id=sbom.id, name=name, version=version, tenant_id=1,
                purl=f"pkg:generic/{name}@{version}",
            )
            db.add(component)
            db.commit()
            return component

        def run(self, sbom, findings, *, status="FINDINGS", is_current=True):
            """``findings`` is a list of ``(component, vuln_id[, severity, aliases])``."""
            run = AnalysisRun(
                sbom_id=sbom.id, tenant_id=1, run_status=status, started_on=NOW,
                completed_on=NOW, is_current=is_current, project_id=project.id,
                product_id=product.id,
            )
            db.add(run)
            db.flush()
            for entry in findings:
                component, vuln_id, *rest = entry
                db.add(
                    AnalysisFinding(
                        analysis_run_id=run.id, component_id=component.id, vuln_id=vuln_id,
                        tenant_id=1, source="NVD", severity=(rest[0] if rest else "HIGH"),
                        aliases=(rest[1] if len(rest) > 1 else None),
                        component_name=component.name, component_version=component.version,
                    )
                )
            db.commit()
            return run

        def reconcile(self, sbom):
            recompute_for_sbom(db, tenant_id=1, sbom_id=sbom.id)
            db.commit()

    line = Line()
    line.project, line.product = project, product
    yield line

    db.rollback()
    for model in (VexOverrideAudit, VexInvestigation, VexStatement, AnalysisFinding, AnalysisRun):
        db.query(model).delete()
    db.query(SBOMComponent).delete()
    db.query(Product).filter(Product.id == product.id).update({"current_sbom_id": None})
    db.query(SBOMSource).filter(SBOMSource.parent_id.isnot(None)).delete()
    db.query(SBOMSource).delete()
    db.query(Product).delete()
    db.query(Projects).delete()
    db.commit()


def queue(client, **params):
    response = client.get(QUEUE, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def tiles(client, **params):
    response = client.get("/dashboard/vex", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def two_versions(line):
    """A1.0.0 with three findings; A1.1.0 (its child) with two, one overlapping."""
    v1 = line.version("A1.0.0")
    v1_openssl = line.component(v1, "openssl", "1.1.1")
    v1_zlib = line.component(v1, "zlib", "1.2.11")
    line.run(v1, [(v1_openssl, "CVE-2026-1001"), (v1_openssl, "CVE-2026-1002"), (v1_zlib, "CVE-2026-1003")])
    line.reconcile(v1)

    v2 = line.version("A1.1.0", parent=v1)
    v2_openssl = line.component(v2, "openssl", "1.1.1")
    v2_curl = line.component(v2, "curl", "8.0.0")
    line.run(v2, [(v2_openssl, "CVE-2026-1001"), (v2_curl, "CVE-2026-1004")])
    line.reconcile(v2)
    return v1, v2


# ---------------------------------------------------------------------------
# Version scope — the queue must use the same eligible-SBOM scope as the tiles
# ---------------------------------------------------------------------------


def test_new_version_does_not_merge_previous_version_into_current_queue__VEX_INV_002(client, app_line):
    two_versions(app_line)
    assert tiles(client)["total_contexts"] == 2
    assert queue(client)["total"] == 2


def test_previous_version_contexts_are_retained_as_history__VEX_INV_002(client, app_line, db):
    v1, v2 = two_versions(app_line)
    retained = db.scalars(select(VexInvestigation).where(VexInvestigation.sbom_id == v1.id)).all()
    assert len(retained) == 3


def test_tiles_equal_queue_total_for_project_and_application_filters__VEX_DASH_004(client, app_line):
    two_versions(app_line)
    scope = {"project_id": app_line.project.id, "product_id": app_line.product.id}
    assert tiles(client, **scope)["total_contexts"] == queue(client, **scope)["total"] == 2


def test_inactive_sbom_is_excluded_from_queue__VEX_DASH_005(client, app_line):
    sbom = app_line.version("A2.0.0", lifecycle_status="INACTIVE")
    component = app_line.component(sbom, "openssl", "3.0.0")
    app_line.run(sbom, [(component, "CVE-2026-2001")])
    app_line.reconcile(sbom)
    assert tiles(client)["total_contexts"] == 0
    assert queue(client)["total"] == 0


# ---------------------------------------------------------------------------
# Filtered metrics — one predicate for cards, count and rows
# ---------------------------------------------------------------------------


def summary(client, **params):
    response = client.get(f"{QUEUE}/summary", params=params)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    "filters",
    [
        {},
        {"effective_status": "UNDER_INVESTIGATION"},
        {"reconciliation_status": "ANALYZER_ONLY"},
        {"component": "openssl"},
        {"severity": "HIGH"},
        {"needs_review": "true"},
        {"my_work": "unassigned"},
    ],
)
def test_filtered_metrics_equal_matching_count__VEX_DASH_004(client, app_line, filters):
    two_versions(app_line)
    cards = summary(client, **filters)
    rows = queue(client, **filters)
    assert cards["scope"] == "filtered"
    assert cards["total"] == rows["total"]


def test_filtered_metrics_honour_scope_filters__VEX_DASH_004(client, app_line):
    two_versions(app_line)
    scope = {"project_id": app_line.project.id, "product_id": app_line.product.id}
    cards = summary(client, **scope)
    assert cards["total"] == queue(client, **scope)["total"] == tiles(client, **scope)["total_contexts"]


def test_pagination_never_changes_metric_totals__VEX_DASH_004(client, app_line):
    two_versions(app_line)
    first = queue(client, limit=1, offset=0)
    second = queue(client, limit=1, offset=1)
    assert first["total"] == second["total"] == summary(client)["total"] == 2
    assert first["items"][0]["id"] != second["items"][0]["id"]


def test_filtered_status_buckets_reconcile__VEX_DASH_002(client, app_line):
    two_versions(app_line)
    cards = summary(client)
    assert cards["mapped_total"] == (
        cards["affected_count"] + cards["not_affected_count"]
        + cards["fixed_count"] + cards["under_investigation_count"]
    )
    assert cards["total"] == cards["mapped_total"] + cards["unresolved_mapping_count"]


def test_tenant_overview_is_unaffected_by_queue_filters__VEX_DASH_004(client, app_line):
    two_versions(app_line)
    assert summary(client, effective_status="AFFECTED")["total"] == 0
    assert tiles(client)["total_contexts"] == 2


def test_summary_is_tenant_scoped__VEX_SEC_002(client, app_line, db):
    """A context moved to another tenant vanishes from both queue and cards."""
    two_versions(app_line)
    db.execute(
        text(
            "INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, "
            "created_at, updated_at) VALUES (2, 'Other', 'other', 'other', 'ACTIVE', "
            ":now, :now) ON CONFLICT (id) DO NOTHING"
        ),
        {"now": NOW},
    )
    db.execute(text("UPDATE vex_investigation SET tenant_id = 2"))
    db.commit()
    try:
        assert summary(client)["total"] == queue(client)["total"] == 0
    finally:
        db.execute(text("UPDATE vex_investigation SET tenant_id = 1"))
        db.commit()


# ---------------------------------------------------------------------------
# Analysis-run lifecycle
# ---------------------------------------------------------------------------


def test_repeated_runs_do_not_aggregate__VEX_INV_002(client, app_line, db):
    sbom = app_line.version("A1.0.0")
    a, b, c = (app_line.component(sbom, n, "1.0") for n in ("a", "b", "c"))
    app_line.run(sbom, [(a, "CVE-2026-3001"), (b, "CVE-2026-3002"), (c, "CVE-2026-3003")])
    app_line.reconcile(sbom)
    app_line.run(sbom, [(a, "CVE-2026-3001"), (b, "CVE-2026-3002")])
    app_line.reconcile(sbom)
    app_line.run(sbom, [(a, "CVE-2026-3001"), (b, "CVE-2026-3002"), (c, "CVE-2026-3005")])
    app_line.reconcile(sbom)

    assert queue(client)["total"] == 3
    rows = db.scalars(select(VexInvestigation).where(VexInvestigation.sbom_id == sbom.id)).all()
    assert len(rows) == 4  # CVE-2026-3003 retained as history, not deleted
    assert sum(1 for r in rows if r.is_current) == 3


def test_failed_run_does_not_replace_current_posture__VEX_REC_004(client, app_line):
    sbom = app_line.version("A1.0.0")
    a = app_line.component(sbom, "a", "1.0")
    app_line.run(sbom, [(a, "CVE-2026-3101"), (a, "CVE-2026-3102")])
    app_line.reconcile(sbom)
    app_line.run(sbom, [], status="ERROR")
    app_line.reconcile(sbom)
    assert queue(client)["total"] == 2


def test_obsolete_run_never_becomes_current_posture__VEX_INV_002(client, app_line, db):
    """A run marked ``is_current = False`` (SBOM changed under it) is history.

    ``latest_run_per_sbom_subquery`` already excludes it; VEX must agree, or a
    VEX import or decision recompute would rebuild the queue from a stale run.
    """
    sbom = app_line.version("A1.0.0")
    a = app_line.component(sbom, "a", "1.0")
    good = app_line.run(sbom, [(a, "CVE-2026-3201")])
    app_line.run(sbom, [(a, "CVE-2026-3299")], is_current=False)
    app_line.reconcile(sbom)
    current = db.scalars(
        select(VexInvestigation).where(
            VexInvestigation.sbom_id == sbom.id, VexInvestigation.is_current.is_(True)
        )
    ).all()
    assert [r.canonical_vulnerability_id for r in current] == ["CVE-2026-3201"]
    assert current[0].last_analysis_run_id == good.id


# ---------------------------------------------------------------------------
# Identity — aliases must not lose severity
# ---------------------------------------------------------------------------


def test_ghsa_reported_finding_keeps_its_severity__VEX_CTX_002(client, app_line):
    sbom = app_line.version("A1.0.0")
    a = app_line.component(sbom, "a", "1.0")
    app_line.run(sbom, [(a, "GHSA-abcd-1234-5678", "CRITICAL", '["CVE-2026-3301"]')])
    app_line.reconcile(sbom)
    row = queue(client)["items"][0]
    assert row["canonical_vulnerability_id"] == "CVE-2026-3301"
    assert row["severity"] == "CRITICAL"
    assert queue(client, severity="CRITICAL")["total"] == 1


# ---------------------------------------------------------------------------
# Decision and assignment persistence across versions
# ---------------------------------------------------------------------------


def test_previous_not_affected_is_not_auto_applied_to_new_version__VEX_CTX_001(client, app_line, db):
    v1 = app_line.version("A1.0.0")
    c1 = app_line.component(v1, "openssl", "1.1.1")
    app_line.run(v1, [(c1, "CVE-2026-4001")])
    db.add(
        VexStatement(
            sbom_id=v1.id, component_id=c1.id, vulnerability_id="CVE-2026-4001", tenant_id=1,
            status="not_affected", normalized_status="NOT_AFFECTED", source_status="not_affected",
            justification="code_not_reachable", source_name=MANUAL_SOURCE_NAME, created_at=NOW,
        )
    )
    db.commit()
    app_line.reconcile(v1)

    v2 = app_line.version("A1.1.0", parent=v1)
    c2 = app_line.component(v2, "openssl", "1.1.1")
    app_line.run(v2, [(c2, "CVE-2026-4001")])
    app_line.reconcile(v2)

    old = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == v1.id))
    new = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == v2.id))
    assert old.effective_status == "NOT_AFFECTED"  # preserved on A1.0.0
    assert new.effective_status == "UNDER_INVESTIGATION"  # not silently inherited
    assert new.reconciliation_status == "ANALYZER_ONLY"


def test_assignment_is_not_carried_onto_new_version__VEX_AUD_001(client, app_line, db):
    v1 = app_line.version("A1.0.0")
    c1 = app_line.component(v1, "openssl", "1.1.1")
    app_line.run(v1, [(c1, "CVE-2026-4101")])
    app_line.reconcile(v1)
    db.query(VexInvestigation).filter(VexInvestigation.sbom_id == v1.id).update(
        {"assigned_to": "membership:999"}
    )
    db.commit()

    v2 = app_line.version("A1.1.0", parent=v1)
    c2 = app_line.component(v2, "openssl", "1.1.1")
    app_line.run(v2, [(c2, "CVE-2026-4101")])
    app_line.reconcile(v2)

    new = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == v2.id))
    assert new.assigned_to is None
