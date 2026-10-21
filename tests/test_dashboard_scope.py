"""Dashboard hierarchy, active data and shared metric scope regressions."""

from datetime import UTC, datetime

import pytest
from app import metrics
from app.core.context import CurrentContext
from app.core.security import get_current_tenant_context
from app.db import Base, get_db
from app.main import app
from app.models import AnalysisFinding, AnalysisRun, LogicalSBOM, Product, Projects, SBOMSource, Tenant
from app.services.dashboard_scope import dashboard_scope, resolve_dashboard_scope
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from tests.tenant_fixture_scope import scoped_context_override, verified_fixture_tenant


@pytest.fixture
def scoped_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        now = datetime.now(UTC)
        db.add_all([
            Tenant(id=1, name="One", slug="one", status="ACTIVE", created_at=now, updated_at=now),
            Tenant(id=2, name="Two", slug="two", status="ACTIVE", created_at=now, updated_at=now),
        ])
        db.flush()
        with verified_fixture_tenant(db, 1):
            db.add_all([
                Projects(id=1, tenant_id=1, project_name="A", project_status=1),
                Projects(id=2, tenant_id=1, project_name="B", project_status=1),
                Product(id=1, tenant_id=1, project_id=1, name="A1", normalized_name="a1", slug="a1", created_at="2026-01-01"),
                Product(id=2, tenant_id=1, project_id=2, name="B1", normalized_name="b1", slug="b1", created_at="2026-01-01"),
                SBOMSource(id=1, tenant_id=1, projectid=1, product_id=1, sbom_name="active-a", is_active=True),
                SBOMSource(id=2, tenant_id=1, projectid=1, product_id=1, sbom_name="inactive-a", is_active=False),
                SBOMSource(id=3, tenant_id=1, projectid=2, product_id=2, sbom_name="active-b", is_active=True),
            ])
            db.flush()
        # Foreign fixture rows use their independently verified owner.
        with verified_fixture_tenant(db, 2):
            # Direct Core inserts simulate a second tenant without bypassing the
            # production ORM's cross-tenant write guard for application writes.
            db.execute(Projects.__table__.insert().values(id=3, tenant_id=2, project_name="Other tenant", project_status=1))
            db.execute(Product.__table__.insert().values(id=3, tenant_id=2, project_id=3, name="T2", normalized_name="t2", slug="t2", created_at="2026-01-01"))
            db.execute(LogicalSBOM.__table__.insert().values(id=4, tenant_id=2, product_id=3, name="Other tenant", created_at="2026-01-01", updated_at="2026-01-01"))
            db.execute(SBOMSource.__table__.insert().values(id=4, tenant_id=2, projectid=3, product_id=3, logical_sbom_id=4, sbom_name="other-tenant", is_active=True))
        for run_id, sbom_id, project_id, product_id, tenant_id in [
            (1, 1, 1, 1, 1), (2, 2, 1, 1, 1), (3, 3, 2, 2, 1), (4, 4, 3, 3, 2),
        ]:
            with verified_fixture_tenant(db, tenant_id):
                run = AnalysisRun(
                    id=run_id, tenant_id=tenant_id, sbom_id=sbom_id,
                    project_id=project_id, product_id=product_id,
                    run_status="FINDINGS", started_on="2026-01-01", completed_on="2026-01-01",
                    total_findings=1,
                )
                finding = AnalysisFinding(
                    tenant_id=tenant_id, analysis_run_id=run_id,
                    vuln_id=f"CVE-{run_id}", severity="high",
                )
                if tenant_id == 1:
                    db.add_all([run, finding])
                else:
                    db.execute(AnalysisRun.__table__.insert().values(**{
                        column: value for column, value in run.__dict__.items() if column != "_sa_instance_state"
                    }))
                    db.execute(AnalysisFinding.__table__.insert().values(**{
                        column: value for column, value in finding.__dict__.items() if column != "_sa_instance_state"
                    }))
                db.flush()
        with verified_fixture_tenant(db, 1):
            db.commit()
            yield db
    engine.dispose()


def test_scope_filters_every_metric_to_active_hierarchy(scoped_db):
    db = scoped_db
    tenant = resolve_dashboard_scope(db, tenant_id=1)
    with dashboard_scope(db, tenant):
        assert metrics.sboms_total(db) == 2
        assert metrics.findings_latest_per_sbom_total(db) == 2
        assert metrics.findings_latest_per_sbom_severity_distribution(db)["high"] == 2

    project = resolve_dashboard_scope(db, tenant_id=1, project_id=1)
    with dashboard_scope(db, project):
        assert metrics.sboms_total(db) == 1
        assert metrics.findings_latest_per_sbom_total(db) == 1
        assert metrics.projects_active_total(db) == 1

    application = resolve_dashboard_scope(db, tenant_id=1, project_id=1, product_id=1)
    with dashboard_scope(db, application):
        assert metrics.findings_latest_per_sbom_total(db) == 1

    sbom = resolve_dashboard_scope(db, tenant_id=1, project_id=1, product_id=1, sbom_id=1)
    with dashboard_scope(db, sbom):
        assert metrics.sboms_total(db) == 1
        assert metrics.findings_latest_per_sbom_total(db) == 1


def test_latest_successful_run_replaces_previous_findings(scoped_db):
    db = scoped_db
    db.add(AnalysisRun(
        id=5, tenant_id=1, sbom_id=1, project_id=1, product_id=1,
        run_status="OK", started_on="2026-02-01", completed_on="2026-02-01",
        total_findings=0,
    ))
    db.commit()
    scope = resolve_dashboard_scope(db, tenant_id=1, project_id=1, product_id=1, sbom_id=1)
    with dashboard_scope(db, scope):
        assert metrics.findings_latest_per_sbom_total(db) == 0
        assert [run["id"] for run in metrics.dashboard_runs(db, limit=10, latest_only=True)] == [5]
        assert metrics.dashboard_runs(db, limit=10, latest_only=True, run_status="FINDINGS") == []


def test_deactivated_or_deleted_parent_excludes_child_sboms(scoped_db):
    db = scoped_db
    scope = resolve_dashboard_scope(db, tenant_id=1)
    db.execute(Product.__table__.update().where(Product.id == 1).values(deleted_at="2026-02-01"))
    db.commit()
    with dashboard_scope(db, scope):
        assert metrics.sboms_total(db) == 1
        assert metrics.findings_latest_per_sbom_total(db) == 1
    with pytest.raises(HTTPException) as exc:
        resolve_dashboard_scope(db, tenant_id=1, project_id=1, product_id=1)
    assert exc.value.status_code == 404

    db.execute(Projects.__table__.update().where(Projects.id == 2).values(is_active=False))
    db.commit()
    with dashboard_scope(db, scope):
        assert metrics.sboms_total(db) == 0
        assert metrics.findings_latest_per_sbom_total(db) == 0


@pytest.mark.parametrize("ids,status", [
    ({"project_id": 3}, 404),
    ({"project_id": 1, "product_id": 2}, 404),
    ({"project_id": 1, "product_id": 1, "sbom_id": 3}, 404),
    ({"product_id": 1}, 400),
    ({"sbom_id": 1}, 400),
    ({"project_id": 1, "product_id": 1, "sbom_id": 2}, 404),
])
def test_scope_rejects_invalid_or_inactive_selection(scoped_db, ids, status):
    with pytest.raises(HTTPException) as exc:
        resolve_dashboard_scope(scoped_db, tenant_id=1, **ids)
    assert exc.value.status_code == status


def test_dashboard_option_and_metric_routes_share_scope(scoped_db):
    context = CurrentContext(
        user_id=1, external_user_id="test", email=None, display_name=None,
        tenant_id=1, external_tenant_id="one", roles=frozenset(),
        permissions=frozenset({"dashboard:read", "sbom:read"}),
    )
    previous_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = lambda: scoped_db
    app.dependency_overrides[get_current_tenant_context] = scoped_context_override(lambda: context)
    p1, p2 = [str(scoped_db.get(Projects, i).public_id) for i in (1,2)]
    with verified_fixture_tenant(scoped_db, 2):
        p3 = str(scoped_db.get(Projects, 3).public_id)
    prod = str(scoped_db.get(Product, 1).public_id)
    sbom = str(scoped_db.get(SBOMSource, 1).public_id)
    try:
        client = TestClient(app)
        projects = client.get("/dashboard/filter-options/projects")
        assert projects.status_code == 200
        assert [item["id"] for item in projects.json()["items"]] == [p1, p2]
        applications = client.get(f"/dashboard/filter-options/applications?project_id={p1}")
        assert applications.status_code == 200
        assert [item["id"] for item in applications.json()["items"]] == [prod]
        sboms = client.get(f"/dashboard/filter-options/sboms?project_id={p1}&product_id={prod}")
        assert sboms.status_code == 200
        assert [item["id"] for item in sboms.json()["items"]] == [sbom]
        assert client.get(f"/dashboard/severity?project_id={p1}&product_id={prod}&sbom_id={sbom}").json()["high"] == 1
        assert client.get("/dashboard/severity").json()["high"] == 2
        summary = client.get(f"/dashboard/summary?project_id={p1}&product_id={prod}&sbom_id={sbom}")
        assert summary.status_code == 200, summary.text
        body = summary.json()
        assert body["scope"]["level"] == "SBOM"
        assert body["posture"]["total_findings"] == 1
        assert body["posture"]["severity"]["high"] == 1
        assert len(body["risk_map"]["items"]) == 1
        scanned = client.get(f"/dashboard/scanned-project-ids?project_id={p1}&product_id={prod}&sbom_id={sbom}")
        assert scanned.status_code == 200, scanned.text
        assert len(scanned.json()["ids"]) == body["posture"]["total_applications_scanned"]
        detail = client.get(f"/api/vulnerabilities?severity=high&project_id={p1}&product_id={prod}&sbom_id={sbom}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["total"] == body["posture"]["severity"]["high"]
        sbom_list = client.get(f"/api/sboms?project_id={p1}&product_id={prod}&sbom_id={sbom}")
        assert sbom_list.status_code == 200, sbom_list.text
        assert [item["id"] for item in sbom_list.json()] == [sbom]
        analysed = client.get(f"/api/sboms?project_id={p1}&product_id={prod}&sbom_id={sbom}&analysed=true")
        assert analysed.status_code == 200, analysed.text
        assert len(analysed.json()) == body["posture"]["total_sboms_analysed"]
        latest_runs = client.get(f"/dashboard/runs?project_id={p1}&product_id={prod}&latest_only=true")
        assert latest_runs.status_code == 200, latest_runs.text
        assert [run["sbom_id"] for run in latest_runs.json()] == [sbom]
        assert "raw_report" not in latest_runs.json()[0]
        assert client.get(f"/dashboard/severity?project_id={p3}").status_code == 404
        assert client.get(f"/dashboard/severity?product_id={prod}").status_code == 400
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)
