"""Overview rows share canonical current posture, with bounded stable ordering."""

from dataclasses import replace

import pytest
from app.core.context import CurrentContext
from app.core.security import get_current_tenant_context
from app.db import get_db
from app.main import app
from app.metrics.findings import dashboard_priority_findings, findings_latest_per_sbom_total
from app.models import AnalysisFinding, AnalysisRun
from app.services.dashboard_scope import DashboardScope, dashboard_scope
from fastapi.testclient import TestClient

pytest_plugins = ["tests.test_dashboard_scope"]


def test_priority_order_limit_and_current_run(scoped_db):
    db = scoped_db
    db.add_all([
        AnalysisFinding(tenant_id=1, analysis_run_id=1, vuln_id="CRITICAL-low", severity="CRITICAL", score=8),
        AnalysisFinding(tenant_id=1, analysis_run_id=1, vuln_id="CRITICAL-high", severity="critical", score=9),
        AnalysisFinding(tenant_id=1, analysis_run_id=1, vuln_id="UNKNOWN", severity=None, score=10),
    ])
    db.commit()
    with dashboard_scope(db, DashboardScope(1)):
        rows = dashboard_priority_findings(db, limit=2)
        assert [r["vuln_id"] for r in rows] == ["CRITICAL-high", "CRITICAL-low"]
        assert dashboard_priority_findings(db, limit=2) == rows
        assert len(dashboard_priority_findings(db, limit=20)) == findings_latest_per_sbom_total(db) == 5
    db.add(AnalysisRun(id=5, tenant_id=1, sbom_id=1, project_id=1, product_id=1, run_status="OK", started_on="2026-02-01", completed_on="2026-02-01"))
    db.commit()
    with dashboard_scope(db, DashboardScope(1)):
        assert [r["vuln_id"] for r in dashboard_priority_findings(db)] == ["CVE-3"]


@pytest.mark.parametrize("scope,expected", [
    (DashboardScope(1), ["CVE-1", "CVE-3"]),
    (DashboardScope(1, 1), ["CVE-1"]),
    (DashboardScope(1, 1, 1), ["CVE-1"]),
    (DashboardScope(1, 1, 1, 1), ["CVE-1"]),
    (DashboardScope(2), ["CVE-4"]),
])
def test_priority_scope_matches_metrics(scoped_db, scope, expected):
    with dashboard_scope(scoped_db, scope):
        assert [r["vuln_id"] for r in dashboard_priority_findings(scoped_db)] == expected
        assert len(expected) == findings_latest_per_sbom_total(scoped_db)


def test_priority_endpoint_permission_ownership_and_bound(scoped_db):
    context = CurrentContext(user_id=1, external_user_id="test", email=None, display_name=None,
                             tenant_id=1, external_tenant_id="one", roles=frozenset(),
                             permissions=frozenset({"dashboard:read", "analysis:read"}))
    app.dependency_overrides[get_db] = lambda: scoped_db
    app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        client = TestClient(app)
        response = client.get("/dashboard/priority-findings?limit=1")
        assert response.status_code == 200
        assert len(response.json()["items"]) == 1
        assert client.get("/dashboard/priority-findings?limit=21").status_code == 422
        assert client.get("/dashboard/priority-findings?project_id=3").status_code == 404
        app.dependency_overrides[get_current_tenant_context] = lambda: replace(context, permissions=frozenset({"dashboard:read"}))
        assert client.get("/dashboard/priority-findings").status_code == 403
        app.dependency_overrides[get_current_tenant_context] = lambda: replace(context, permissions=frozenset())
        assert client.get("/dashboard/priority-findings").status_code == 403
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_tenant_context, None)


def test_priority_page_does_not_query_per_row(scoped_db):
    from sqlalchemy import event

    statements = []

    def record(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(scoped_db.bind, "before_cursor_execute", record)
    try:
        with dashboard_scope(scoped_db, DashboardScope(1)):
            assert len(dashboard_priority_findings(scoped_db, limit=20)) == 2
        assert len(statements) == 1
    finally:
        event.remove(scoped_db.bind, "before_cursor_execute", record)
