"""Paged history contract on isolated fixtures; never uses live analysis data."""
from __future__ import annotations

import pytest
from tests.tenant_fixture_scope import verified_fixture_tenant, declare_fixture_tenant


@pytest.fixture()
def history(client):
    from app.db import SessionLocal
    from app.models import AnalysisRun, Product, Projects, SBOMSource
    with SessionLocal() as db:
        with verified_fixture_tenant(db, 1):
            project = Projects(project_name="History project", project_status=1)
            db.add(project)
            db.flush()
            product = Product(name="History application", normalized_name="history application", slug="history-application", project_id=project.id,
                              created_at="2026-10-22T10:00:00Z")
            db.add(product)
            db.flush()
            sbom = SBOMSource(sbom_name="History SBOM", sbom_version="2.4", sbom_data='{}',
                              status="validated", error_count=0, projectid=project.id, product_id=product.id)
            db.add(sbom)
            db.flush()
            rows = []
            for i in range(107):
                run = AnalysisRun(sbom_id=sbom.id, project_id=project.id, product_id=product.id,
                                  run_status="PASS" if i == 0 else "FINDINGS", source="OSV",
                                  started_on="2026-10-22T10:00:00Z", completed_on="2026-10-22T10:00:00Z",
                                  total_findings=i, high_count=i, raw_report='{"large":"report"}')
                db.add(run)
                rows.append(run)
            db.commit()
            selectors = {"sbom_id": str(sbom.public_id), "project_id": str(project.public_id),
                         "product_id": str(product.public_id)}
            ids = [str(row.public_id) for row in rows]
        yield db, selectors, ids


def test_pages_search_sort_metadata_and_summary_contract(client, history):
    _, scope, ids = history
    params = {**scope, "page_size": 25, "summary_only": "true"}
    first = client.get("/api/runs", params=params, headers={"Origin": "http://testserver"})
    assert first.status_code == 200, first.text
    assert first.headers["X-Total-Count"] == "107"
    assert "x-total-count" in first.headers["Access-Control-Expose-Headers"].lower()
    assert len(first.json()) == 25
    assert first.json()[0]["id"] == ids[-1]
    row = first.json()[0]
    assert (row["project_name"], row["product_name"], row["sbom_version"]) == ("History project", "History application", "2.4")
    assert row["total_findings"] == row["high_count"] == 106
    assert row["raw_report"] is None
    fifth = client.get("/api/runs", params={**params, "page": 5})
    assert len(fifth.json()) == 7
    assert not {row["id"] for row in first.json()} & {row["id"] for row in fifth.json()}
    assert fifth.json()[-1]["id"] == ids[0]
    found = client.get("/api/runs", params={**params, "q": ids[0]})
    assert found.headers["X-Total-Count"] == "1"
    assert found.json()[0]["id"] == ids[0]
    ordered = client.get("/api/runs", params={**params, "sort_by": "total_findings", "sort_direction": "asc"})
    assert [row["total_findings"] for row in ordered.json()] == list(range(25))
    legacy = client.get("/api/runs", params={**params, "run_status": "OK"})
    assert [row["id"] for row in legacy.json()] == [ids[0]]
    empty = client.get("/api/runs", params={**params, "q": "no matching history"})
    assert empty.json() == [] and empty.headers["X-Total-Count"] == "0"
    source = client.get("/api/runs", params={**params, "source": "NVD"})
    assert source.json() == []
    full = client.get("/api/runs", params={**scope, "page_size": 1})
    assert full.json()[0]["raw_report"] == '{"large":"report"}'
    assert client.get("/api/runs", params={"sort_by": "raw_report"}).status_code == 422
    # Searching a literal SQL wildcard must not select the whole portfolio.
    assert client.get("/api/runs", params={**params, "q": "%"}).json() == []
    assert client.get("/api/runs", params={**params, "q": "9" * 200}).json() == []


def test_compare_and_picker_expose_existing_sbom_version(client, history):
    _, _, ids = history
    response = client.post("/api/v1/compare", json={"run_a_id": ids[-2], "run_b_id": ids[-1]})
    assert response.status_code == 200, response.text
    assert response.json()["run_a"]["sbom_version"] == "2.4"
    assert response.json()["run_b"]["sbom_version"] == "2.4"
    recent = client.get("/api/runs/recent").json()
    assert recent[0]["sbom_version"] == "2.4"


def test_history_search_count_and_metadata_remain_tenant_scoped(client, history):
    from app.models import AnalysisRun, SBOMSource
    db, _, _ = history
    declare_fixture_tenant(db, 9876)
    db.commit()
    with verified_fixture_tenant(db, 9876):
        other = SBOMSource(sbom_name="Foreign history secret", sbom_data='{}', status="validated")
        db.add(other)
        db.flush()
        row = AnalysisRun(sbom_id=other.id, run_status="OK", source="OSV",
                          started_on="2026-10-22T10:00:00Z", completed_on="2026-10-22T10:00:00Z")
        db.add(row)
        db.commit()
        foreign_id = str(row.public_id)
    for needle in ("Foreign history secret", foreign_id):
        response = client.get("/api/runs", params={"q": needle, "summary_only": "true"})
        assert response.status_code == 200
        assert response.json() == []
        assert response.headers["X-Total-Count"] == "0"
