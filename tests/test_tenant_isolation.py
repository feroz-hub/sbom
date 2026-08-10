"""Cross-tenant isolation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.context import bind_context, minimal_background_context, reset_context
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    IAMUser,
    Product,
    Projects,
    SBOMSource,
    Tenant,
    TenantUser,
    VulnerabilityRemediation,
)


@pytest.fixture
def two_tenant_setup():
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        now = datetime.now(UTC)
        suffix = uuid4().hex[:8]
        t2 = Tenant(
            name="Tenant B",
            slug=f"tenant-b-{suffix}",
            external_iam_tenant_id=f"tenant-b-ext-{suffix}",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(t2)
        db.flush()

        token = bind_context(minimal_background_context(t2.id, t2.external_iam_tenant_id))
        try:
            user_b = IAMUser(
                external_iam_user_id=f"user-b-{suffix}",
                email=f"b-{suffix}@example.com",
                display_name="User B",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            db.add(user_b)
            db.flush()
            db.add(
                TenantUser(
                    tenant_id=t2.id,
                    user_id=user_b.id,
                    role="VIEWER",
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            )

            project_b = Projects(project_name="Project B", tenant_id=t2.id, created_on=now.isoformat())
            db.add(project_b)
            db.flush()
            product_b = Product(
                project_id=project_b.id,
                name="Product B",
                normalized_name="product b",
                slug="product-b",
                status="active",
                created_at=now.isoformat(),
                tenant_id=t2.id,
            )
            db.add(product_b)
            db.flush()
            sbom_b = SBOMSource(
                sbom_name="sbom-b",
                sbom_version="1.0",
                projectid=project_b.id,
                product_id=product_b.id,
                tenant_id=t2.id,
                created_on=now.isoformat(),
                status="validated",
            )
            db.add(sbom_b)
            db.flush()
            run_b = AnalysisRun(
                sbom_id=sbom_b.id,
                project_id=project_b.id,
                product_id=product_b.id,
                run_status="FINDINGS",
                source="NVD",
                started_on=now.isoformat(),
                completed_on=now.isoformat(),
                tenant_id=t2.id,
            )
            db.add(run_b)
            db.flush()
            finding_b = AnalysisFinding(
                analysis_run_id=run_b.id,
                vuln_id="CVE-2026-9999",
                component_name="tenant-b-component",
                component_version="1.0",
                severity="HIGH",
                tenant_id=t2.id,
            )
            remediation_b = VulnerabilityRemediation(
                project_id=project_b.id,
                vuln_id="CVE-2026-9999",
                component_name="tenant-b-component",
                component_version="1.0",
                status="Open",
                created_on=now.isoformat(),
                updated_on=now.isoformat(),
                tenant_id=t2.id,
            )
            db.add_all([finding_b, remediation_b])
            db.commit()
            yield {
                "tenant_b_id": t2.id,
                "project_b_id": project_b.id,
                "product_b_id": product_b.id,
                "sbom_b_id": sbom_b.id,
                "run_b_id": run_b.id,
                "finding_b_id": finding_b.id,
                "remediation_b_id": remediation_b.id,
            }
        finally:
            reset_context(token)
    finally:
        db.close()


def test_tenant_a_cannot_access_tenant_b_sbom(client, two_tenant_setup):
    sbom_id = two_tenant_setup["sbom_b_id"]
    resp = client.get(f"/api/sboms/{sbom_id}")
    if resp.status_code == 200:
        # Same numeric id may exist in tenant A — must not return tenant B's row.
        assert resp.json().get("sbom_name") != "sbom-b"
    else:
        assert resp.status_code == 404


def test_tenant_a_cannot_access_tenant_b_project(client, two_tenant_setup):
    project_id = two_tenant_setup["project_b_id"]
    resp = client.get(f"/api/projects/{project_id}")
    if resp.status_code == 200:
        assert resp.json().get("project_name") != "Project B"
    else:
        assert resp.status_code == 404


def test_tenant_a_cannot_update_or_delete_tenant_b_project(client, two_tenant_setup):
    project_id = two_tenant_setup["project_b_id"]
    assert client.patch(
        f"/api/projects/{project_id}",
        json={"project_name": "Cross-tenant overwrite"},
    ).status_code == 404
    assert client.delete(f"/api/projects/{project_id}?confirm=yes").status_code == 404


def test_tenant_a_cannot_update_or_delete_tenant_b_sbom(client, two_tenant_setup):
    sbom_id = two_tenant_setup["sbom_b_id"]
    assert client.patch(
        f"/api/sboms/{sbom_id}",
        json={"name": "cross-tenant-overwrite"},
    ).status_code == 404
    assert client.delete(f"/api/sboms/{sbom_id}?confirm=yes").status_code == 404


def test_tenant_header_cannot_select_an_unrelated_tenant(client, two_tenant_setup):
    response = client.get(
        f"/api/projects/{two_tenant_setup['project_b_id']}",
        headers={"X-Tenant-ID": str(two_tenant_setup["tenant_b_id"])},
    )
    assert response.status_code == 403


def test_tenant_a_cannot_read_update_or_delete_tenant_b_product(client, two_tenant_setup):
    product_id = two_tenant_setup["product_b_id"]
    assert client.get(f"/api/products/{product_id}").status_code == 404
    assert client.patch(f"/api/products/{product_id}", json={"name": "Hijacked"}).status_code == 404
    assert client.delete(f"/api/products/{product_id}").status_code == 404


def test_tenant_a_cannot_read_tenant_b_run_or_findings(client, two_tenant_setup):
    run_id = two_tenant_setup["run_b_id"]
    assert client.get(f"/api/runs/{run_id}").status_code == 404
    assert client.get(f"/api/runs/{run_id}/findings").status_code == 404


def test_tenant_a_cannot_read_tenant_b_vex_or_remediation(client, two_tenant_setup):
    sbom_id = two_tenant_setup["sbom_b_id"]
    finding_id = two_tenant_setup["finding_b_id"]
    remediation_id = two_tenant_setup["remediation_b_id"]
    assert client.get(f"/api/sboms/{sbom_id}/vex").status_code == 404
    assert client.get(f"/api/sboms/{sbom_id}/vex/report").status_code == 404
    assert client.get(f"/api/remediation/finding/{finding_id}").status_code == 404
    assert client.get(f"/api/remediation/{remediation_id}/history").status_code == 404
