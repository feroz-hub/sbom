"""Cross-tenant isolation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.context import bind_context, minimal_background_context, reset_context
from app.models import IAMUser, Projects, SBOMSource, Tenant, TenantUser


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
                external_iam_user_id="user-b",
                email="b@example.com",
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
            sbom_b = SBOMSource(
                sbom_name="sbom-b",
                sbom_version="1.0",
                tenant_id=t2.id,
                created_on=now.isoformat(),
                status="validated",
            )
            db.add(sbom_b)
            db.commit()
            yield {"tenant_b_id": t2.id, "project_b_id": project_b.id, "sbom_b_id": sbom_b.id}
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
