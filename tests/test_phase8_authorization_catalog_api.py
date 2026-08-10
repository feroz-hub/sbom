from app.db import SessionLocal
from app.models import AuthorizationAuditLog
from sqlalchemy import select

from tests.phase6_helpers import seed_dev_platform_admin


def test_platform_catalog_read_apis_are_available(client):

    with SessionLocal() as db:
        seed_dev_platform_admin(db)
    roles = client.get("/api/platform/authorization/roles")
    permissions = client.get("/api/platform/authorization/permissions")
    matrix = client.get("/api/platform/authorization/matrix")
    assert roles.status_code == 200, roles.text
    assert permissions.status_code == 200, permissions.text
    assert matrix.status_code == 200, matrix.text
    assert roles.json()["total"] == 5
    assert permissions.json()["total"] >= 55
    assert len(matrix.json()["roles"]) == 5
    with SessionLocal() as db:
        audits = db.scalars(
            select(AuthorizationAuditLog).where(
                AuthorizationAuditLog.action.in_(
                    (
                        "AUTHORIZATION_CATALOG_VIEWED",
                        "AUTHORIZATION_PERMISSION_VIEWED",
                        "AUTHORIZATION_MATRIX_VIEWED",
                    )
                )
            )
        ).all()
        assert audits
        assert all(audit.tenant_id is None for audit in audits)


def test_system_role_cannot_be_disabled(client):
    with SessionLocal() as db:
        seed_dev_platform_admin(db)
    roles = client.get("/api/platform/authorization/roles").json()["items"]
    viewer = next(role for role in roles if role["code"] == "VIEWER")
    response = client.patch(
        f"/api/platform/authorization/roles/{viewer['id']}",
        json={"expected_version": viewer["version"], "status": "DISABLED"},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "IAM_ROLE_SYSTEM_IMMUTABLE"
