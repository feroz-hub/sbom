"""Tests for user search endpoints used in access management redesign."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import IAMUser, Tenant, TenantUser


def test_platform_user_search_case_insensitive(
    client: TestClient, db_session: Session, platform_admin_auth_headers: dict[str, str]
):
    user = IAMUser(
        external_iam_issuer="https://localhost:5180",
        external_iam_user_id="user-search-sub-1",
        email="ferozebasha.s@hcltech.com",
        display_name="Feroze Basha",
        user_principal_name="ferozebasha",
        status="ACTIVE",
        email_verified=True,
        verification_required=False,
    )
    db_session.add(user)
    db_session.commit()

    response = client.get(
        "/api/platform/users/search?q=feroze",
        headers=platform_admin_auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert any(item["email"] == "ferozebasha.s@hcltech.com" for item in data["items"])


def test_tenant_user_candidate_search(
    client: TestClient, db_session: Session, tenant_admin_auth_headers: dict[str, str]
):
    tenant = db_session.query(Tenant).filter(Tenant.id == 1).first()
    assert tenant is not None

    user = IAMUser(
        external_iam_issuer="https://localhost:5180",
        external_iam_user_id="user-candidate-sub-2",
        email="candidate.user@hcltech.com",
        display_name="Candidate User",
        user_principal_name="candidate",
        status="ACTIVE",
        email_verified=True,
        verification_required=False,
    )
    db_session.add(user)
    db_session.commit()

    response = client.get(
        f"/api/tenants/{tenant.id}/user-candidates?q=candidate",
        headers=tenant_admin_auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert any(item["email"] == "candidate.user@hcltech.com" for item in data["items"])
