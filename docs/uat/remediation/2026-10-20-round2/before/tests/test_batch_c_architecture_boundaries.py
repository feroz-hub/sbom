"""Reproduce an architecture decision without adding platform capabilities."""

from app.core.security import _resolve_context, get_current_claims
from app.db import SessionLocal
from app.models import AccountActionToken, IAMUser, SecurityMailOutbox, TenantUser, UserIdentity
from app.routers.native_auth import router
from app.services import native_auth_service as auth
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tests.test_native_bootstrap import config as config
from tests.test_native_bootstrap import create, token_from_test_mail
from tests.test_native_iam_phase2 import PASSWORD
from tests.test_native_iam_phase2 import native_config as native_config


def test_fresh_native_platform_admin_cannot_use_generic_user_provisioning(config, monkeypatch):
    """V2 excludes global user management; a real Native token cannot override it."""
    with SessionLocal() as db:
        uid = create(db)
        db.commit()
        activation = token_from_test_mail(db, uid, monkeypatch)
        auth.activate(db, activation, PASSWORD)
        db.commit()
        token = auth.login(db, "first@native.test", PASSWORD)
        assert token
        claims = get_current_claims("Bearer " + token)
        actor = _resolve_context(db, claims, None, allow_platform_context=True)
        assert actor.user_id == uid
        assert actor.is_platform_admin
        assert "platform:user:manage_status" not in actor.permissions
        db.commit()
        models = (IAMUser, UserIdentity, TenantUser, AccountActionToken, SecurityMailOutbox)
        before = [db.scalar(select(func.count()).select_from(model)) for model in models]

    isolated_app = FastAPI()
    isolated_app.include_router(router)
    with TestClient(isolated_app) as client:
        response = client.post(
            "/api/platform/native-users",
            headers={"Authorization": "Bearer " + token},
            json={
                "first_name": "Denied",
                "last_name": "Enrollment",
                "phone": "test-phone",
                "email": "denied-enrollment@example.test",
                "tenant_id": 1,
                "role_codes": ["TENANT_ADMIN"],
            },
        )
    assert response.status_code == 403
    with SessionLocal() as db:
        assert [db.scalar(select(func.count()).select_from(model)) for model in models] == before
        assert db.scalar(select(IAMUser.id).where(IAMUser.email == "denied-enrollment@example.test")) is None
