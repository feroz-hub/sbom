"""Regression coverage for contextvars crossing FastAPI's sync-route worker."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest


def test_sync_project_create_receives_async_tenant_context(app, client):
    from app.core.context import minimal_background_context
    from app.core.security import get_current_tenant_context
    from app.db import SessionLocal
    from app.models import IAMUser, Projects

    # The test bootstrap creates tenant 1 and grants the local authenticated
    # test identity access to it, so request authorization remains realistic.
    tenant_id = 1
    external_id = "local-default"
    db = SessionLocal()
    try:
        actor_id = db.query(IAMUser.id).order_by(IAMUser.id).limit(1).scalar() or 0
    finally:
        db.close()

    async def _async_context_override():
        # An async generator is essential: its bind/reset lifecycle remains in
        # the request task while the synchronous route executes in a worker.
        from app.core.context import bind_context, reset_context

        context = replace(
            minimal_background_context(tenant_id, external_id),
            user_id=actor_id,
            permissions=frozenset({"project:create"}),
        )
        token = bind_context(context)
        try:
            yield context
        finally:
            reset_context(token)

    app.dependency_overrides[get_current_tenant_context] = _async_context_override
    name = f"Context propagation {uuid4().hex[:8]}"
    try:
        response = client.post("/api/projects", json={"project_name": name, "project_status": 1})
        assert response.status_code == 201, response.text
        db = SessionLocal()
        try:
            project = db.query(Projects).filter(Projects.project_name == name).one()
            assert project.tenant_id == tenant_id
        finally:
            db.close()
    finally:
        app.dependency_overrides.pop(get_current_tenant_context, None)


def test_missing_tenant_context_still_blocks_tenant_owned_write(monkeypatch):
    from app import settings
    from app.db import SessionLocal
    from app.models import Projects

    monkeypatch.setattr(settings, "_settings_instance", SimpleNamespace(auth_enabled=True))
    db = SessionLocal()
    try:
        db.add(Projects(project_name=f"Blocked {uuid4().hex}", project_status=1))
        with pytest.raises(RuntimeError, match="Tenant context is required for tenant-owned writes"):
            db.flush()
        db.rollback()
    finally:
        db.close()
