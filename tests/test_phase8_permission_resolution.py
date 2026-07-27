from datetime import UTC, datetime

from app.db import SessionLocal
from app.models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
)
from app.services.authorization_catalog_service import resolve_permissions_for_roles
from app.settings import reset_settings
from sqlalchemy import select


def _mode(monkeypatch, value: str):
    monkeypatch.setenv("AUTHORIZATION_CATALOG_MODE", value)
    reset_settings()


def test_database_mode_uses_database_and_reflects_next_request(monkeypatch):
    _mode(monkeypatch, "DATABASE")
    with SessionLocal() as db:
        before = resolve_permissions_for_roles(db, {"VIEWER"})
        permission = db.scalar(select(AuthorizationPermission).where(AuthorizationPermission.code == "analysis:read"))
        permission.status = "DISABLED"
        db.flush()
        after = resolve_permissions_for_roles(db, {"VIEWER"})
        db.rollback()
    assert "analysis:read" in before
    assert "analysis:read" not in after


def test_database_mode_new_mapping_applies_on_next_resolution(monkeypatch):
    _mode(monkeypatch, "DATABASE")
    with SessionLocal() as db:
        role = db.scalar(
            select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER")
        )
        permission = db.scalar(
            select(AuthorizationPermission).where(
                AuthorizationPermission.code == "sbom:upload"
            )
        )
        before = resolve_permissions_for_roles(db, {"VIEWER"})
        now = datetime.now(UTC)
        db.add(
            AuthorizationRolePermission(
                role_id=role.id,
                permission_id=permission.id,
                is_protected=False,
                created_at=now,
                updated_at=now,
            )
        )
        db.flush()
        after = resolve_permissions_for_roles(db, {"VIEWER"})
        db.rollback()
    assert "sbom:upload" not in before
    assert "sbom:upload" in after


def test_legacy_and_compare_preserve_legacy_decision(monkeypatch):
    for mode in ("LEGACY", "COMPARE"):
        _mode(monkeypatch, mode)
        with SessionLocal() as db:
            assert "sbom:read" in resolve_permissions_for_roles(db, {"VIEWER"})


def test_database_mode_unknown_role_fails_closed(monkeypatch):
    _mode(monkeypatch, "DATABASE")
    with SessionLocal() as db:
        assert not resolve_permissions_for_roles(db, {"DOES_NOT_EXIST"})
