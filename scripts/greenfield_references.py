"""Current authorization reference data for the explicit fresh installation."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from sqlalchemy import select


def seed_catalog(db):
    from app.core.permissions import ALL_PERMISSIONS, PROTECTED_ROLE_PERMISSIONS, ROLE_PERMISSIONS, ROLE_SCOPES
    from app.models import AuthorizationPermission, AuthorizationRole, AuthorizationRolePermission

    now = datetime.now(UTC)
    roles = {r.code: r for r in db.scalars(select(AuthorizationRole))}
    permissions = {p.code: p for p in db.scalars(select(AuthorizationPermission))}
    for code in sorted(ALL_PERMISSIONS):
        if code not in permissions:
            resource, action = code.rsplit(":", 1)
            p = AuthorizationPermission(
                code=code,
                name=code,
                scope="PLATFORM" if code.startswith("platform:") else "TENANT",
                resource=resource,
                action=action,
                status="ACTIVE",
                is_system=True,
                created_at=now,
                updated_at=now,
            )
            db.add(p)
            db.flush()
            permissions[code] = p
    for code, scope in ROLE_SCOPES.items():
        if code not in roles:
            r = AuthorizationRole(
                code=code,
                name=code,
                scope=scope,
                status="ACTIVE",
                is_system=True,
                is_assignable=True,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(r)
            db.flush()
            roles[code] = r
        r = roles[code]
        current = {
            m.permission_id: m
            for m in db.scalars(select(AuthorizationRolePermission).where(AuthorizationRolePermission.role_id == r.id))
        }
        expected = {permissions[p].id: p for p in ROLE_PERMISSIONS[code]}
        for pid, row in current.items():
            if pid not in expected:
                db.delete(row)
        for pid, permission in expected.items():
            if pid not in current:
                db.add(
                    AuthorizationRolePermission(
                        role_id=r.id,
                        permission_id=pid,
                        is_protected=permission in PROTECTED_ROLE_PERMISSIONS.get(code, ()),
                        created_at=now,
                        updated_at=now,
                    )
                )
    db.flush()


def seed():
    from scripts.dev import GreenfieldStack
    STATE = GreenfieldStack.STATE
    settings = GreenfieldStack.settings

    env = settings()
    os.environ.clear()
    os.environ.update(env)
    os.chdir(STATE)
    from app.db import SessionLocal

    with SessionLocal() as db:
        seed_catalog(db)
        db.commit()
    print("Current greenfield authorization references verified")


if __name__ == "__main__":
    seed()
