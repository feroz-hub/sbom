#!/usr/bin/env python3
"""Dry-run-first repair of missing Phase 8 system catalogue definitions."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.authorization_catalog_seed_v1 import (
    ALL_PERMISSIONS_V1,
    PROTECTED_ROLE_PERMISSIONS_V1,
    ROLE_PERMISSIONS_V1,
    ROLE_SCOPES_V1,
)
from app.db import SessionLocal
from app.models import (
    AuthorizationPermission,
    AuthorizationRole,
    AuthorizationRolePermission,
)
from app.services.audit_service import write_authorization_audit


def _permission_parts(code: str) -> tuple[str, str]:
    parts = code.split(":")
    return ":".join(parts[:-1]), parts[-1]


def synchronize(*, apply: bool) -> list[str]:
    changes: list[str] = []
    with SessionLocal() as db:
        roles = {role.code: role for role in db.scalars(select(AuthorizationRole))}
        permissions = {
            permission.code: permission
            for permission in db.scalars(select(AuthorizationPermission))
        }
        now = datetime.now(UTC)
        for code, scope in ROLE_SCOPES_V1.items():
            if code not in roles:
                changes.append(f"add role {code}")
                if apply:
                    role = AuthorizationRole(
                        code=code,
                        name=code.replace("_", " ").title(),
                        description=f"System {scope.lower()} role {code}.",
                        scope=scope,
                        status="ACTIVE",
                        is_system=True,
                        is_assignable=True,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(role)
                    db.flush()
                    roles[code] = role
        for code in ALL_PERMISSIONS_V1:
            if code not in permissions:
                changes.append(f"add permission {code}")
                if apply:
                    resource, action = _permission_parts(code)
                    permission = AuthorizationPermission(
                        code=code,
                        name=code.replace(":", " ").replace("-", " ").title(),
                        description=f"Allows {action} access to {resource}.",
                        scope="PLATFORM" if code.startswith("platform:") else "TENANT",
                        resource=resource,
                        action=action,
                        status="ACTIVE",
                        is_system=True,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(permission)
                    db.flush()
                    permissions[code] = permission
        if apply:
            existing = {
                (mapping.role_id, mapping.permission_id)
                for mapping in db.scalars(select(AuthorizationRolePermission))
            }
            for role_code, codes in ROLE_PERMISSIONS_V1.items():
                role = roles[role_code]
                protected = set(
                    PROTECTED_ROLE_PERMISSIONS_V1.get(role_code, ())
                )
                for code in codes:
                    permission = permissions[code]
                    if (role.id, permission.id) not in existing:
                        changes.append(f"add mapping {role_code} -> {code}")
                        db.add(
                            AuthorizationRolePermission(
                                role_id=role.id,
                                permission_id=permission.id,
                                is_protected=code in protected,
                                created_at=now,
                                updated_at=now,
                            )
                        )
            write_authorization_audit(
                db,
                action="AUTHORIZATION_CATALOG_SEEDED",
                outcome="SUCCESS",
                tenant_id=None,
                new_value={"change_count": len(changes)},
                detail="Controlled catalogue synchronization",
            )
            db.commit()
        else:
            # Report missing mappings without modifying them.
            for role_code, codes in ROLE_PERMISSIONS_V1.items():
                role = roles.get(role_code)
                if role is None:
                    continue
                existing_codes = {
                    mapping.permission.code for mapping in role.permissions
                }
                changes.extend(
                    f"add mapping {role_code} -> {code}"
                    for code in codes
                    if code not in existing_codes
                )
    return changes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply additions. Without this flag the command is read-only.",
    )
    args = parser.parse_args()
    changes = synchronize(apply=args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{mode}: {len(changes)} change(s)")
    for change in changes:
        print(change)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
