#!/usr/bin/env python3
"""Idempotently map an existing HCL.CS subject to an SBOM tenant membership.

This intentionally does not create an HCL.CS identity or accept a password.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.permissions import MEMBERSHIP_STATUSES, TENANT_ROLES, normalize_role
from app.db import SessionLocal
from app.models import IAMUser, Tenant, TenantUser
from sqlalchemy import select


def _masked(value: str) -> str:
    if len(value) <= 8:
        return f"{value[:2]}***"
    return f"{value[:4]}…{value[-4:]}"


def _available_slug(db, requested: str, external_tenant: str) -> str:
    slug = requested
    suffix = 2
    while True:
        existing = db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none()
        if existing is None or existing.external_iam_tenant_id == external_tenant:
            return slug
        slug = f"{requested}-{suffix}"
        suffix += 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True, help="Validated HCL.CS sub value")
    parser.add_argument("--external-tenant", required=True, help="HCL.CS tenant_id value")
    parser.add_argument("--tenant-name", default="HCL.CS Local Test Tenant")
    parser.add_argument("--tenant-slug", default="hcl-cs-local")
    parser.add_argument("--email")
    parser.add_argument("--display-name")
    parser.add_argument("--role", default="VIEWER")
    parser.add_argument("--status", default="ACTIVE")
    args = parser.parse_args()
    role = normalize_role(args.role)
    status = args.status.strip().upper()
    if role not in TENANT_ROLES:
        raise SystemExit("Seed role must be a non-platform SBOM application role")
    if status not in MEMBERSHIP_STATUSES:
        raise SystemExit("Seed status must be ACTIVE, PENDING, or DISABLED")
    now = datetime.now(UTC)
    with SessionLocal() as db:
        tenant = db.execute(select(Tenant).where(Tenant.external_iam_tenant_id == args.external_tenant)).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(name=args.tenant_name, slug=_available_slug(db, args.tenant_slug, args.external_tenant),
                            external_iam_tenant_id=args.external_tenant, status="ACTIVE",
                            created_at=now, updated_at=now)
            db.add(tenant)
            db.flush()
        user = db.execute(select(IAMUser).where(IAMUser.external_iam_user_id == args.subject)).scalar_one_or_none()
        if user is None:
            user = IAMUser(external_iam_user_id=args.subject, email=args.email,
                           display_name=args.display_name, status="ACTIVE",
                           created_at=now, updated_at=now)
            db.add(user)
            db.flush()
        else:
            if args.email is not None:
                user.email = args.email
            if args.display_name is not None:
                user.display_name = args.display_name
            user.updated_at = now
        membership = db.execute(select(TenantUser).where(
            TenantUser.tenant_id == tenant.id, TenantUser.user_id == user.id,
        )).scalar_one_or_none()
        if membership is None:
            membership = TenantUser(tenant_id=tenant.id, user_id=user.id, role=role,
                                    status=status, created_at=now, updated_at=now)
            db.add(membership)
        else:
            membership.role = role
            membership.status = status
            membership.updated_at = now
        db.commit()
        print(f"Mapped subject {_masked(args.subject)} to tenant {tenant.id} as {role} ({status})")


if __name__ == "__main__":
    main()
