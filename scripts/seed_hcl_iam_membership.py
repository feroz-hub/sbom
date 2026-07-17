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

from sqlalchemy import select

from app.db import SessionLocal
from app.models import IAMUser, Tenant, TenantUser
from app.core.permissions import ROLE_PERMISSIONS, normalize_role


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True, help="Validated HCL.CS sub value")
    parser.add_argument("--external-tenant", required=True, help="HCL.CS tenant_id value")
    parser.add_argument("--tenant-name", default="HCL.CS Local Test Tenant")
    parser.add_argument("--tenant-slug", default="hcl-cs-local")
    parser.add_argument("--email")
    parser.add_argument("--display-name")
    parser.add_argument("--role", default="VIEWER")
    args = parser.parse_args()
    role = normalize_role(args.role)
    if role not in ROLE_PERMISSIONS or role == "PLATFORM_ADMIN":
        raise SystemExit("Seed role must be a non-platform SBOM application role")
    now = datetime.now(UTC)
    with SessionLocal() as db:
        tenant = db.execute(select(Tenant).where(Tenant.external_iam_tenant_id == args.external_tenant)).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(name=args.tenant_name, slug=args.tenant_slug,
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
        membership = db.execute(select(TenantUser).where(
            TenantUser.tenant_id == tenant.id, TenantUser.user_id == user.id,
        )).scalar_one_or_none()
        if membership is None:
            membership = TenantUser(tenant_id=tenant.id, user_id=user.id, role=role,
                                    status="ACTIVE", created_at=now, updated_at=now)
            db.add(membership)
        else:
            membership.role = role
            membership.status = "ACTIVE"
            membership.updated_at = now
        db.commit()
        print(f"Mapped subject {args.subject} to tenant {tenant.id} as {role}")


if __name__ == "__main__":
    main()
