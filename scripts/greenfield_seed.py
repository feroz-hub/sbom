"""Synthetic local identities, never an imported customer or production record."""

from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime

from scripts.dev import GreenfieldStack

STATE = GreenfieldStack.STATE

private_file = GreenfieldStack.private_file

settings = GreenfieldStack.settings


def seed():
    os.environ.update(settings())

    os.chdir(STATE)
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import IAMUser, NativeUserCredential, SBOMType, Tenant, TenantUser, UserIdentity
    from app.services.password_service import hash_password
    from app.services.tenant_role_assignment_service import create_initial_assignment
    from sqlalchemy import select

    now = datetime.now(UTC)
    if (STATE / "users.json").exists():
        seed_platform()
        return
    users = {}
    with SessionLocal() as db:
        tenants = []
        for name in ("Olympus", "Isolation Control"):
            tenant = Tenant(
                name=name, slug=name.lower().replace(" ", "-"), status="ACTIVE", created_at=now, updated_at=now
            )
            db.add(tenant)
            db.flush()
            tenants.append(tenant)
        for label, role, tenant in [
            ("admin", "TENANT_ADMIN", tenants[0]),
            ("analyst", "SECURITY_ANALYST", tenants[0]),
            ("developer", "DEVELOPER", tenants[0]),
            ("viewer", "VIEWER", tenants[0]),
            ("foreign", "TENANT_ADMIN", tenants[1]),
        ]:
            email = f"{label}@olympus.example.test"
            password = secrets.token_urlsafe(24) + "!Aa9"
            user = IAMUser(
                email=email,
                display_name=f"Synthetic Olympus {label}",
                status="ACTIVE",
                email_verified=True,
                email_verified_at=now,
                verification_required=False,
                created_at=now,
                updated_at=now,
            )
            db.add(user)
            db.flush()
            db.add(
                UserIdentity(
                    user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now
                )
            )
            db.add(
                NativeUserCredential(
                    user_id=user.id,
                    password_hash=hash_password(password),
                    password_changed_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            with tenant_scope(minimal_background_context(tenant.id)):
                member = TenantUser(
                    tenant_id=tenant.id, user_id=user.id, role=role, status="ACTIVE", created_at=now, updated_at=now
                )
                db.add(member)
                db.flush()
                create_initial_assignment(db, member, role_code=role, actor_user_id=user.id, source="PLATFORM_ADMIN")
            users[label] = {
                "email": email,
                "password": password,
                "tenant_id": str(tenant.public_id),
                "user_id": user.id,
            }
        for name in ("CycloneDX", "SPDX"):
            if not db.scalar(select(SBOMType).where(SBOMType.typename == name)):
                db.add(SBOMType(typename=name))
        first_tenant_id = tenants[0].id
        db.commit()
    with tenant_scope(minimal_background_context(first_tenant_id)):
        from app.models import Product, Projects

        with SessionLocal() as db:
            project = Projects(
                tenant_id=first_tenant_id, project_name="Olympus Release", project_status=1, created_on=now.isoformat()
            )
            db.add(project)
            db.flush()
            db.add(
                Product(
                    tenant_id=first_tenant_id,
                    project_id=project.id,
                    name="Olympus Gateway",
                    normalized_name="olympus gateway",
                    slug="olympus-gateway",
                    created_at=now.isoformat(),
                )
            )
            db.commit()
    private_file("users.json", json.dumps(users, indent=2))
    seed_platform()
    print("Synthetic Olympus identities created; credentials remain in private users.json")


def seed_platform():
    # Synthetic development authority only. Existing passwords never appear in output.
    from app.db import SessionLocal
    from app.models import IAMUser, NativeUserCredential, PlatformUserRole, UserIdentity
    from app.services.password_service import hash_password

    path = STATE / "users.json"
    users = json.loads(path.read_text())
    if "platform" in users:
        return
    now = datetime.now(UTC)
    email = "platform@olympus.example.test"
    password = secrets.token_urlsafe(24) + "!Aa9"
    with SessionLocal() as db:
        user = IAMUser(
            email=email,
            display_name="Synthetic Greenfield Platform Administrator",
            status="ACTIVE",
            email_verified=True,
            email_verified_at=now,
            verification_required=False,
            created_at=now,
            updated_at=now,
        )
        db.add(user)
        db.flush()
        db.add(
            UserIdentity(
                user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now
            )
        )
        db.add(
            NativeUserCredential(
                user_id=user.id,
                password_hash=hash_password(password),
                password_changed_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            PlatformUserRole(user_id=user.id, role="PLATFORM_ADMIN", status="ACTIVE", created_at=now, updated_at=now)
        )
        db.commit()
        users["platform"] = {"email": email, "password": password, "tenant_id": None, "user_id": user.id}
    path.write_text(json.dumps(users, indent=2))
    path.chmod(0o600)


if __name__ == "__main__":
    seed()
