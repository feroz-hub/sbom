#!/usr/bin/env python3
"""Read-only SF migration inventory. Never links identities or copies credentials.

Use explicitly supplied DATABASE_URL and --output on an approved environment.
Output is access-restricted JSON: IDs and role mappings, no email/token material.
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def inventory(db):
    from app.models import IAMUser, PlatformUserRole, TenantUser, UserIdentity
    from app.services.user_management_service import membership_summary
    from sqlalchemy import select

    # Keep identity references, not subject/email values, in the exported report.
    identities = defaultdict(list)
    for identity in db.scalars(select(UserIdentity)):
        identities[identity.user_id].append(identity)
    memberships = defaultdict(list)
    from app.models import Tenant

    for member, tenant in db.execute(select(TenantUser, Tenant).join(Tenant, Tenant.id == TenantUser.tenant_id)):
        memberships[member.user_id].append(membership_summary(db, member, tenant))
    grants = {g.user_id: g.status for g in db.scalars(select(PlatformUserRole))}
    users = list(db.scalars(select(IAMUser).order_by(IAMUser.id)))
    email_groups = defaultdict(list)
    for user in users:
        if user.email:
            email_groups[user.email.strip().lower()].append(user.id)
    collisions = {uid for ids in email_groups.values() if len(ids) > 1 for uid in ids}
    items = []
    for user in users:
        records = identities[user.id]
        providers = {i.provider_type for i in records}
        legacy = bool(user.external_iam_user_id or user.external_subject or user.external_issuer)
        category = (
            "DUAL_PROVIDER"
            if providers == {"NATIVE", "HCL_CS"}
            else "NATIVE_ONLY"
            if providers == {"NATIVE"}
            else "HCL_ONLY"
            if "HCL_CS" in providers
            else "LEGACY_EXTERNAL"
            if legacy
            else "NO_IDENTITY"
        )
        incomplete = legacy and not any(i.provider_type == "HCL_CS" for i in records)
        items.append(
            dict(
                user_id=user.id,
                category=category,
                account_status=user.status,
                inactive=user.status != "ACTIVE",
                collision_review=user.id in collisions,
                incomplete_external_identity=incomplete,
                identity_records=[{"identity_id": i.id, "provider": i.provider_type} for i in records],
                platform_grant_status=grants.get(user.id),
                memberships=memberships[user.id],
                target="MANUAL_REVIEW" if incomplete or user.id in collisions else "PRESERVE_EXISTING_COHABITATION",
                native_onboarding="EXPLICIT_APPROVAL_REQUIRED" if "NATIVE" not in providers else "ALREADY_NATIVE",
            )
        )
    return {
        "categories": dict(Counter(i["category"] for i in items)),
        "users": items,
        "rules": [
            "Never merge by email",
            "Preserve IAMUser IDs and tenant-specific database roles",
            "No SF credential/password transfer",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL"):
        parser.error("Explicit DATABASE_URL is required")
    from app.db import SessionLocal

    with SessionLocal() as db:
        db.connection(execution_options={"postgresql_readonly": True})
        result = inventory(db)
        db.rollback()
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(result, output, indent=2, default=str)
    print("Inventory written; no identities or permissions modified.")


if __name__ == "__main__":
    main()
