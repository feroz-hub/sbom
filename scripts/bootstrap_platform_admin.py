#!/usr/bin/env python3
"""Audited, one-time bootstrap for the first authenticated platform admin."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SessionLocal
from app.models import IAMUser, PlatformUserRole
from app.services import audit_service, platform_service
from app.settings import get_settings
from sqlalchemy import func, select


def _mask(subject: str) -> str:
    return f"{subject[:4]}…{subject[-4:]}" if len(subject) > 8 else f"{subject[:2]}***"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap the first database-authorized platform administrator."
    )
    parser.add_argument("--subject", required=True, help="Exact existing HCL.CS sub")
    parser.add_argument("--change-reference", required=True, help="Approved ticket/change reference")
    parser.add_argument("--confirm", required=True, help="Must equal BOOTSTRAP_PLATFORM_ADMIN")
    args = parser.parse_args()

    if args.confirm != "BOOTSTRAP_PLATFORM_ADMIN":
        raise SystemExit("Explicit --confirm BOOTSTRAP_PLATFORM_ADMIN is required")
    if not get_settings().auth_enabled:
        raise SystemExit("Use grant_local_platform_admin.py when AUTH_ENABLED=false")
    if len(args.change_reference.strip()) < 4:
        raise SystemExit("A valid approved change reference is required")

    with SessionLocal() as db:
        active_count = db.execute(
            select(func.count(PlatformUserRole.id))
            .join(IAMUser, IAMUser.id == PlatformUserRole.user_id)
            .where(PlatformUserRole.status == "ACTIVE", IAMUser.status == "ACTIVE")
        ).scalar_one()
        if active_count:
            raise SystemExit("An active platform administrator already exists; use the authenticated API")

        grant, user, old = platform_service.grant_platform_administrator(
            db,
            external_iam_user_id=args.subject,
            created_by_user_id=None,
        )
        audit_service.write_authorization_audit(
            db,
            action="platform_admin.bootstrap_granted",
            outcome="SUCCESS",
            target_user_id=user.id,
            correlation_id=args.change_reference.strip(),
            old_value=old,
            new_value={"role": grant.role, "status": grant.status},
            detail="Approved database-operator bootstrap of the first platform administrator",
        )
        db.commit()
        print(f"Bootstrapped platform administration for {_mask(args.subject)}")


if __name__ == "__main__":
    main()
