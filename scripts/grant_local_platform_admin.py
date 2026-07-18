#!/usr/bin/env python3
"""Explicit development-only bootstrap for the first local platform grant."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SessionLocal
from app.services import audit_service, platform_service
from app.settings import get_settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True, help="Exact existing HCL.CS sub")
    parser.add_argument("--confirm", required=True, help="Must equal GRANT_LOCAL_PLATFORM_ADMIN")
    args = parser.parse_args()
    if args.confirm != "GRANT_LOCAL_PLATFORM_ADMIN":
        raise SystemExit("Explicit --confirm GRANT_LOCAL_PLATFORM_ADMIN is required")
    if get_settings().auth_enabled or os.getenv("APP_ENV", "development").lower() in {"prod", "production", "staging"}:
        raise SystemExit("Local platform bootstrap is disabled in authenticated or production-like environments")
    with SessionLocal() as db:
        grant, user, old = platform_service.grant_platform_administrator(
            db,
            external_iam_user_id=args.subject,
            created_by_user_id=None,
        )
        audit_service.write_authorization_audit(
            db,
            action="platform_admin.local_bootstrap",
            target_user_id=user.id,
            old_value=old,
            new_value={"role": grant.role, "status": grant.status},
            detail="Explicit development-only platform administrator bootstrap",
        )
        db.commit()
        masked = f"{args.subject[:4]}…{args.subject[-4:]}" if len(args.subject) > 8 else f"{args.subject[:2]}***"
        print(f"Granted local platform administration to {masked}")


if __name__ == "__main__":
    main()
