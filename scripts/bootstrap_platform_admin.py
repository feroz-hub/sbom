#!/usr/bin/env python3
"""Explicit, audited emergency bootstrap for the first platform administrator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.identity_states import IdentityAuditEvent
from app.db import SessionLocal
from app.services import audit_service, platform_service
from app.settings import get_settings

CONFIRMATION = "BOOTSTRAP_PLATFORM_ADMIN"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap the first database-authorized Platform Administrator."
    )
    parser.add_argument("--user-id", type=int, help="Exact existing local IAM user ID")
    parser.add_argument("--issuer", help="Exact trusted external issuer; use with --subject")
    parser.add_argument(
        "--subject",
        help=(
            "Exact external subject. With --issuer this selects the composite "
            "identity; alone it retains the legacy exact-subject selector."
        ),
    )
    parser.add_argument("--employee-id", help="Exact, uniquely resolved employee ID")
    parser.add_argument("--email", help="Exact, uniquely resolved email address")
    parser.add_argument(
        "--change-reference",
        required=True,
        help="Approved ticket/change reference",
    )
    parser.add_argument(
        "--confirm",
        required=True,
        help=f"Must equal {CONFIRMATION}",
    )
    return parser


def execute_bootstrap(db, args: argparse.Namespace) -> tuple[str, int]:
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"Explicit --confirm {CONFIRMATION} is required")
    if not get_settings().auth_enabled:
        raise SystemExit(
            "Use grant_local_platform_admin.py when AUTH_ENABLED=false"
        )
    change_reference = args.change_reference.strip()
    if len(change_reference) < 4:
        raise SystemExit("A valid approved change reference is required")

    target = None
    try:
        target = platform_service.resolve_bootstrap_user(
            db,
            user_id=args.user_id,
            external_issuer=args.issuer,
            external_subject=args.subject if args.issuer else None,
            employee_id=args.employee_id,
            email=args.email,
            legacy_subject=args.subject if not args.issuer else None,
        )
        mutation = platform_service.bootstrap_platform_administrator(
            db,
            user=target,
        )
        audit_service.write_authorization_audit(
            db,
            action=str(IdentityAuditEvent.PLATFORM_ADMIN_BOOTSTRAPPED),
            outcome="SUCCESS",
            target_user_id=target.id,
            tenant_id=None,
            correlation_id=change_reference,
            old_value=mutation.old_state,
            new_value={
                "role": mutation.grant.role,
                "status": mutation.grant.status,
                "bootstrap_action": mutation.action,
            },
            detail="Explicit database-operator bootstrap",
        )
        db.commit()
        return mutation.action, target.id
    except HTTPException as exc:
        db.rollback()
        code = (
            str(exc.detail.get("code"))
            if isinstance(exc.detail, dict)
            else "IAM_PLATFORM_ADMIN_BOOTSTRAP_REJECTED"
        )
        audit_service.write_authorization_audit(
            db,
            action=str(IdentityAuditEvent.PLATFORM_ADMIN_BOOTSTRAP_REJECTED),
            outcome="DENIED",
            target_user_id=target.id if target else None,
            tenant_id=None,
            correlation_id=change_reference,
            new_value={"reason_code": code},
            detail=code,
        )
        db.commit()
        raise


def main() -> None:
    args = build_parser().parse_args()
    with SessionLocal() as db:
        try:
            action, user_id = execute_bootstrap(db, args)
        except HTTPException as exc:
            message = (
                exc.detail.get("message")
                if isinstance(exc.detail, dict)
                else "Bootstrap rejected"
            )
            raise SystemExit(message) from None
    print(f"Platform Administrator bootstrap: {action}; local user ID {user_id}")


if __name__ == "__main__":
    main()
