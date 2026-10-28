#!/usr/bin/env python3
"""Explicit Native bootstrap, recovery and secret-safe status. Never sends mail."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-database", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create")
    for name in ("email", "first-name", "last-name", "phone", "operator-reference"):
        create.add_argument("--" + name, required=True)
    sub.add_parser("status")
    sub.add_parser("resend-activation")
    args = parser.parse_args()
    from sqlalchemy.engine import make_url
    try:
        matches = bool(os.environ.get("DATABASE_URL")) and make_url(os.environ["DATABASE_URL"]).database == args.confirm_database
    except Exception:
        matches = False
    if not matches:
        parser.error("Explicit DATABASE_URL and matching database confirmation required")
    try:
        from app.db import SessionLocal
        from app.services import native_platform_bootstrap as bootstrap
        with SessionLocal() as db:
            if args.action == "create":
                bootstrap.create(db, **{k: getattr(args, k) for k in ("email", "first_name", "last_name", "phone", "operator_reference")})
            elif args.action == "resend-activation":
                bootstrap.resend(db)
            db.commit()
            print(json.dumps(bootstrap.status(db)))
        return 0
    except Exception:
        # Database/provider exceptions can contain parameters: never print them.
        print("Native bootstrap refused or unavailable; check configuration and safe status.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
