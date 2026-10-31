#!/usr/bin/env python3
"""Explicit Native bootstrap, recovery and secret-safe status. Never sends mail."""
import sys

if __name__ == "__main__" and "status" in sys.argv[1:] and any(
    value.split("=", 1)[0] in {"--profile", "--legacy-config"} for value in sys.argv[1:]
):
    sys.dont_write_bytecode = True

import argparse
import json
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-database", required=True)
    parser.add_argument("--profile", choices=("auto", "legacy", "greenfield"),
                        help="opt-in development configuration for read-only aggregate status")
    parser.add_argument("--legacy-config", choices=("auto", "managed", "windows", "env"),
                        help="selected existing development family; requires --profile")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create")
    for name in ("email", "first-name", "last-name", "phone", "operator-reference"):
        create.add_argument("--" + name, required=True)
    sub.add_parser("status")
    sub.add_parser("resend-activation")
    args = parser.parse_args()
    if args.profile is not None or args.legacy_config is not None:
        if args.profile is None or args.action != "status":
            parser.error("Profile resolution supports read-only status only; privileged enrollment requires a separately approved operator flow")
        args.legacy_config = args.legacy_config or "auto"
        from scripts import dev

        return dev.native_admin_status(args)
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
