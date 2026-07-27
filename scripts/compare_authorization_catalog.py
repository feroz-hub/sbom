#!/usr/bin/env python3
"""Read-only comparison of the frozen legacy matrix and database catalogue."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.authorization_catalog_seed_v1 import ROLE_PERMISSIONS_V1, ROLE_SCOPES_V1
from app.db import SessionLocal
from app.models import AuthorizationRole


def comparison() -> dict[str, dict[str, object]]:
    report: dict[str, dict[str, object]] = {}
    with SessionLocal() as db:
        roles = {
            role.code: role
            for role in db.scalars(
                select(AuthorizationRole).order_by(AuthorizationRole.code)
            )
        }
        for code, legacy_codes in ROLE_PERMISSIONS_V1.items():
            role = roles.get(code)
            if role is None:
                report[code] = {
                    "missing_role": True,
                    "missing_from_database": sorted(legacy_codes),
                    "extra_in_database": [],
                    "scope_mismatches": [],
                    "inactive_permissions": [],
                }
                continue
            database_codes = {
                mapping.permission.code for mapping in role.permissions
            }
            report[code] = {
                "missing_role": False,
                "missing_from_database": sorted(set(legacy_codes) - database_codes),
                "extra_in_database": sorted(database_codes - set(legacy_codes)),
                "scope_mismatches": sorted(
                    mapping.permission.code
                    for mapping in role.permissions
                    if mapping.permission.scope != role.scope
                    and role.code != "PLATFORM_ADMIN"
                ),
                "inactive_permissions": sorted(
                    mapping.permission.code
                    for mapping in role.permissions
                    if mapping.permission.status != "ACTIVE"
                ),
                "role_scope_mismatch": role.scope != ROLE_SCOPES_V1[code],
                "role_inactive": role.status != "ACTIVE",
            }
    return report


def has_mismatch(report: dict[str, dict[str, object]]) -> bool:
    return any(
        bool(value)
        for result in report.values()
        for key, value in result.items()
        if key not in {"missing_role"} or value
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args()
    report = comparison()
    mismatch = has_mismatch(report)
    if args.format == "json":
        print(json.dumps({"mismatch": mismatch, "roles": report}, indent=2))
    else:
        for role, result in report.items():
            print(f"{role}: {'MISMATCH' if any(result.values()) else 'OK'}")
            for key, value in result.items():
                if value:
                    print(f"  {key}: {value}")
    return 1 if mismatch and args.fail_on_mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
