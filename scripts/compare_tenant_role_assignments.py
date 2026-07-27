#!/usr/bin/env python3
"""Compare legacy membership roles with Phase 9 assignment state (read-only)."""

from __future__ import annotations

import argparse
import json
import os

from sqlalchemy import create_engine, text

QUERY = text(
    """
    SELECT tu.id AS membership_id,
           tu.tenant_id,
           tu.role AS legacy_role,
           tu.role_assignment_version AS version,
           max(ar.code) FILTER (
               WHERE a.status = 'ACTIVE' AND a.is_primary
           ) AS primary_assignment_role,
           coalesce(
               array_agg(ar.code ORDER BY ar.code)
                   FILTER (WHERE a.status = 'ACTIVE'),
               ARRAY[]::varchar[]
           ) AS active_role_codes,
           count(a.id) FILTER (WHERE a.status = 'ACTIVE') AS active_count,
           count(a.id) FILTER (
               WHERE a.status = 'ACTIVE' AND a.is_primary
           ) AS primary_count,
           count(a.id) FILTER (
               WHERE a.status = 'ACTIVE' AND ar.id IS NULL
           ) AS unknown_catalogue_count
      FROM tenant_users tu
      LEFT JOIN tenant_user_role_assignments a ON a.tenant_user_id = tu.id
      LEFT JOIN authorization_roles ar ON ar.id = a.role_id
     GROUP BY tu.id, tu.tenant_id, tu.role, tu.role_assignment_version
     ORDER BY tu.tenant_id, tu.id
    """
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        parser.error("DATABASE_URL is required")
    engine = create_engine(database_url)
    with engine.connect() as connection:
        rows = [dict(row) for row in connection.execute(QUERY).mappings()]
    for row in rows:
        row["active_role_codes"] = list(row["active_role_codes"])
        row["missing_assignment"] = row["active_count"] == 0
        row["multiple_primary_assignments"] = row["primary_count"] > 1
        row["zero_primary_assignments"] = row["primary_count"] == 0
        row["unknown_catalogue_role"] = row["unknown_catalogue_count"] > 0
        row["mismatch"] = any(
            (
                row["missing_assignment"],
                row["multiple_primary_assignments"],
                row["zero_primary_assignments"],
                row["unknown_catalogue_role"],
                row["primary_assignment_role"] != row["legacy_role"],
            )
        )
    if args.format == "json":
        print(json.dumps(rows, indent=2, default=str))
    else:
        for row in rows:
            print(
                "membership={membership_id} tenant={tenant_id} legacy={legacy_role} "
                "primary={primary_assignment_role} active={active_role_codes} "
                "version={version} mismatch={mismatch}".format(**row)
            )
        print(f"memberships={len(rows)} mismatches={sum(row['mismatch'] for row in rows)}")
    return 1 if args.fail_on_mismatch and any(row["mismatch"] for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
