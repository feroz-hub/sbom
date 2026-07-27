#!/usr/bin/env python3
"""Report or explicitly consolidate memberships before a Phase 9 downgrade."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime

from sqlalchemy import create_engine, text

REPORT = text(
    """
    SELECT tu.id, tu.tenant_id, tu.role,
           count(a.id) FILTER (WHERE a.status = 'ACTIVE') AS active_count,
           count(a.id) FILTER (
               WHERE a.status = 'ACTIVE' AND a.is_primary
           ) AS primary_count
      FROM tenant_users tu
      LEFT JOIN tenant_user_role_assignments a ON a.tenant_user_id = tu.id
     GROUP BY tu.id, tu.tenant_id, tu.role
    HAVING count(a.id) FILTER (WHERE a.status = 'ACTIVE') <> 1
        OR count(a.id) FILTER (
               WHERE a.status = 'ACTIVE' AND a.is_primary
           ) <> 1
     ORDER BY tu.tenant_id, tu.id
    """
)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--primary-only",
        action="store_true",
        help="With --apply, explicitly revoke every non-primary active assignment.",
    )
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        parser.error("DATABASE_URL is required")
    if args.apply and not args.primary_only:
        parser.error("--apply requires the explicit --primary-only policy")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        rows = list(connection.execute(REPORT).mappings())
        for row in rows:
            print(
                f"membership={row.id} tenant={row.tenant_id} legacy={row.role} "
                f"active={row.active_count} primary={row.primary_count}"
            )
        if args.apply:
            now = datetime.now(UTC)
            connection.execute(
                text(
                    """
                    UPDATE tenant_user_role_assignments
                       SET status = 'REVOKED',
                           is_primary = false,
                           revoked_at = :now,
                           revocation_reason = 'Explicit Phase 9 downgrade consolidation',
                           version = version + 1,
                           updated_at = :now
                     WHERE status = 'ACTIVE' AND is_primary = false
                    """
                ),
                {"now": now},
            )
            connection.execute(
                text(
                    """
                    UPDATE tenant_users tu
                       SET role = ar.code,
                           role_assignment_version = role_assignment_version + 1,
                           updated_at = :now
                      FROM tenant_user_role_assignments a
                      JOIN authorization_roles ar ON ar.id = a.role_id
                     WHERE a.tenant_user_id = tu.id
                       AND a.status = 'ACTIVE'
                       AND a.is_primary = true
                    """
                ),
                {"now": now},
            )
            print("Applied explicit primary-only consolidation.")
    return 1 if rows and not args.apply else 0


if __name__ == "__main__":
    raise SystemExit(main())
