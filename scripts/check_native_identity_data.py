#!/usr/bin/env python3
"""Read-only, platform-wide IAM migration preflight; never merges or links users.

Run with DATABASE_URL set using the deployment's secret injection mechanism.
Output contains local user IDs, not email addresses or database credentials.
Exit 1 means duplicate canonical profile emails need explicit review before a
future global email-uniqueness migration. Native identity uniqueness is already
enforced separately by user_identities.uq_user_identities_native_email.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.native_identity import canonicalize_email


def duplicate_email_user_ids(rows) -> list[list[int]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for user_id, email in rows:
        canonical = canonicalize_email(email)
        if canonical is not None:
            grouped[canonical].append(int(user_id))
    return sorted(sorted(ids) for ids in grouped.values() if len(ids) > 1)


def main() -> int:
    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.connect() as connection:
            # This is an explicitly global operator preflight, not a tenant API.
            if connection.dialect.name == "postgresql":
                connection.execute(text("SET TRANSACTION READ ONLY"))
            groups = duplicate_email_user_ids(connection.execute(text("SELECT id, email FROM iam_users")))
            incomplete = (
                connection.execute(
                    text(
                        "SELECT id FROM iam_users WHERE external_iam_user_id IS NOT NULL "
                        "AND (external_issuer IS NULL OR external_subject IS NULL) ORDER BY id"
                    )
                )
                .scalars()
                .all()
            )
        print(
            json.dumps(
                {
                    "duplicate_normalized_email_user_ids": groups,
                    "legacy_identity_backfill_deferred_user_ids": incomplete,
                }
            )
        )
        return 1 if groups else 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
