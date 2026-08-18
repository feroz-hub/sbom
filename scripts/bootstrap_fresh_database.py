#!/usr/bin/env python3
"""Safely bootstrap an empty PostgreSQL database from the frozen revision 047 schema.

This avoids the repository's historical revision-001 ``create_all`` behavior,
which is not a stable fresh-install contract. The command refuses any database
that already contains public tables and requires the operator to repeat the
target database name explicitly.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "scripts" / "schema" / "postgresql_047_baseline.sql"
BASELINE_REVISION = "047_email_verification_tokens"

def _expected_head() -> set[str]:
    config = Config(ROOT / "alembic.ini")
    script = ScriptDirectory.from_config(config)
    return set(script.get_heads())
def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True)
    parser.add_argument(
        "--confirm-empty-database",
        required=True,
        metavar="DATABASE_NAME",
        help="Repeat the exact target database name to authorize an empty bootstrap.",
    )
    return parser.parse_args()


def bootstrap(database_url: str, confirmation: str) -> None:
    parsed = make_url(database_url)
    if not parsed.get_backend_name().startswith("postgresql"):
        raise RuntimeError("Fresh bootstrap supports PostgreSQL only")
    database_name = parsed.database or ""
    if not database_name or confirmation != database_name:
        raise RuntimeError("--confirm-empty-database must exactly match the target database name")
    if not SNAPSHOT.is_file():
        raise RuntimeError("Frozen revision-047 schema snapshot is missing")

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            existing = inspect(connection).get_table_names(schema="public")
            if existing:
                raise RuntimeError("Refusing fresh bootstrap because the target database is not empty")
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            try:
                cursor.execute(SNAPSHOT.read_text(encoding="utf-8"), prepare=False)
                cursor.execute("CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)")
                cursor.execute(
                    "INSERT INTO public.alembic_version (version_num) VALUES (%s)",
                    (BASELINE_REVISION,),
                )
            finally:
                cursor.close()
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()
    finally:
        engine.dispose()

    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
    )
    verification_engine = create_engine(database_url)
    try:
        with verification_engine.connect() as connection:
            expected_heads = _expected_head()
            actual_heads = {
                str(row[0])
                for row in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
            }
            if actual_heads != expected_heads:
                raise RuntimeError(
                    "Fresh bootstrap did not reach the expected Alembic head(s). "
                    f"Expected {sorted(expected_heads)}, "
                    f"found {sorted(actual_heads)}"
                )
    finally:
        verification_engine.dispose()

def main() -> int:
    args = _arguments()
    try:
        bootstrap(args.database_url, args.confirm_empty_database)
    except Exception as exc:  # noqa: BLE001
        print(f"Fresh database bootstrap failed: {exc}", file=sys.stderr)
        return 1
    heads = ", ".join(sorted(_expected_head()))
    print(f"Fresh PostgreSQL database bootstrapped at revision {heads}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
