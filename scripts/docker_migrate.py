#!/usr/bin/env python3
"""Apply migrations safely for both empty and existing PostgreSQL databases."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from bootstrap_fresh_database import bootstrap
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    database_url = (os.getenv("DATABASE_URL") or "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")

    parsed = make_url(database_url)
    if not parsed.get_backend_name().startswith("postgresql"):
        raise RuntimeError("The Docker server migration service requires PostgreSQL")

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            is_empty = not inspect(connection).get_table_names(schema="public")
    finally:
        engine.dispose()

    if is_empty:
        # The historical revision-001 create_all migration is not a stable
        # fresh-install contract. Use the repository's guarded frozen baseline,
        # which refuses non-empty databases, and then advances to current head.
        bootstrap(database_url, parsed.database or "")
    else:
        command.upgrade(Config(ROOT / "alembic.ini"), "head")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
