"""Alembic migration environment."""

from __future__ import annotations

import os

# Load .env file if present before importing db or resolving URLs
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from logging.config import fileConfig
from pathlib import Path

import app.models  # noqa: F401 — register tables on Base.metadata
import app.nvd_mirror.db.models  # noqa: F401 — register mirror tables on Base.metadata
from alembic import context
from alembic.script import ScriptDirectory
from app.db import DATABASE_URL, Base
from sqlalchemy import create_engine, inspect, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return (os.getenv("DATABASE_URL") or "").strip() or DATABASE_URL


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            # Historical 001 uses live metadata. The repository's frozen 047
            # baseline is the supported fresh-install contract, with no user data.
            options = context.get_context().opts
            fresh_upgrade = options.get("destination_rev") in ("head", "heads") and not options.get("dont_mutate")
            if fresh_upgrade and connection.dialect.name == "postgresql" and not inspect(connection).get_table_names(schema="public"):
                snapshot = Path(__file__).resolve().parent.parent / "scripts/schema/postgresql_047_baseline.sql"
                cursor = connection.connection.cursor()
                try:
                    cursor.execute(snapshot.read_text(), prepare=False)
                finally:
                    cursor.close()
                connection.exec_driver_sql("SET LOCAL search_path TO public")
                context.get_context().stamp(ScriptDirectory.from_config(config), "047_email_verification_tokens")
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
