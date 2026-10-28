from __future__ import annotations

import argparse
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from scripts.migrate_sqlite_to_postgres import MigrationError, convert_value, validate_args


def _args(**overrides):
    values = {
        "sqlite_url": "sqlite:///source.db",
        "postgres_url": "postgresql+psycopg://user:pass@localhost/target",
        "dry_run": False,
        "truncate_target": False,
        "confirm_truncate": False,
        "verify_only": False,
        "batch_size": 1000,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_truncate_requires_second_confirmation() -> None:
    with pytest.raises(MigrationError, match="requires --confirm-truncate"):
        validate_args(_args(truncate_target=True))


def test_verify_only_rejects_mutating_options() -> None:
    with pytest.raises(MigrationError, match="cannot be combined"):
        validate_args(_args(verify_only=True, dry_run=True))


def test_type_conversion_for_postgresql_targets() -> None:
    metadata = sa.MetaData()
    table = sa.Table(
        "sample",
        metadata,
        sa.Column("flag", sa.Boolean()),
        sa.Column("payload", sa.JSON()),
        sa.Column("seen_at", sa.DateTime(timezone=True)),
    )
    assert convert_value(1, table.c.flag) is True
    assert convert_value("0", table.c.flag) is False
    assert convert_value('{"ok": true}', table.c.payload) == {"ok": True}
    converted = convert_value("2026-06-22T10:30:00", table.c.seen_at)
    assert converted == datetime(2026, 6, 22, 10, 30, tzinfo=UTC)
