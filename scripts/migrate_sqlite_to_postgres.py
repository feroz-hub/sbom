#!/usr/bin/env python3
"""Copy an Alembic-managed SBOM Analyzer database from SQLite to PostgreSQL.

The source is never modified. The PostgreSQL schema must already exist at
Alembic head. All copy operations, optional target clearing, self-reference
repairs, and sequence resets run in one PostgreSQL transaction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.dialects.postgresql import JSONB

ALEMBIC_TABLE = "alembic_version"
DEFAULT_BATCH_SIZE = 1_000


class MigrationError(RuntimeError):
    """A safety or verification gate prevented migration."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite-url", required=True, help="Source SQLite SQLAlchemy URL")
    parser.add_argument("--postgres-url", required=True, help="Target PostgreSQL SQLAlchemy URL")
    parser.add_argument("--dry-run", action="store_true", help="Validate and report without writing")
    parser.add_argument(
        "--truncate-target",
        action="store_true",
        help="Delete target application rows in reverse FK order before copy",
    )
    parser.add_argument(
        "--confirm-truncate",
        action="store_true",
        help="Second mandatory confirmation for --truncate-target",
    )
    parser.add_argument("--verify-only", action="store_true", help="Compare source and target without copying")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    source_backend = sa.engine.make_url(args.sqlite_url).get_backend_name()
    target_backend = sa.engine.make_url(args.postgres_url).get_backend_name()
    if source_backend != "sqlite":
        raise MigrationError("--sqlite-url must use the SQLite dialect")
    if target_backend != "postgresql":
        raise MigrationError("--postgres-url must use the PostgreSQL dialect")
    if args.batch_size < 1:
        raise MigrationError("--batch-size must be at least 1")
    if args.truncate_target and not args.confirm_truncate:
        raise MigrationError("--truncate-target requires --confirm-truncate")
    if args.confirm_truncate and not args.truncate_target:
        raise MigrationError("--confirm-truncate is valid only with --truncate-target")
    if args.verify_only and (args.dry_run or args.truncate_target):
        raise MigrationError("--verify-only cannot be combined with copy or truncate options")


def _alembic_heads() -> set[str]:
    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / "alembic.ini"))
    return set(ScriptDirectory.from_config(config).get_heads())


def _database_revisions(connection: sa.Connection) -> set[str]:
    inspector = sa.inspect(connection)
    if ALEMBIC_TABLE not in inspector.get_table_names():
        raise MigrationError("Database has no alembic_version table")
    return {str(row[0]) for row in connection.execute(sa.text("SELECT version_num FROM alembic_version"))}


def require_target_at_head(connection: sa.Connection) -> None:
    expected = _alembic_heads()
    actual = _database_revisions(connection)
    if actual != expected:
        raise MigrationError(
            f"PostgreSQL is not at Alembic head; expected {sorted(expected)}, found {sorted(actual)}"
        )


def reflect_database(engine: sa.Engine) -> sa.MetaData:
    metadata = sa.MetaData()
    metadata.reflect(engine)
    return metadata


def application_table_names(metadata: sa.MetaData) -> set[str]:
    return set(metadata.tables) - {ALEMBIC_TABLE}


def validate_schema_compatibility(source: sa.MetaData, target: sa.MetaData) -> None:
    source_names = application_table_names(source)
    target_names = application_table_names(target)
    if source_names != target_names:
        raise MigrationError(
            "Application table mismatch: "
            f"source-only={sorted(source_names - target_names)}, "
            f"target-only={sorted(target_names - source_names)}"
        )
    for name in sorted(target_names):
        source_columns = set(source.tables[name].c.keys())
        target_columns = set(target.tables[name].c.keys())
        if source_columns != target_columns:
            raise MigrationError(
                f"Column mismatch for {name}: source-only={sorted(source_columns - target_columns)}, "
                f"target-only={sorted(target_columns - source_columns)}"
            )


def dependency_order(metadata: sa.MetaData) -> list[sa.Table]:
    names = application_table_names(metadata)
    return [table for table in metadata.sorted_tables if table.name in names]


def _batches(rows: Sequence[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for offset in range(0, len(rows), size):
        yield list(rows[offset : offset + size])


def _convert_datetime(value: Any, column: sa.Column) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MigrationError(f"Invalid datetime in {column.table.name}.{column.name}") from exc
    else:
        raise MigrationError(f"Unsupported datetime value in {column.table.name}.{column.name}")
    if column.type.timezone and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def convert_value(value: Any, column: sa.Column) -> Any:
    if value is None:
        return None
    column_type = column.type
    if isinstance(column_type, sa.Boolean):
        if value in (True, 1, "1"):
            return True
        if value in (False, 0, "0"):
            return False
        raise MigrationError(f"Invalid Boolean value in {column.table.name}.{column.name}")
    if isinstance(column_type, (sa.JSON, JSONB)):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise MigrationError(f"Invalid JSON in {column.table.name}.{column.name}") from exc
        return value
    if isinstance(column_type, sa.DateTime):
        return _convert_datetime(value, column)
    if isinstance(column_type, sa.LargeBinary) and isinstance(value, memoryview):
        return bytes(value)
    if isinstance(column_type, sa.Numeric) and isinstance(value, float):
        return Decimal(str(value))
    return value


def _self_fk_columns(table: sa.Table) -> set[str]:
    columns: set[str] = set()
    for constraint in table.foreign_key_constraints:
        if constraint.referred_table is not table:
            continue
        for element in constraint.elements:
            if not element.parent.nullable:
                raise MigrationError(
                    f"Non-nullable self-reference requires manual ordering: {table.name}.{element.parent.name}"
                )
            columns.add(element.parent.name)
    return columns


def prepare_rows(
    source_connection: sa.Connection,
    source_table: sa.Table,
    target_table: sa.Table,
) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any]]]]:
    pk_names = [column.name for column in target_table.primary_key.columns]
    self_columns = _self_fk_columns(target_table)
    prepared: list[dict[str, Any]] = []
    deferred: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for source_row in source_connection.execute(sa.select(source_table)).mappings():
        row = {
            column.name: convert_value(source_row[column.name], column)
            for column in target_table.columns
        }
        self_values = {name: row[name] for name in self_columns if row[name] is not None}
        if self_values:
            identity = {name: row[name] for name in pk_names}
            if any(value is None for value in identity.values()):
                raise MigrationError(f"Self-referenced row in {target_table.name} has a NULL primary key")
            deferred.append((identity, self_values))
            for name in self_values:
                row[name] = None
        prepared.append(row)
    return prepared, deferred


def target_row_counts(connection: sa.Connection, tables: Iterable[sa.Table]) -> dict[str, int]:
    return {
        table.name: int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
        for table in tables
    }


def ensure_empty_or_clear(
    connection: sa.Connection,
    ordered_tables: Sequence[sa.Table],
    *,
    truncate_target: bool,
) -> None:
    counts = target_row_counts(connection, ordered_tables)
    populated = {name: count for name, count in counts.items() if count}
    if not populated:
        return
    if not truncate_target:
        raise MigrationError(f"PostgreSQL target is not empty: {populated}")
    for table in reversed(ordered_tables):
        connection.execute(table.delete())


def copy_all_tables(
    source_connection: sa.Connection,
    target_connection: sa.Connection,
    source: sa.MetaData,
    target: sa.MetaData,
    *,
    batch_size: int,
) -> None:
    for target_table in dependency_order(target):
        source_table = source.tables[target_table.name]
        rows, deferred = prepare_rows(source_connection, source_table, target_table)
        for batch in _batches(rows, batch_size):
            target_connection.execute(target_table.insert(), batch)
        for identity, values in deferred:
            predicate = sa.and_(*(target_table.c[name] == value for name, value in identity.items()))
            target_connection.execute(target_table.update().where(predicate).values(**values))


def reset_sequences(connection: sa.Connection, metadata: sa.MetaData) -> None:
    for table in dependency_order(metadata):
        for column in table.primary_key.columns:
            if not isinstance(column.type, (sa.Integer, sa.BigInteger)):
                continue
            sequence = connection.scalar(
                sa.text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
                {"table_name": table.name, "column_name": column.name},
            )
            if not sequence:
                continue
            maximum = connection.scalar(sa.select(sa.func.max(column)))
            value = int(maximum) if maximum is not None else 1
            called = maximum is not None
            connection.execute(
                sa.text("SELECT setval(CAST(:sequence AS regclass), :value, :called)"),
                {"sequence": sequence, "value": value, "called": called},
            )


def _pk_digest(connection: sa.Connection, table: sa.Table) -> tuple[int, str, Any, Any]:
    columns = list(table.primary_key.columns)
    if not columns:
        return 0, hashlib.sha256(b"").hexdigest(), None, None
    statement = sa.select(*columns).order_by(*columns).execution_options(stream_results=True)
    digest = hashlib.sha256()
    count = 0
    first: Any = None
    last: Any = None
    for row in connection.execute(statement):
        identity = tuple(row)
        if first is None:
            first = identity
        last = identity
        digest.update(json.dumps(identity, default=str, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return count, digest.hexdigest(), first, last


def _sbom_hashes(connection: sa.Connection, table: sa.Table) -> dict[Any, str]:
    result: dict[Any, str] = {}
    statement = sa.select(table.c.id, table.c.sbom_data).order_by(table.c.id)
    for identity, content in connection.execute(statement):
        raw = b"" if content is None else str(content).encode("utf-8")
        result[identity] = hashlib.sha256(raw).hexdigest()
    return result


def _foreign_key_orphans(connection: sa.Connection, metadata: sa.MetaData) -> list[str]:
    failures: list[str] = []
    for child in dependency_order(metadata):
        for constraint in child.foreign_key_constraints:
            parent = constraint.referred_table.alias(f"parent_{child.name}_{len(failures)}")
            joins = []
            populated = []
            for element in constraint.elements:
                joins.append(element.parent == parent.c[element.column.name])
                populated.append(element.parent.is_not(None))
            probe = next(iter(constraint.elements)).column.name
            statement = (
                sa.select(sa.func.count())
                .select_from(child.outerjoin(parent, sa.and_(*joins)))
                .where(sa.and_(*populated), parent.c[probe].is_(None))
            )
            count = int(connection.scalar(statement) or 0)
            if count:
                failures.append(f"{child.name}:{constraint.name or 'unnamed'}={count}")
    return failures


def verify_databases(
    source_connection: sa.Connection,
    target_connection: sa.Connection,
    source: sa.MetaData,
    target: sa.MetaData,
) -> bool:
    rows: list[tuple[str, int, int, str]] = []
    ok = True
    for target_table in dependency_order(target):
        source_table = source.tables[target_table.name]
        source_count, source_digest, source_min, source_max = _pk_digest(source_connection, source_table)
        target_count, target_digest, target_min, target_max = _pk_digest(target_connection, target_table)
        status = "OK"
        if (
            source_count != target_count
            or source_digest != target_digest
            or source_min != target_min
            or source_max != target_max
        ):
            status = "MISMATCH"
            ok = False
        rows.append((target_table.name, source_count, target_count, status))

    source_sbom = source.tables.get("sbom_source")
    target_sbom = target.tables.get("sbom_source")
    if source_sbom is not None and target_sbom is not None:
        if _sbom_hashes(source_connection, source_sbom) != _sbom_hashes(target_connection, target_sbom):
            ok = False
            rows.append(("sbom_source.sbom_data SHA-256", 0, 0, "MISMATCH"))

    orphan_failures = _foreign_key_orphans(target_connection, target)
    invalid_constraints = target_connection.execute(
        sa.text(
            "SELECT conname FROM pg_constraint c "
            "JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE n.nspname = current_schema() AND NOT c.convalidated"
        )
    ).scalars().all()
    if orphan_failures or invalid_constraints:
        ok = False

    print("\nMigration Summary:\n")
    print("| Table | SQLite Count | PostgreSQL Count | Status |")
    print("| ----- | -----------: | ---------------: | ------ |")
    for name, source_count, target_count, status in rows:
        print(f"| {name} | {source_count} | {target_count} | {status} |")
    print(f"\nForeign-key integrity: {'PASS' if not orphan_failures else 'FAIL: ' + ', '.join(orphan_failures)}")
    print(
        "Constraint validation: "
        + ("PASS" if not invalid_constraints else "FAIL: " + ", ".join(invalid_constraints))
    )
    return ok


def dry_run_preflight(
    source_connection: sa.Connection,
    target_connection: sa.Connection,
    source: sa.MetaData,
    target: sa.MetaData,
    *,
    truncate_target: bool,
) -> None:
    ordered = dependency_order(target)
    counts = target_row_counts(target_connection, ordered)
    populated = {name: count for name, count in counts.items() if count}
    if populated and not truncate_target:
        raise MigrationError(f"PostgreSQL target is not empty: {populated}")
    total = 0
    for table in ordered:
        rows, _ = prepare_rows(source_connection, source.tables[table.name], table)
        total += len(rows)
    print(f"Dry run passed: {len(ordered)} application tables, {total} rows ready to copy; no writes performed.")


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    source_engine = sa.create_engine(args.sqlite_url)
    target_engine = sa.create_engine(args.postgres_url, pool_pre_ping=True)
    try:
        source = reflect_database(source_engine)
        target = reflect_database(target_engine)
        validate_schema_compatibility(source, target)
        with source_engine.connect() as source_connection, target_engine.connect() as target_connection:
            _database_revisions(source_connection)
            require_target_at_head(target_connection)
            if args.dry_run:
                dry_run_preflight(
                    source_connection,
                    target_connection,
                    source,
                    target,
                    truncate_target=args.truncate_target,
                )
                return 0
            if args.verify_only:
                return 0 if verify_databases(source_connection, target_connection, source, target) else 1

        with source_engine.connect() as source_connection, target_engine.begin() as target_connection:
            ensure_empty_or_clear(
                target_connection,
                dependency_order(target),
                truncate_target=args.truncate_target,
            )
            copy_all_tables(
                source_connection,
                target_connection,
                source,
                target,
                batch_size=args.batch_size,
            )
            reset_sequences(target_connection, target)

        with source_engine.connect() as source_connection, target_engine.connect() as target_connection:
            return 0 if verify_databases(source_connection, target_connection, source, target) else 1
    finally:
        source_engine.dispose()
        target_engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (MigrationError, sa.exc.SQLAlchemyError) as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
