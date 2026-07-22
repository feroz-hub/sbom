"""Create canonical KEV vulnerabilities table.

Revision ID: 044_kev_vulnerabilities_table
Revises: 043_widen_analysis_finding_match_reason
Create Date: 2026-07-17

The application already had a KEV mirror in ``kev_entry``.  This migration
promotes that cache to the requested canonical table name,
``kev_vulnerabilities``, and adds the richer CISA metadata fields used by
finding enrichment.

Date-like values remain ISO strings to match the existing application
convention and keep PostgreSQL/SQLite test migrations identical.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "044_kev_vulnerabilities_table"
down_revision = "043_widen_analysis_finding_match_reason"
branch_labels = None
depends_on = None

OLD_TABLE = "kev_entry"
TABLE = "kev_vulnerabilities"


def _table_exists(bind: sa.engine.Connection, table_name: str) -> bool:
    return table_name in set(sa.inspect(bind).get_table_names())


def _columns(bind: sa.engine.Connection, table_name: str) -> set[str]:
    if not _table_exists(bind, table_name):
        return set()
    return {column["name"] for column in sa.inspect(bind).get_columns(table_name)}


def _index_exists(bind: sa.engine.Connection, table_name: str, index_name: str) -> bool:
    if not _table_exists(bind, table_name):
        return False
    return index_name in {index["name"] for index in sa.inspect(bind).get_indexes(table_name)}


def _add_column_if_missing(bind: sa.engine.Connection, table_name: str, column: sa.Column) -> None:
    if column.name in _columns(bind, table_name):
        return
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.add_column(column)


def _rename_column_if_present(
    bind: sa.engine.Connection,
    table_name: str,
    old_name: str,
    new_name: str,
    existing_type: sa.types.TypeEngine,
) -> None:
    cols = _columns(bind, table_name)
    if old_name not in cols or new_name in cols:
        return
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.alter_column(old_name, new_column_name=new_name, existing_type=existing_type, nullable=True)


def _create_kev_table() -> None:
    op.create_table(
        TABLE,
        sa.Column("cve_id", sa.String(length=32), primary_key=True),
        sa.Column("vendor_project", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_name", sa.Text(), nullable=True),
        sa.Column("date_added", sa.String(length=10), nullable=True),
        sa.Column("short_description", sa.Text(), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("due_date", sa.String(length=10), nullable=True),
        sa.Column("known_ransomware_campaign_use", sa.String(length=32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("cwes", sa.JSON(), nullable=True),
        sa.Column("catalog_version", sa.String(length=32), nullable=True),
        sa.Column("catalog_date_released", sa.String(length=64), nullable=True),
        sa.Column("refreshed_at", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.String(), nullable=True),
        sa.Column("updated_at", sa.String(), nullable=True),
    )


def _merge_legacy_table(bind: sa.engine.Connection) -> None:
    """Merge a bootstrap-created legacy table into the canonical table."""
    legacy = sa.Table(OLD_TABLE, sa.MetaData(), autoload_with=bind)
    canonical = sa.Table(TABLE, sa.MetaData(), autoload_with=bind)
    existing = set(bind.execute(sa.select(canonical.c.cve_id)).scalars())
    rows = []
    for legacy_row in bind.execute(sa.select(legacy)).mappings():
        if legacy_row["cve_id"] in existing:
            continue
        row = {
            column.name: legacy_row[column.name]
            for column in canonical.columns
            if column.name in legacy_row
        }
        if "known_ransomware_campaign_use" not in row:
            row["known_ransomware_campaign_use"] = legacy_row.get("known_ransomware_use")
        rows.append(row)
    if rows:
        bind.execute(canonical.insert(), rows)
    op.drop_table(OLD_TABLE)


def _ensure_indexes(bind: sa.engine.Connection) -> None:
    if not _index_exists(bind, TABLE, "ix_kev_vulnerabilities_date_added"):
        op.create_index("ix_kev_vulnerabilities_date_added", TABLE, ["date_added"])
    if not _index_exists(bind, TABLE, "ix_kev_vulnerabilities_ransomware"):
        op.create_index(
            "ix_kev_vulnerabilities_ransomware",
            TABLE,
            ["known_ransomware_campaign_use"],
        )


def upgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, OLD_TABLE):
        if _table_exists(bind, TABLE):
            _merge_legacy_table(bind)
        else:
            op.rename_table(OLD_TABLE, TABLE)
    elif not _table_exists(bind, TABLE):
        _create_kev_table()

    if not _table_exists(bind, TABLE):
        return

    _rename_column_if_present(
        bind,
        TABLE,
        "known_ransomware_use",
        "known_ransomware_campaign_use",
        sa.String(),
    )

    _add_column_if_missing(bind, TABLE, sa.Column("notes", sa.Text(), nullable=True))
    _add_column_if_missing(bind, TABLE, sa.Column("cwes", sa.JSON(), nullable=True))
    _add_column_if_missing(bind, TABLE, sa.Column("catalog_version", sa.String(length=32), nullable=True))
    _add_column_if_missing(bind, TABLE, sa.Column("catalog_date_released", sa.String(length=64), nullable=True))
    _add_column_if_missing(bind, TABLE, sa.Column("first_seen_at", sa.String(), nullable=True))
    _add_column_if_missing(bind, TABLE, sa.Column("updated_at", sa.String(), nullable=True))
    _ensure_indexes(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, TABLE):
        return

    if "known_ransomware_campaign_use" in _columns(bind, TABLE) and "known_ransomware_use" not in _columns(bind, TABLE):
        with op.batch_alter_table(TABLE) as batch_op:
            batch_op.alter_column(
                "known_ransomware_campaign_use",
                new_column_name="known_ransomware_use",
                existing_type=sa.String(length=32),
                nullable=True,
            )

    for index_name in ("ix_kev_vulnerabilities_ransomware", "ix_kev_vulnerabilities_date_added"):
        if _index_exists(bind, TABLE, index_name):
            op.drop_index(index_name, table_name=TABLE)

    for column_name in (
        "updated_at",
        "first_seen_at",
        "catalog_date_released",
        "catalog_version",
        "cwes",
        "notes",
    ):
        if column_name in _columns(bind, TABLE):
            with op.batch_alter_table(TABLE) as batch_op:
                batch_op.drop_column(column_name)

    if not _table_exists(bind, OLD_TABLE):
        op.rename_table(TABLE, OLD_TABLE)
