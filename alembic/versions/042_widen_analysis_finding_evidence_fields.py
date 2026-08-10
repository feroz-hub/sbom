"""Widen analysis finding evidence fields.

Revision ID: 042_widen_analysis_finding_evidence_fields
Revises: 041_project_product_hierarchy
Create Date: 2026-07-07

The streaming analysis endpoint bulk-inserts provider findings. External
identifiers, versions, version ranges, URLs, and CVSS vectors are provider
evidence, not short enum values; silently truncating them would corrupt the
audit trail and vulnerability matching context.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "042_widen_analysis_finding_evidence_fields"
down_revision = "041_project_product_hierarchy"
branch_labels = None
depends_on = None

TABLE = "analysis_finding"


def _table_exists(bind: sa.engine.Connection) -> bool:
    return TABLE in set(sa.inspect(bind).get_table_names())


def _alter_columns(bind: sa.engine.Connection, changes: list[tuple[str, dict]]) -> None:
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(TABLE) as batch:
            for column_name, options in changes:
                batch.alter_column(column_name, **options)
        return
    for column_name, options in changes:
        op.alter_column(TABLE, column_name, **options)


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind):
        return

    _alter_columns(
        bind,
        [
            ("vuln_id", {"existing_type": sa.String(), "type_": sa.String(length=255), "nullable": False}),
            ("source", {"existing_type": sa.String(), "type_": sa.String(length=128), "nullable": True}),
            ("severity", {"existing_type": sa.String(), "type_": sa.String(length=16), "nullable": True}),
            ("vector", {"existing_type": sa.String(), "type_": sa.Text(), "nullable": True}),
            ("reference_url", {"existing_type": sa.String(), "type_": sa.Text(), "nullable": True}),
            ("component_name", {"existing_type": sa.String(), "type_": sa.Text(), "nullable": True}),
            ("component_version", {"existing_type": sa.String(), "type_": sa.Text(), "nullable": True}),
            ("attack_vector", {"existing_type": sa.String(), "type_": sa.String(length=64), "nullable": True}),
            ("cvss_version", {"existing_type": sa.String(), "type_": sa.String(length=16), "nullable": True}),
            (
                "match_reason",
                {"existing_type": sa.String(length=32), "type_": sa.String(length=64), "nullable": True},
            ),
            ("matched_range", {"existing_type": sa.String(length=128), "type_": sa.Text(), "nullable": True}),
            (
                "match_strategy",
                {"existing_type": sa.String(length=32), "type_": sa.String(length=64), "nullable": True},
            ),
        ],
    )


def downgrade() -> None:
    """Restore the previous column definitions.

    Downgrade may fail if rows written after this migration contain
    ``match_reason``/``match_strategy`` values longer than 32 characters or
    ``matched_range`` values longer than 128 characters. That is intentional:
    Alembic should not silently truncate vulnerability evidence.
    """

    bind = op.get_bind()
    if not _table_exists(bind):
        return

    _alter_columns(
        bind,
        [
            (
                "match_strategy",
                {"existing_type": sa.String(length=64), "type_": sa.String(length=32), "nullable": True},
            ),
            ("matched_range", {"existing_type": sa.Text(), "type_": sa.String(length=128), "nullable": True}),
            (
                "match_reason",
                {"existing_type": sa.String(length=64), "type_": sa.String(length=32), "nullable": True},
            ),
            ("cvss_version", {"existing_type": sa.String(length=16), "type_": sa.String(), "nullable": True}),
            ("attack_vector", {"existing_type": sa.String(length=64), "type_": sa.String(), "nullable": True}),
            ("component_version", {"existing_type": sa.Text(), "type_": sa.String(), "nullable": True}),
            ("component_name", {"existing_type": sa.Text(), "type_": sa.String(), "nullable": True}),
            ("reference_url", {"existing_type": sa.Text(), "type_": sa.String(), "nullable": True}),
            ("vector", {"existing_type": sa.Text(), "type_": sa.String(), "nullable": True}),
            ("severity", {"existing_type": sa.String(length=16), "type_": sa.String(), "nullable": True}),
            ("source", {"existing_type": sa.String(length=128), "type_": sa.String(), "nullable": True}),
            ("vuln_id", {"existing_type": sa.String(length=255), "type_": sa.String(), "nullable": False}),
        ],
    )
