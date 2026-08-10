"""Widen analysis finding match_reason.

Revision ID: 043_widen_analysis_finding_match_reason
Revises: 042_widen_analysis_finding_evidence_fields
Create Date: 2026-07-07

``match_reason`` is provider/version-range evidence, not a compact enum.
Preserve the full reason string so finding persistence does not fail on
legitimate source-generated explanations.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "043_widen_analysis_finding_match_reason"
down_revision = "042_widen_analysis_finding_evidence_fields"
branch_labels = None
depends_on = None

TABLE = "analysis_finding"


def _table_exists(bind: sa.engine.Connection) -> bool:
    return TABLE in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind):
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(TABLE) as batch:
            batch.alter_column(
                "match_reason",
                existing_type=sa.String(length=64),
                type_=sa.String(length=255),
                existing_nullable=True,
            )
    else:
        op.alter_column(
            TABLE,
            "match_reason",
            existing_type=sa.String(length=64),
            type_=sa.String(length=255),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Restore the previous bound without silently truncating data."""

    bind = op.get_bind()
    if not _table_exists(bind):
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(TABLE) as batch:
            batch.alter_column(
                "match_reason",
                existing_type=sa.String(length=255),
                type_=sa.String(length=64),
                existing_nullable=True,
            )
    else:
        op.alter_column(
            TABLE,
            "match_reason",
            existing_type=sa.String(length=255),
            type_=sa.String(length=64),
            existing_nullable=True,
        )
