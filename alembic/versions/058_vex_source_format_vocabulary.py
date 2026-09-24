"""Normalise backfilled VexStatement.source_format to the controlled vocabulary.

Revision ID: 058_vex_source_format
Revises: 057_vex_audit_hardening
Create Date: 2026-09-24

Migration 056 backfilled ``source_format`` with ``lower(vex_documents.format)``.
That column holds free text — a real database contained ``"CycloneDX VEX"`` —
so the backfill produced ``cyclonedx vex`` while the importers write the
controlled token ``cyclonedx``. One format ended up with two values, which
silently splits the ``source_format`` filter on the investigation queue and
any grouping by format: a user filtering for CycloneDX would miss every
pre-enhancement statement.

This maps the legacy values onto the vocabulary the importers use
(``cyclonedx``, ``openvex``, ``csaf``, ``manual``) by substring, which is
robust to the variants free text produces (``CycloneDX``, ``CycloneDX VEX``,
``cyclonedx-vex``). Anything unrecognised is left untouched rather than
guessed at — a wrong label is worse than an unfamiliar one.

Data-only and idempotent; re-running changes nothing. There is no meaningful
downgrade: restoring the un-normalised text would reintroduce the split.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "058_vex_source_format"
down_revision = "057_vex_audit_hardening"
branch_labels = None
depends_on = None

#: Substring -> canonical token. Order matters only in that the first match
#: wins, and the substrings are mutually exclusive in practice.
_VOCABULARY = (
    ("cyclonedx", "cyclonedx"),
    ("cdx", "cyclonedx"),
    ("openvex", "openvex"),
    ("csaf", "csaf"),
    ("manual", "manual"),
)


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "vex_statements"):
        return
    columns = {c["name"] for c in sa.inspect(bind).get_columns("vex_statements")}
    if "source_format" not in columns:
        return

    for needle, canonical in _VOCABULARY:
        bind.execute(
            sa.text(
                "UPDATE vex_statements SET source_format = :canonical "
                "WHERE source_format IS NOT NULL "
                "AND source_format <> :canonical "
                "AND position(:needle in lower(source_format)) > 0"
            ),
            {"canonical": canonical, "needle": needle},
        )


def downgrade() -> None:
    """Intentionally a no-op.

    The original values were free text with no canonical form; restoring them
    would mean re-introducing the inconsistency this migration exists to
    remove, and the pre-normalisation text is not recoverable from the
    normalised token anyway.
    """
