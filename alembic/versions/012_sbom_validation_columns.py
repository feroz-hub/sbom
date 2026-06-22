"""sbom_source — persist 8-stage validation outcomes alongside the row.

Revision ID: 012_sbom_validation_columns
Revises: 011_ai_fix_batch
Create Date: 2026-05-07

Why this exists
---------------
Until now, SBOM uploads either succeeded (row written, no validation
record) or failed (no row at all — error envelope was returned and
discarded). The frontend therefore had nowhere to render the structured
report the 8-stage validator was already producing: refresh-the-page lost
everything; users were left guessing why an upload was rejected.

This migration adds the columns needed to keep the validator output
durable and queryable for the lifetime of the row.

Schema additions on ``sbom_source``
-----------------------------------
* ``status``              — one of ``validated`` / ``failed`` /
                             ``quarantined`` / ``pending``. ``pending`` is
                             reserved for any future async path; today the
                             route writes ``validated`` or ``failed`` (or
                             ``quarantined`` when a security-stage error
                             is present).
* ``failed_stage``        — the orchestrator stage at which the first
                             error-severity entry was emitted. Denormalised
                             so list filtering ``WHERE failed_stage = 'schema'``
                             stays cheap.
* ``validation_errors``   — full ``ErrorReport.entries`` payload as JSON.
                             Populated whenever the report has any entry
                             (errors, warnings, or info), so a healthy SBOM
                             with NTIA warnings still carries the warnings
                             list the detail page renders.
* ``error_count`` /
  ``warning_count``       — denormalised counts so the list page does not
                             have to deserialise the JSON to render a badge.
* ``validated_at``        — ISO timestamp captured immediately after the
                             pipeline returns. Independent of ``created_on``
                             because future async paths will lag.

Idempotency: existence-checked, mirrors 002 / 003 / 004 / 006-011.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "012_sbom_validation_columns"
down_revision = "011_ai_fix_batch"
branch_labels = None
depends_on = None


def _column_exists(bind: sa.engine.Connection, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {ix["name"] for ix in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def upgrade() -> None:
    bind = op.get_bind()

    if not _column_exists(bind, "sbom_source", "status"):
        op.add_column(
            "sbom_source",
            sa.Column(
                "status",
                sa.String(length=24),
                nullable=False,
                server_default=sa.text("'validated'"),
            ),
        )

    if not _column_exists(bind, "sbom_source", "failed_stage"):
        op.add_column(
            "sbom_source",
            sa.Column("failed_stage", sa.String(length=32), nullable=True),
        )

    if not _column_exists(bind, "sbom_source", "validation_errors"):
        # Stored as JSON — portable across SQLite (TEXT) and Postgres
        # (JSON). Keep the entries list verbatim from
        # ``ErrorReport.to_dict()``.
        op.add_column(
            "sbom_source",
            sa.Column("validation_errors", sa.JSON(), nullable=True),
        )

    if not _column_exists(bind, "sbom_source", "error_count"):
        op.add_column(
            "sbom_source",
            sa.Column(
                "error_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
        )

    if not _column_exists(bind, "sbom_source", "warning_count"):
        op.add_column(
            "sbom_source",
            sa.Column(
                "warning_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
        )

    if not _column_exists(bind, "sbom_source", "validated_at"):
        op.add_column(
            "sbom_source",
            sa.Column("validated_at", sa.String(), nullable=True),
        )

    if not _index_exists(bind, "sbom_source", "ix_sbom_source_status"):
        op.create_index("ix_sbom_source_status", "sbom_source", ["status"])

    if not _index_exists(bind, "sbom_source", "ix_sbom_source_failed_stage"):
        op.create_index(
            "ix_sbom_source_failed_stage",
            "sbom_source",
            ["failed_stage"],
        )

    # Alembic's built-in version table uses VARCHAR(32). Several existing
    # revision identifiers after this migration are longer than 32 bytes;
    # SQLite silently accepts them while PostgreSQL correctly rejects them.
    # Widen before Alembic attempts to record revision 013.
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "alembic_version",
            "version_num",
            existing_type=sa.String(length=32),
            type_=sa.String(length=128),
            existing_nullable=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    for ix in ("ix_sbom_source_status", "ix_sbom_source_failed_stage"):
        if _index_exists(bind, "sbom_source", ix):
            op.drop_index(ix, table_name="sbom_source")
    for col in (
        "status",
        "failed_stage",
        "validation_errors",
        "error_count",
        "warning_count",
        "validated_at",
    ):
        if _column_exists(bind, "sbom_source", col):
            op.drop_column("sbom_source", col)
