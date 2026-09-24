"""VEX investigation foundation: contexts, source-native status, provenance.

Revision ID: 056_vex_investigation
Revises: 055_ai_model_registry
Create Date: 2026-09-24

PR-1 of the VEX Dashboard & Investigation workstream
(``docs/requirements/vex-dashboard-investigation.md``). Purely additive:

* ``vex_investigation`` — the vulnerability context joining analyser findings,
  VEX statements and manual decisions (VEX-DATA-001). No rows are created here;
  the PR-2 reconciliation engine populates it.
* ``vex_statements`` gains source-native status and mapping provenance
  (VEX-DATA-002/VEX-STAT-002). The existing ``status`` column is untouched so
  reports, exports and the dashboard keep working unchanged.
* ``vex_documents`` gains provenance and the ``source_hash`` that makes
  re-import idempotent (VEX-ING-002/003).

Backfill: existing statements get ``normalized_status`` derived from ``status``
(``unknown`` maps to ``UNDER_INVESTIGATION`` per spec section 8) and
``source_status`` seeded from ``status`` as the best available record of what
the producer said. ``source_format`` is inferred from the owning document's
``format``. Existing documents get a ``source_hash`` only where the raw
document survives; NULL means "unknown provenance", not "no document".
"""

from __future__ import annotations

import hashlib
import json

import sqlalchemy as sa
from alembic import op

revision = "056_vex_investigation"
down_revision = "055_ai_model_registry"
branch_labels = None
depends_on = None


#: Legacy status -> canonical EffectiveVexStatus (spec sections 7 and 8).
_NORMALIZED_BY_STATUS = {
    "affected": "AFFECTED",
    "not_affected": "NOT_AFFECTED",
    "fixed": "FIXED",
    "under_investigation": "UNDER_INVESTIGATION",
    "unknown": "UNDER_INVESTIGATION",
}


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _columns(bind: sa.engine.Connection, table: str) -> set[str]:
    try:
        return {item["name"] for item in sa.inspect(bind).get_columns(table)}
    except sa.exc.NoSuchTableError:
        return set()


def _index_exists(bind: sa.engine.Connection, table: str, index: str) -> bool:
    try:
        return index in {item["name"] for item in sa.inspect(bind).get_indexes(table)}
    except sa.exc.NoSuchTableError:
        return False


def _add_column(bind: sa.engine.Connection, table: str, column: sa.Column) -> None:
    if _table_exists(bind, table) and column.name not in _columns(bind, table):
        op.add_column(table, column)


def _drop_column(bind: sa.engine.Connection, table: str, name: str) -> None:
    if _table_exists(bind, table) and name in _columns(bind, table):
        op.drop_column(table, name)


def upgrade() -> None:
    bind = op.get_bind()

    # ---- vex_statements: source-native status + mapping provenance ----
    for column in (
        sa.Column("source_format", sa.String(length=32), nullable=True),
        sa.Column("source_status", sa.String(length=64), nullable=True),
        sa.Column("normalized_status", sa.String(length=32), nullable=True),
        sa.Column("asserted_at", sa.String(), nullable=True),
        sa.Column("match_strategy", sa.String(length=32), nullable=True),
        sa.Column("match_confidence", sa.String(length=16), nullable=True),
        sa.Column("version_applicable", sa.Boolean(), nullable=True),
    ):
        _add_column(bind, "vex_statements", column)

    if _table_exists(bind, "vex_statements"):
        if not _index_exists(bind, "vex_statements", "ix_vex_statements_source_format"):
            op.create_index("ix_vex_statements_source_format", "vex_statements", ["source_format"])
        if not _index_exists(bind, "vex_statements", "ix_vex_statements_normalized_status"):
            op.create_index("ix_vex_statements_normalized_status", "vex_statements", ["normalized_status"])

    # ---- vex_documents: provenance + idempotency ----
    for column in (
        sa.Column("source_document_id", sa.String(), nullable=True),
        sa.Column("source_document_version", sa.String(), nullable=True),
        sa.Column("source_hash", sa.String(length=64), nullable=True),
        sa.Column("asserted_at", sa.String(), nullable=True),
        sa.Column("superseded_by_id", sa.Integer(), nullable=True),
    ):
        _add_column(bind, "vex_documents", column)

    if _table_exists(bind, "vex_documents"):
        for name, cols in (
            ("ix_vex_documents_source_document_id", ["source_document_id"]),
            ("ix_vex_documents_source_hash", ["source_hash"]),
            ("ix_vex_documents_asserted_at", ["asserted_at"]),
            ("ix_vex_documents_superseded_by_id", ["superseded_by_id"]),
        ):
            if not _index_exists(bind, "vex_documents", name):
                op.create_index(name, "vex_documents", cols)

    # ---- vex_investigation ----
    if not _table_exists(bind, "vex_investigation"):
        op.create_table(
            "vex_investigation",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column(
                "sbom_id",
                sa.Integer(),
                sa.ForeignKey("sbom_source.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "component_id",
                sa.Integer(),
                sa.ForeignKey("sbom_component.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("component_key", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("canonical_vulnerability_id", sa.String(length=255), nullable=False),
            sa.Column("aliases_json", sa.Text(), nullable=True),
            sa.Column("effective_status", sa.String(length=32), nullable=False),
            sa.Column("reconciliation_status", sa.String(length=32), nullable=False),
            sa.Column("analyzer_detection_state", sa.String(length=32), nullable=True),
            sa.Column(
                "effective_vex_statement_id",
                sa.Integer(),
                sa.ForeignKey("vex_statements.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "unresolved_discriminator",
                sa.String(length=64),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "is_current",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
            sa.Column("first_seen_at", sa.String(), nullable=False),
            sa.Column("last_seen_at", sa.String(), nullable=False),
            sa.Column(
                "last_analysis_run_id",
                sa.Integer(),
                sa.ForeignKey("analysis_run.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("assigned_to", sa.String(), nullable=True),
            sa.Column("reviewed_by", sa.String(), nullable=True),
            sa.Column("reviewed_at", sa.String(), nullable=True),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=True),
            sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
            sa.UniqueConstraint(
                "tenant_id",
                "sbom_id",
                "component_key",
                "canonical_vulnerability_id",
                "unresolved_discriminator",
                name="uq_vex_investigation_context",
            ),
        )
        for name, cols in (
            ("ix_vex_investigation_tenant_id", ["tenant_id"]),
            ("ix_vex_investigation_sbom_id", ["sbom_id"]),
            ("ix_vex_investigation_component_id", ["component_id"]),
            ("ix_vex_investigation_canonical_vulnerability_id", ["canonical_vulnerability_id"]),
            ("ix_vex_investigation_effective_status", ["effective_status"]),
            ("ix_vex_investigation_reconciliation_status", ["reconciliation_status"]),
            ("ix_vex_investigation_analyzer_detection_state", ["analyzer_detection_state"]),
            ("ix_vex_investigation_effective_vex_statement_id", ["effective_vex_statement_id"]),
            ("ix_vex_investigation_is_current", ["is_current"]),
            ("ix_vex_investigation_first_seen_at", ["first_seen_at"]),
            ("ix_vex_investigation_last_seen_at", ["last_seen_at"]),
            ("ix_vex_investigation_last_analysis_run_id", ["last_analysis_run_id"]),
            ("ix_vex_investigation_assigned_to", ["assigned_to"]),
            ("ix_vex_investigation_queue", ["tenant_id", "is_current", "reconciliation_status"]),
            ("ix_vex_investigation_status", ["tenant_id", "is_current", "effective_status"]),
            ("ix_vex_investigation_sbom_current", ["sbom_id", "is_current"]),
        ):
            op.create_index(name, "vex_investigation", cols)

    _backfill(bind)


def _backfill(bind: sa.engine.Connection) -> None:
    """Populate the new columns for data that predates this migration."""
    if not _table_exists(bind, "vex_statements"):
        return

    # normalized_status + source_status from the legacy status column.
    for status, normalized in _NORMALIZED_BY_STATUS.items():
        bind.execute(
            sa.text(
                "UPDATE vex_statements SET normalized_status = :normalized, "
                "source_status = COALESCE(source_status, :status) "
                "WHERE normalized_status IS NULL AND lower(status) = :status"
            ),
            {"normalized": normalized, "status": status},
        )
    # Anything with an unrecognised legacy status is still a valid context; it
    # is under investigation until someone looks at it.
    bind.execute(
        sa.text(
            "UPDATE vex_statements SET normalized_status = 'UNDER_INVESTIGATION', "
            "source_status = COALESCE(source_status, status) WHERE normalized_status IS NULL"
        )
    )

    # source_format from the owning document; manual overrides have none.
    if _table_exists(bind, "vex_documents"):
        bind.execute(
            sa.text(
                "UPDATE vex_statements SET source_format = lower(d.format) "
                "FROM vex_documents d "
                "WHERE vex_statements.vex_document_id = d.id "
                "AND vex_statements.source_format IS NULL AND d.format IS NOT NULL"
            )
        )
    bind.execute(
        sa.text(
            "UPDATE vex_statements SET source_format = 'manual' "
            "WHERE source_format IS NULL AND vex_document_id IS NULL"
        )
    )

    # source_hash for documents whose raw body survives. Hashed in Python to
    # match app.services.lifecycle.vex_provider.document_source_hash exactly.
    if not _table_exists(bind, "vex_documents"):
        return
    rows = bind.execute(
        sa.text(
            "SELECT id, raw_document_json FROM vex_documents "
            "WHERE source_hash IS NULL AND raw_document_json IS NOT NULL"
        )
    ).fetchall()
    for document_id, raw in rows:
        payload = raw
        if isinstance(payload, (str, bytes)):
            try:
                payload = json.loads(payload)
            except (TypeError, ValueError):
                continue
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        bind.execute(
            sa.text("UPDATE vex_documents SET source_hash = :hash WHERE id = :id"),
            {"hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(), "id": document_id},
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "vex_investigation"):
        op.drop_table("vex_investigation")

    for name in (
        "ix_vex_documents_superseded_by_id",
        "ix_vex_documents_asserted_at",
        "ix_vex_documents_source_hash",
        "ix_vex_documents_source_document_id",
    ):
        if _index_exists(bind, "vex_documents", name):
            op.drop_index(name, table_name="vex_documents")
    for name in ("superseded_by_id", "asserted_at", "source_hash", "source_document_version", "source_document_id"):
        _drop_column(bind, "vex_documents", name)

    for name in ("ix_vex_statements_normalized_status", "ix_vex_statements_source_format"):
        if _index_exists(bind, "vex_statements", name):
            op.drop_index(name, table_name="vex_statements")
    for name in (
        "version_applicable",
        "match_confidence",
        "match_strategy",
        "asserted_at",
        "normalized_status",
        "source_status",
        "source_format",
    ):
        _drop_column(bind, "vex_statements", name)
