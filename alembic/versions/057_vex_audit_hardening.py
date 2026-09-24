"""VEX audit hardening: queryable statuses, SBOM link, unresolved actions.

Revision ID: 057_vex_audit_hardening
Revises: 056_vex_investigation
Create Date: 2026-09-24

PR-6 of the VEX Dashboard & Investigation workstream (VEX-AUD-001, spec
section 40). Three gaps in ``vex_override_audit``:

* previous and new status existed only inside the JSON blobs, so "who set
  this to AFFECTED and when" needed a JSON scan rather than a query;
* there was no ``sbom_id``, and for an unresolved mapping it cannot be
  derived from the component;
* ``component_id`` was NOT NULL, which made an action on an unresolved
  mapping impossible to audit at all — precisely the action PR-6 adds.

Backfill fills ``sbom_id`` from the component where one exists, and lifts
``previous_status`` / ``new_status`` out of the existing JSON. Rows whose
blobs do not carry a status keep NULLs; that is honest, not a failure.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "057_vex_audit_hardening"
down_revision = "056_vex_investigation"
branch_labels = None
depends_on = None

TABLE = "vex_override_audit"


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


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, TABLE):
        return

    existing = _columns(bind, TABLE)
    for column in (
        sa.Column("sbom_id", sa.Integer(), nullable=True),
        sa.Column("investigation_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False, server_default="DECISION"),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=True),
    ):
        if column.name not in existing:
            op.add_column(TABLE, column)

    # An unresolved mapping has no component, and binding it to one is an
    # audited action taken while component_id is still NULL.
    op.alter_column(TABLE, "component_id", existing_type=sa.Integer(), nullable=True)

    for name, cols in (
        ("ix_vex_override_audit_sbom_id", ["sbom_id"]),
        ("ix_vex_override_audit_investigation_id", ["investigation_id"]),
        ("ix_vex_override_audit_action", ["action"]),
    ):
        if not _index_exists(bind, TABLE, name):
            op.create_index(name, TABLE, cols)

    # Foreign keys are created separately so a partially-migrated database
    # cannot leave a column without its constraint.
    inspector = sa.inspect(bind)
    fk_names = {fk.get("name") for fk in inspector.get_foreign_keys(TABLE)}
    if "fk_vex_override_audit_sbom_id_sbom_source" not in fk_names:
        op.create_foreign_key(
            "fk_vex_override_audit_sbom_id_sbom_source",
            TABLE, "sbom_source", ["sbom_id"], ["id"], ondelete="CASCADE",
        )
    if _table_exists(bind, "vex_investigation") and (
        "fk_vex_override_audit_investigation_id_vex_investigation" not in fk_names
    ):
        op.create_foreign_key(
            "fk_vex_override_audit_investigation_id_vex_investigation",
            TABLE, "vex_investigation", ["investigation_id"], ["id"], ondelete="SET NULL",
        )

    _backfill(bind)


def _backfill(bind: sa.engine.Connection) -> None:
    bind.execute(
        sa.text(
            "UPDATE vex_override_audit SET sbom_id = c.sbom_id "
            "FROM sbom_component c "
            "WHERE vex_override_audit.component_id = c.id "
            "AND vex_override_audit.sbom_id IS NULL"
        )
    )
    # Lift the statuses out of the JSON so they become queryable. Postgres
    # ->> yields NULL for a missing key, which is the honest result for rows
    # whose blobs never carried a status.
    for column, source in (("previous_status", "old_value_json"), ("new_status", "new_value_json")):
        bind.execute(
            sa.text(
                f"UPDATE vex_override_audit SET {column} = upper({source} ->> 'status') "
                f"WHERE {column} IS NULL AND {source} IS NOT NULL"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, TABLE):
        return

    inspector = sa.inspect(bind)
    fk_names = {fk.get("name") for fk in inspector.get_foreign_keys(TABLE)}
    for name in (
        "fk_vex_override_audit_investigation_id_vex_investigation",
        "fk_vex_override_audit_sbom_id_sbom_source",
    ):
        if name in fk_names:
            op.drop_constraint(name, TABLE, type_="foreignkey")

    for name in (
        "ix_vex_override_audit_action",
        "ix_vex_override_audit_investigation_id",
        "ix_vex_override_audit_sbom_id",
    ):
        if _index_exists(bind, TABLE, name):
            op.drop_index(name, table_name=TABLE)

    existing = _columns(bind, TABLE)
    for name in ("new_status", "previous_status", "action", "investigation_id", "sbom_id"):
        if name in existing:
            op.drop_column(TABLE, name)

    # Restoring NOT NULL would fail against rows audited on an unresolved
    # mapping, so those are removed first — they can only exist because this
    # migration allowed them.
    bind.execute(sa.text("DELETE FROM vex_override_audit WHERE component_id IS NULL"))
    op.alter_column(TABLE, "component_id", existing_type=sa.Integer(), nullable=False)
