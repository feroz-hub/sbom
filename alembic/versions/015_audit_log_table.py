"""Add general-purpose audit_log table.

Revision ID: 015_audit_log_table
Revises: 014_add_soft_delete_columns
Create Date: 2026-05-07

Why this exists
---------------
Phase 1 audit found that the codebase had no general-purpose audit
table — only ``ai_credential_audit_log`` (security-specific). The
soft-delete refactor needs a durable record of which user soft-deleted,
permanent-deleted, or restored which record, so admins can answer
"what happened to project X" after the fact.

Schema choice — additive, not a rename
--------------------------------------
The Phase 1 audit recommended option (A): repurpose
``ai_credential_audit_log`` as a generic audit log via a rename. After
re-evaluation we ship option (B) — add a new ``audit_log`` table, keep
the credentials audit pipeline untouched. Reasons:

* The credentials audit module ships strict regex redaction
  (``app/ai/credential_audit.py:84-101``). Generalising the helper
  risks accidentally widening that redaction policy or, worse, dropping
  it when callers pass non-credential payloads.
* Two tables makes retention and access-control policies simpler:
  the security audit can be locked down separately from the
  lifecycle audit.
* Cleaner rollback story — adding a table is reversible without
  data motion; renaming with consumers in flight is not.

Idempotency: existence-checked, mirrors prior migrations.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "015_audit_log_table"
down_revision = "014_add_soft_delete_columns"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, table: str) -> bool:
    return table in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind, "audit_log"):
        return

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.String(length=128), nullable=True),
        sa.Column("action", sa.String(length=48), nullable=False),
        sa.Column("target_kind", sa.String(length=24), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=True),
        sa.Column("detail", sa.String(length=240), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_target_kind", "audit_log", ["target_kind"])
    op.create_index("ix_audit_log_target_id", "audit_log", ["target_id"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind, "audit_log"):
        return
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_index("ix_audit_log_target_id", table_name="audit_log")
    op.drop_index("ix_audit_log_target_kind", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_table("audit_log")
