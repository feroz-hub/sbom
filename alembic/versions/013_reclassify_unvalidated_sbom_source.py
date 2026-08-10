"""Reclassify pre-validator legacy ``sbom_source`` rows as ``pending``.

Revision ID: 013_reclassify_unvalidated_sbom_source
Revises: 012_sbom_validation_columns
Create Date: 2026-05-07

Why this exists
---------------
Migration 012 added the validation columns to ``sbom_source`` with
``status`` carrying ``server_default=sa.text("'validated'")`` so the
NOT NULL constraint held when the column was added to existing rows.

That default was correct for *new* rows — the route's ``create_sbom``
always sets ``status`` explicitly after running the 8-stage validator —
but for *existing* rows inserted before commit ``ea80cc7`` (where the
validator was wired into ``create_sbom``) the SQL default fired and
labelled them ``validated``. No validator ever inspected those rows.
The UI then rendered them as "Passed all 8 stages", which contradicted
their other fields (Format: Unknown, Components: 0, Spec version: —).

This migration corrects that. Any row whose ``validated_at`` is NULL
(the unambiguous tell that the validator never ran on it) and whose
status is still the post-012 default ``validated`` is reclassified as
``pending``. The frontend renders ``pending`` as a slate "Validation
pending" badge with a "Run validation" affordance that calls
``POST /api/sboms/{id}/revalidate`` — that endpoint re-runs the
8-stage pipeline against the stored body and updates the row.

Idempotent
----------
The ``WHERE validated_at IS NULL AND status = 'validated'`` predicate
excludes any row that has already been reclassified or has been freshly
validated, so re-running this migration after the first run is a no-op.

No downgrade
------------
``downgrade()`` is intentionally a no-op. Reversing this update would
re-introduce the lie that legacy rows passed validation, which is the
exact bug it's correcting. The recovery path is to call
``POST /api/sboms/{id}/revalidate`` (or simply re-upload), not to
roll the migration back.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "013_reclassify_unvalidated_sbom_source"
down_revision = "012_sbom_validation_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE sbom_source "
            "SET status = 'pending' "
            "WHERE validated_at IS NULL AND status = 'validated'"
        )
    )


def downgrade() -> None:
    # Intentional no-op — see module docstring.
    pass
