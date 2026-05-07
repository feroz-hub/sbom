"""ORM mixins shared across model classes.

``SoftDeleteMixin`` adds the three columns every soft-delete-eligible
table needs: ``is_active``, ``deactivated_at``, and ``deactivated_by``.

Naming choice — ``is_active`` rather than ``is_deleted``
--------------------------------------------------------
Default-true is more intuitive than default-false-meaning-deleted: a row
that forgets to set the column lands in the "live" state, which is the
recoverable failure mode. Filter clauses also read more naturally
(``WHERE is_active``) and align with the convention used by
``Projects.project_status`` (1 = active, 0 = inactive) that already
exists in this codebase.

Naming choice — ``deactivated_by`` (String) not ``deactivated_by_user_id``
--------------------------------------------------------------------------
The codebase has no ``user`` table; identity is carried as the
header-trusted ``created_by`` / ``modified_by`` strings on every model.
Pairing ``deactivated_by`` (String) keeps the soft-delete attribution
identical in shape to existing audit fields, and avoids inventing an FK
that would dangle. When a real users table is introduced this column
can be migrated to FK without breaking the mixin contract.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.sql import expression


class SoftDeleteMixin:
    """Adds soft-delete fields to a model.

    Apply by adding the mixin to the model's MRO ahead of ``Base``::

        class Projects(Base, SoftDeleteMixin):
            __tablename__ = "projects"
            ...

    ``server_default=sa.true()`` lets ``Base.metadata.create_all`` produce
    a CREATE TABLE statement that mirrors the Alembic migration's
    ``ADD COLUMN ... DEFAULT TRUE``, so dev databases bootstrapped via
    the startup hook end up with the same NOT NULL safety net as
    production migrations install.
    """

    # ``sa.true()`` is dialect-aware (renders ``TRUE`` on Postgres, ``1``
    # on SQLite) and matches the pattern already used by migration 002.
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default=expression.true(),
    )
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    deactivated_by = Column(String(128), nullable=True)


__all__ = ["SoftDeleteMixin"]
