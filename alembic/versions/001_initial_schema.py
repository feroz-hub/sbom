"""Initial schema (bootstrap via SQLAlchemy metadata).

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-04-13

"""

from __future__ import annotations

from alembic import op

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Load database-backed metadata only when executing the migration.
    import app.models  # noqa: F401
    from app.db import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    import app.models  # noqa: F401
    from app.db import Base

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
