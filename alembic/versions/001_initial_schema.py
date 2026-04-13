"""Initial schema (bootstrap via SQLAlchemy metadata).

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-04-13

"""

from __future__ import annotations

from alembic import op

import app.models  # noqa: F401
from app.db import Base

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
