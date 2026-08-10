"""SQLAlchemy ORM models for the NVD mirror tables.

Kept separate from ``domain/`` so the domain layer remains pure. The
mirror's ORM rows register against the existing ``app.db.Base``
metadata so ``Base.metadata.create_all`` and Alembic both pick them up
without separate wiring.
"""

from .models import CveRow, NvdSettingsRow, NvdSyncRunRow

__all__ = ["CveRow", "NvdSettingsRow", "NvdSyncRunRow"]
