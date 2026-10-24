"""Explicit UUID wire identity to integer ORM-key boundary for integration assertions."""
from uuid import UUID

from sqlalchemy import select


def public_row(db, model, identity):
    public_id = UUID(str(identity))
    assert public_id.version == 4, 'Public fixture identity must be UUIDv4'
    return db.execute(select(model).where(model.public_id == public_id)).scalar_one()
