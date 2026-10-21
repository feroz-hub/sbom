"""Explicit UUID wire identity to integer ORM-key boundary for integration assertions."""
from uuid import UUID

from sqlalchemy import select


def tenant_uuid(internal_id):
    """Read a fixture tenant's public identity; IAM and membership IDs stay integers.

    Tenant is a global authorization resource. This helper does not translate
    requests or bypass tenant-scoped business-record guards.
    """
    from app.db import SessionLocal
    from app.models import Tenant

    with SessionLocal() as db:
        tenant = db.get(Tenant, internal_id)
        assert tenant is not None
        identity = tenant.public_id
        assert identity.version == 4
        return str(identity)


def public_row(db, model, identity):
    public_id = UUID(str(identity))
    assert public_id.version == 4, 'Public fixture identity must be UUIDv4'
    return db.execute(select(model).where(model.public_id == public_id)).scalar_one()
