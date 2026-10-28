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
    assert public_id.version == 4, "Public fixture identity must be UUIDv4"
    return db.execute(select(model).where(model.public_id == public_id)).scalar_one()


def user_uuid(internal_id):
    """Explicit HTTP User fixture identity; internal service assertions stay ints."""
    from app.db import SessionLocal
    from app.models import IAMUser

    with SessionLocal() as db:
        user = db.get(IAMUser, internal_id)
        assert user is not None
        assert user.public_id.version == 4
        return str(user.public_id)


def user_wire_payload(payload):
    """Explicit fixture-only adaptation at HTTP calls, never service inputs.

    Unknown positive fixture keys become fresh nonexistent UUIDs so existing
    not-found tests exercise lookup rather than syntax. Dedicated boundary tests
    deliberately send raw integer inputs and assert 422 without this helper.
    """
    from uuid import uuid4

    from app.db import SessionLocal
    from app.models import IAMUser

    result = dict(payload)
    for key in ("user_id", "initial_admin_user_id"):
        value = result.get(key)
        if isinstance(value, int) and value > 0:
            with SessionLocal() as db:
                user = db.get(IAMUser, value)
                result[key] = str(user.public_id) if user is not None else str(uuid4())
    return result


def resource_uuid(model, internal_id):
    """Explicit fixture boundary for Membership, Grant and Run HTTP selectors."""
    from uuid import uuid4

    from app.db import SessionLocal

    if isinstance(internal_id, str):
        identity = UUID(internal_id)
        assert identity.version == 4
        return str(identity)
    assert type(internal_id) is int and internal_id > 0
    with SessionLocal() as db:
        row = db.execute(select(model.__table__.c.public_id).where(model.__table__.c.id == internal_id)).first()
        # Missing integer fixture keys map to a fresh missing UUID so legacy
        # not-found tests still exercise lookup. Numeric rejection is tested
        # explicitly without this helper in test_public_resource_uuid.py.
        return str(row.public_id) if row is not None else str(uuid4())


def membership_uuid(internal_id):
    from app.models import TenantUser

    return resource_uuid(TenantUser, internal_id)


def grant_uuid(internal_id):
    from app.models import PlatformUserRole

    return resource_uuid(PlatformUserRole, internal_id)


def run_uuid(internal_id):
    from app.models import AnalysisRun

    return resource_uuid(AnalysisRun, internal_id)


def public_membership_key(value):
    """Explicit HTTP fixture form; stored VEX membership keys remain integers."""
    if value is None:
        return None
    if hasattr(value, "public_id"):
        return "membership:" + str(value.public_id)
    assert isinstance(value, str) and value.startswith("membership:")
    return "membership:" + membership_uuid(int(value[11:]) if value[11:].isdigit() else value[11:])
