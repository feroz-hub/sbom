"""Explicit tenant scopes for trusted test setup; never installed autouse.

The caller selects a tenant from its fixture, which must already exist and be
active in that fixture's database. This grants no application permissions.
"""

from contextlib import contextmanager

from app.core.context import minimal_background_context, tenant_scope
from app.models import Tenant
from sqlalchemy import select


@contextmanager
def verified_fixture_tenant(db, tenant_id):
    if type(tenant_id) is not int or tenant_id <= 0:
        raise ValueError("Fixture tenant must be an explicit positive integer")
    with db.no_autoflush:
        active = db.scalar(select(Tenant.id).where(Tenant.id == tenant_id, Tenant.status == "ACTIVE"))
    if active is None:
        raise ValueError("Fixture tenant must exist and be active")
    with tenant_scope(minimal_background_context(tenant_id)):
        yield


def scoped_context_override(context_provider):
    """Model the production auth dependency's lifetime for a trusted test actor.

    This adds no identity or permissions. Data setup must separately declare
    and verify its owner with verified_fixture_tenant. Request headers and
    task payloads are never consulted to select this mock's actor.
    """
    async def dependency():
        context = context_provider()
        with tenant_scope(context):
            yield context

    return dependency


def declare_fixture_tenant(db, tenant_id, *, name="Other", status="ACTIVE"):
    """Declare test IAM metadata through its mapped table, never raw SQL.

    Test setup only. Existing tenants must match the requested active state;
    this helper neither changes ownership nor supplies application authority.
    """
    from datetime import UTC, datetime

    if type(tenant_id) is not int or tenant_id <= 0:
        raise ValueError("Fixture tenant must be an explicit positive integer")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        now = datetime.now(UTC)
        tenant = Tenant(id=tenant_id, name=name, slug=f"fixture-{tenant_id}",
                        external_iam_tenant_id=f"fixture-{tenant_id}", status=status,
                        created_at=now, updated_at=now)
        db.add(tenant)
        db.flush()
    elif tenant.status != status:
        raise ValueError("Existing fixture tenant status does not match")
    return tenant


def fixture_business_snapshot(db, models, tenant_ids):
    """Exact row snapshots through guarded Core SELECTs, one verified owner at a time.

    Used to prove advisory operations did not mutate either fixture tenant.
    No raw SQL, operator connection or HTTP-controlled table/tenant input.
    """
    result = {}
    for tenant_id in tenant_ids:
        with verified_fixture_tenant(db, tenant_id):
            for model in models:
                table = model.__table__
                rows = db.execute(select(table).order_by(*table.primary_key.columns)
                                  .execution_options(include_deleted=True)).all()
                result[(tenant_id, table.name)] = tuple(tuple(row) for row in rows)
    return result
