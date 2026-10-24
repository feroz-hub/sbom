"""Explicit authenticated test actors resolved from the existing database RBAC.

No application grants, catalog overrides or request-controlled authority are added.
"""

from app.core.security import _resolve_context

from tests.phase6_helpers import identity_claims, seed_membership, seed_user
from tests.tenant_fixture_scope import verified_fixture_tenant


def tenant_actor_from_database(db, role, *, tenant_id=1):
    with verified_fixture_tenant(db, tenant_id):
        user = seed_user(db, display_name=f"Batch C {role}")
        membership = seed_membership(db, user, tenant_id=tenant_id, role=role)
        db.commit()
        claims = identity_claims(user)
        user_id = user.id
        assert membership.status == "ACTIVE"
        context = _resolve_context(db, claims, str(tenant_id))
        assert context.user_id == user_id and context.tenant_id == tenant_id
        assert role in context.roles and not context.is_platform_admin
        return context


def authenticated_actor_label(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 200, response.text
    identity = response.json()
    assert identity["authenticated"] is True
    return identity["email"] or identity["external_user_id"] or str(identity["user_id"])
