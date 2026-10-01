"""Tenant-scoped, paginated administrative audit projections."""

from sqlalchemy import or_, select

from ..models import AuthorizationAuditLog as Audit
from ..models import IAMUser
from .platform_service import _escape_search

CATEGORIES = {
    "membership": (
        "membership.created",
        "membership.updated",
        "membership.removed",
        "membership.activated",
        "membership.deactivated",
        "TENANT_MEMBER_ADDED",
        "TENANT_MEMBER_REMOVED",
        "TENANT_MEMBER_ACTIVATED",
        "TENANT_MEMBER_DEACTIVATED",
    ),
    "role": (
        "ROLE_ASSIGNED",
        "TENANT_ROLE_ASSIGNMENT_GRANTED",
        "TENANT_ROLE_ASSIGNMENT_REVOKED",
        "TENANT_ROLE_SET_REPLACED",
        "TENANT_ROLE_PRIMARY_CHANGED",
        "TENANT_ROLE_ASSIGNMENT_REJECTED",
        "TENANT_ADMIN_RECOVERED",
    ),
    "invitation": (
        "NATIVE_USER_CREATED",
        "NATIVE_ACTIVATION_RESENT",
        "TENANT_INITIAL_ADMIN_INVITED",
        "ACTIVATION_ISSUED",
    ),
    "tenant": ("tenant.status_changed", "TENANT_ENABLED", "TENANT_DISABLED"),
}
ADMIN_ACTIONS = frozenset(
    action for actions in CATEGORIES.values() for action in actions if not action.startswith("membership.")
)

LABELS = {
    "TENANT_MEMBER_ADDED": "Member added",
    "TENANT_MEMBER_REMOVED": "Member removed",
    "TENANT_MEMBER_ACTIVATED": "Membership enabled",
    "TENANT_MEMBER_DEACTIVATED": "Membership disabled",
    "TENANT_ROLE_SET_REPLACED": "Roles changed",
    "TENANT_ROLE_ASSIGNMENT_GRANTED": "Role granted",
    "TENANT_ROLE_ASSIGNMENT_REVOKED": "Role revoked",
    "NATIVE_USER_CREATED": "Invitation created",
}


def page(
    db,
    tenant_id,
    *,
    page=1,
    page_size=25,
    q=None,
    category=None,
    outcome=None,
    from_time=None,
    to_time=None,
    administrative_only=False,
):
    query = db.query(Audit).filter(Audit.tenant_id == tenant_id)
    if administrative_only:
        query = query.filter(Audit.action.in_(ADMIN_ACTIONS))
    if category:
        query = query.filter(Audit.action.in_(CATEGORIES[category]))
    if outcome:
        query = query.filter(Audit.outcome == outcome)
    if from_time:
        query = query.filter(Audit.created_at >= from_time)
    if to_time:
        query = query.filter(Audit.created_at <= to_time)
    if q:
        pattern = f"%{_escape_search(q.strip())}%"
        people = select(IAMUser.id).where(
            or_(IAMUser.email.ilike(pattern, escape="\\"), IAMUser.display_name.ilike(pattern, escape="\\"))
        )
        query = query.filter(
            or_(
                Audit.action.ilike(pattern, escape="\\"),
                Audit.actor_user_id.in_(people),
                Audit.target_user_id.in_(people),
            )
        )
    total = query.count()
    rows = (
        query.order_by(Audit.created_at.desc(), Audit.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    )
    user_ids = {uid for row in rows for uid in (row.actor_user_id, row.target_user_id) if uid is not None}
    users = {user.id: user for user in db.scalars(select(IAMUser).where(IAMUser.id.in_(user_ids)))}
    items = [
        {
            "id": row.id,
            "action": row.action,
            "label": LABELS.get(row.action, row.action.replace(".", " ").replace("_", " ").title()),
            "category": next((name for name, actions in CATEGORIES.items() if row.action in actions), "other"),
            "outcome": row.outcome,
            "actor_user_id": row.actor_user_id,
            "target_user_id": row.target_user_id,
            "actor_email": users[row.actor_user_id].email if row.actor_user_id in users else None,
            "target_email": users[row.target_user_id].email if row.target_user_id in users else None,
            "old_state": row.old_value,
            "new_state": row.new_value,
            "correlation_id": row.correlation_id,
            "timestamp": row.created_at,
        }
        for row in rows
    ]
    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size,
    }
