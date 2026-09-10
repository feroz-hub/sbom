"""Same authorization policy at subscription, preview, dispatch and download."""

from fastapi import HTTPException
from sqlalchemy import or_, select

from ..core.context import CurrentContext
from ..core.permissions import normalize_role
from ..models import IAMUser, Product, Projects, SBOMSource, Tenant, TenantUser
from .tenant_role_assignment_service import effective_permissions, effective_role_codes


def report_error(code, message, status=403):
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def is_report_admin(context):
    return context.is_platform_admin or "TENANT_ADMIN" in {normalize_role(r) for r in context.roles}


def recipient_context(db, subscription):
    """Never reuse JWT claims or a stale email recorded in the delivery ledger."""
    user = db.get(IAMUser, subscription.iam_user_id)
    tenant = db.get(Tenant, subscription.tenant_id)
    member = db.scalar(
        select(TenantUser).where(
            TenantUser.tenant_id == subscription.tenant_id,
            TenantUser.user_id == subscription.iam_user_id,
            TenantUser.status == "ACTIVE",
        )
    )
    if not user or user.status != "ACTIVE" or not user.email_verified or user.verification_required or not user.email:
        raise report_error("RECIPIENT_NOT_VERIFIED", "The account must be active with a verified email address.")
    if not tenant or tenant.status != "ACTIVE" or not member:
        raise report_error("MEMBERSHIP_REVOKED", "Active tenant membership is required.")
    roles = effective_role_codes(db, member, actor_user_id=user.id)
    permissions = effective_permissions(db, member, actor_user_id=user.id)
    return CurrentContext(
        user.id,
        user.external_iam_user_id,
        user.email,
        user.display_name,
        tenant.id,
        tenant.external_iam_tenant_id,
        roles,
        permissions,
    )


def authorize_preferences(db, preferences, context):
    if context.tenant_id is None:
        raise report_error("TENANT_REQUIRED", "Select a tenant first.")
    if not {"sbom:read", "analysis:read", "project:read", "product:read"} <= context.permissions:
        raise report_error("REPORT_READ_REVOKED", "Read access to the report scope is required.")
    if preferences.scope == "TENANT" and not {"TENANT_ADMIN", "SECURITY_ANALYST"} & {
        normalize_role(r) for r in context.roles
    }:
        raise report_error(
            "TENANT_REPORT_ROLE_REQUIRED", "Tenant reports require tenant admin or security analyst membership."
        )
    targets = [(Projects, preferences.project_id), (Product, preferences.product_id), (SBOMSource, preferences.sbom_id)]
    for model, identifier in targets:
        if (
            identifier is not None
            and db.scalar(select(model.id).where(model.id == identifier, model.tenant_id == context.tenant_id)) is None
        ):
            raise report_error("REPORT_SCOPE_NOT_FOUND", "Report scope is unavailable in this tenant.", 404)


def scope_sboms(db, preferences, tenant_id):
    """Latest-state broad scopes include active heads, not historical versions twice."""
    project_ids = select(Projects.id).where(Projects.tenant_id == tenant_id, Projects.is_active.is_(True))
    product_ids = select(Product.id).where(
        Product.tenant_id == tenant_id,
        Product.is_active.is_(True),
        or_(Product.project_id.is_(None), Product.project_id.in_(project_ids)),
    )
    query = select(SBOMSource).where(
        SBOMSource.tenant_id == tenant_id,
        or_(SBOMSource.projectid.is_(None), SBOMSource.projectid.in_(project_ids)),
        or_(SBOMSource.product_id.is_(None), SBOMSource.product_id.in_(product_ids)),
    )
    if preferences.scope == "SBOM":
        query = query.where(SBOMSource.id == preferences.sbom_id)
    else:
        child_parents = select(SBOMSource.parent_id).where(
            SBOMSource.tenant_id == tenant_id, SBOMSource.is_active.is_(True), SBOMSource.parent_id.is_not(None)
        )
        query = query.where(SBOMSource.id.not_in(child_parents))
        if preferences.scope == "PROJECT":
            query = query.where(SBOMSource.projectid == preferences.project_id)
        if preferences.scope == "PRODUCT":
            query = query.where(SBOMSource.product_id == preferences.product_id)
    return list(db.scalars(query.order_by(SBOMSource.id)))
