"""Deterministic local authorization/onboarding state resolution."""

from __future__ import annotations

from dataclasses import dataclass
import logging

from fastapi import Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..core.identity_states import (
    AuthorizationState,
    IdentityAuditEvent,
    IdentityErrorCode,
    NextAction,
    identity_http_error,
)
from ..models import IAMUser, Tenant, TenantUser
from ..schemas_identity import (
    AuthContextPlatform,
    AuthContextResponse,
    AuthContextSupport,
    AuthContextUser,
    AuthTenantContext,
    AvailableTenant,
)
from ..settings import get_settings
from . import (
    audit_service,
    authorization_catalog_service,
    platform_service,
    tenant_role_assignment_service,
    tenant_service,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ResolvedAuthorizationState:
    status: AuthorizationState
    next_action: NextAction
    user: IAMUser
    is_platform_admin: bool
    platform_permissions: frozenset[str]
    memberships: tuple[tuple[TenantUser, Tenant], ...]
    active_tenant: Tenant | None = None
    active_membership: TenantUser | None = None
    selection_source: str | None = None

    @property
    def selection_required(self) -> bool:
        return self.status == AuthorizationState.TENANT_SELECTION_REQUIRED


def _audit_state(
    db: Session,
    *,
    event: IdentityAuditEvent,
    user: IAMUser,
    request: Request | None,
    outcome: str = "SUCCESS",
    tenant_id: int | None = None,
    reason_code: str | None = None,
    status: AuthorizationState | None = None,
) -> None:
    value = {"target_type": "IAM_USER"}
    if reason_code:
        value["reason_code"] = reason_code
    if status:
        value["authorization_state"] = str(status)
    audit_service.write_authorization_audit(
        db,
        action=str(event),
        outcome=outcome,
        actor_user_id=user.id,
        target_user_id=user.id,
        tenant_id=tenant_id,
        request=request,
        new_value=value,
        detail=reason_code,
    )


def _tenant_matches(tenant: Tenant, value: str) -> bool:
    return value in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}


def resolve_authorization_state(
    db: Session,
    user: IAMUser,
    *,
    selected_tenant: str | None = None,
    selector_hint: str | None = None,
    allow_platform_context: bool = True,
    request: Request | None = None,
    audit_resolution: bool = False,
) -> ResolvedAuthorizationState:
    """Resolve authorization state in the required security precedence."""
    requested = (selected_tenant or "").strip()
    hinted = (selector_hint or "").strip()

    if user.status == "DISABLED":
        result = ResolvedAuthorizationState(
            AuthorizationState.ACCOUNT_DISABLED,
            NextAction.CONTACT_SUPPORT,
            user,
            False,
            frozenset(),
            (),
        )
    elif user.status == "PENDING":
        result = ResolvedAuthorizationState(
            AuthorizationState.ACCOUNT_PENDING_APPROVAL,
            NextAction.WAIT_FOR_APPROVAL,
            user,
            False,
            frozenset(),
            (),
        )
    elif not user.email_verified or user.verification_required:
        result = ResolvedAuthorizationState(
            AuthorizationState.VERIFICATION_REQUIRED,
            NextAction.VERIFY_EMAIL,
            user,
            False,
            frozenset(),
            (),
        )
    else:
        is_platform_admin = (
            platform_service.get_effective_platform_grant(db, user) is not None
        )
        platform_permissions = (
            authorization_catalog_service.resolve_permissions_for_roles(
                db,
                frozenset({"PLATFORM_ADMIN"}),
                actor_user_id=user.id,
                request=request,
            )
            if is_platform_admin
            else frozenset()
        )
        memberships = tuple(tenant_service.get_user_memberships(db, user.id))
        selected: Tenant | None = None
        membership: TenantUser | None = None
        selection_source: str | None = None

        if requested:
            for member, tenant in memberships:
                if _tenant_matches(tenant, requested):
                    selected, membership = tenant, member
                    break
            if selected is None and is_platform_admin:
                selected = db.execute(
                    select(Tenant).where(
                        Tenant.status == "ACTIVE",
                        or_(
                            Tenant.slug == requested,
                            Tenant.external_iam_tenant_id == requested,
                            Tenant.id == int(requested) if requested.isdigit() else False,
                        ),
                    )
                ).scalar_one_or_none()
            if selected is None:
                _audit_state(
                    db,
                    event=IdentityAuditEvent.UNAUTHORIZED_TENANT_SELECTION,
                    user=user,
                    request=request,
                    outcome="DENIED",
                    reason_code=str(IdentityErrorCode.UNAUTHORIZED_TENANT),
                )
                raise identity_http_error(
                    IdentityErrorCode.UNAUTHORIZED_TENANT,
                    "The requested tenant is not available to this account.",
                )
            selection_source = "HEADER"
        if selected is not None:
            roles = {membership.role} if membership else set()
            if is_platform_admin:
                roles.add("PLATFORM_ADMIN")
            result = ResolvedAuthorizationState(
                AuthorizationState.READY,
                NextAction.OPEN_DASHBOARD,
                user,
                is_platform_admin,
                platform_permissions,
                memberships,
                selected,
                membership,
                selection_source,
            )
        elif is_platform_admin and allow_platform_context:
            result = ResolvedAuthorizationState(
                AuthorizationState.READY,
                NextAction.OPEN_PLATFORM_ADMIN,
                user,
                True,
                platform_permissions,
                memberships,
            )
        elif not memberships:
            result = ResolvedAuthorizationState(
                AuthorizationState.NO_TENANT,
                NextAction.CONTACT_ADMIN,
                user,
                is_platform_admin,
                platform_permissions,
                memberships,
            )
            _audit_state(
                db,
                event=IdentityAuditEvent.NO_TENANT,
                user=user,
                request=request,
                reason_code=str(IdentityErrorCode.NO_TENANT),
                status=result.status,
            )
        elif len(memberships) == 1:
            membership, selected = memberships[0]
            result = ResolvedAuthorizationState(
                AuthorizationState.READY,
                NextAction.OPEN_DASHBOARD,
                user,
                is_platform_admin,
                platform_permissions,
                memberships,
                selected,
                membership,
                "AUTO_SINGLE",
            )
        else:
            result = ResolvedAuthorizationState(
                AuthorizationState.TENANT_SELECTION_REQUIRED,
                NextAction.SELECT_TENANT,
                user,
                is_platform_admin,
                platform_permissions,
                memberships,
            )
            _audit_state(
                db,
                event=IdentityAuditEvent.TENANT_SELECTION_REQUIRED,
                user=user,
                request=request,
                reason_code=str(IdentityErrorCode.TENANT_SELECTION_REQUIRED),
                status=result.status,
            )

        if (
            hinted
            and result.active_tenant
            and not _tenant_matches(result.active_tenant, hinted)
        ):
            log.info(
                "identity.tenant_hint_mismatch user_id=%s selected_tenant_id=%s",
                user.id,
                result.active_tenant.id,
            )

    if audit_resolution:
        _audit_state(
            db,
            event=IdentityAuditEvent.AUTH_CONTEXT_RESOLVED,
            user=user,
            request=request,
            tenant_id=result.active_tenant.id if result.active_tenant else None,
            status=result.status,
        )
    return result


def _available_tenant(
    db: Session,
    tenant: Tenant,
    membership: TenantUser | None,
    *,
    is_platform_admin: bool,
) -> AvailableTenant:
    roles = (
        set(
            tenant_role_assignment_service.effective_role_codes(
                db,
                membership,
                actor_user_id=membership.user_id,
            )
        )
        if membership
        else set()
    )
    permissions = (
        set(
            tenant_role_assignment_service.effective_permissions(
                db,
                membership,
                actor_user_id=membership.user_id,
            )
        )
        if membership
        else set()
    )
    if is_platform_admin:
        permissions.update(
            authorization_catalog_service.resolve_permissions_for_roles(
                db,
                frozenset({"PLATFORM_ADMIN"}),
                actor_user_id=membership.user_id if membership else None,
            )
        )
    return AvailableTenant(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        membership_status=membership.status if membership else None,
        current_role=membership.role if membership else "PLATFORM_ADMIN",
        primary_role=membership.role if membership else "PLATFORM_ADMIN",
        roles=sorted(roles | ({"PLATFORM_ADMIN"} if is_platform_admin else set())),
        role_assignment_version=(
            membership.role_assignment_version if membership else None
        ),
        effective_permissions=sorted(permissions),
    )


def build_auth_context_response(
    state: ResolvedAuthorizationState,
    *,
    db: Session | None = None,
) -> AuthContextResponse:
    user = state.user
    if db is None:
        raise ValueError("database session is required to build authorization context")
    available = [
        _available_tenant(
            db,
            tenant,
            membership,
            is_platform_admin=state.is_platform_admin,
        )
        for membership, tenant in state.memberships
    ]
    active = (
        _available_tenant(
            db,
            state.active_tenant,
            state.active_membership,
            is_platform_admin=state.is_platform_admin,
        )
        if state.active_tenant
        else None
    )
    settings = get_settings()
    verification = None
    if db is not None:
        from .email_verification_service import verification_context

        verification = verification_context(db, user)
    return AuthContextResponse(
        status=str(state.status),
        next_action=str(state.next_action),
        user=AuthContextUser(
            id=user.id,
            email=user.email or "",
            display_name=user.display_name or "",
            user_principal_name=user.user_principal_name or "",
            employee_id=user.employee_id,
            department=user.department,
            local_status=user.status,
            email_verified=bool(user.email_verified),
            verification_required=bool(user.verification_required),
        ),
        platform=AuthContextPlatform(
            is_platform_admin=state.is_platform_admin,
            permissions=sorted(state.platform_permissions),
        ),
        tenant_context=AuthTenantContext(
            selection_required=state.selection_required,
            selection_source=state.selection_source,
            active_tenant=active,
            available_tenants=available,
        ),
        support=AuthContextSupport(
            platform_admin_email=settings.platform_admin_contact_email or None,
        ),
        verification=verification,
    )
