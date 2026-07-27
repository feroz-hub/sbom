"""Safe response schemas for authenticated identity onboarding."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuthContextUser(BaseModel):
    id: int
    email: str
    display_name: str
    user_principal_name: str
    employee_id: str | None
    department: str | None
    local_status: str
    email_verified: bool
    verification_required: bool


class AuthContextPlatform(BaseModel):
    is_platform_admin: bool
    permissions: list[str]


class AvailableTenant(BaseModel):
    id: int
    name: str
    slug: str
    membership_status: str | None
    current_role: str | None
    primary_role: str | None = None
    roles: list[str] = Field(default_factory=list)
    role_assignment_version: int | None = None
    effective_permissions: list[str]


class AuthTenantContext(BaseModel):
    selection_required: bool
    selection_source: str | None
    active_tenant: AvailableTenant | None
    available_tenants: list[AvailableTenant]


class AuthContextSupport(BaseModel):
    platform_admin_email: str | None


class VerificationContext(BaseModel):
    delivery_status: str | None
    last_sent_at: str | None
    resend_available_at: str | None
    expires_at: str | None


class AuthContextResponse(BaseModel):
    status: str
    next_action: str
    user: AuthContextUser
    platform: AuthContextPlatform
    tenant_context: AuthTenantContext
    support: AuthContextSupport
    verification: VerificationContext | None = None
