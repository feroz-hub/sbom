"""Explicit, redacted schemas for centralized platform administration."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PlatformUserSummary(BaseModel):
    id: int
    email: str | None
    display_name: str | None
    user_principal_name: str | None
    employee_id: str | None
    department: str | None
    local_status: str
    email_verified: bool
    verification_required: bool
    is_platform_admin: bool
    platform_grant_status: str | None
    active_tenant_count: int
    created_at: datetime
    last_login_at: datetime | None


class PlatformTenantMembershipSummary(BaseModel):
    tenant_id: int
    tenant_name: str
    tenant_slug: str
    membership_status: str
    current_role: str
    tenant_status: str


class PlatformGrantSummary(BaseModel):
    grant_id: int
    user_id: int
    email: str | None
    display_name: str | None
    local_status: str
    email_verified: bool
    verification_required: bool
    role: str
    grant_status: str
    is_effective: bool
    created_at: datetime
    created_by_user_id: int | None
    updated_at: datetime


class PlatformUserDetail(PlatformUserSummary):
    platform_grant: PlatformGrantSummary | None
    tenant_memberships: list[PlatformTenantMembershipSummary]


class PlatformUserPage(BaseModel):
    items: list[PlatformUserSummary]
    page: int
    page_size: int
    total: int
    total_pages: int


class PlatformAdministratorPage(BaseModel):
    items: list[PlatformGrantSummary]
    page: int
    page_size: int
    total: int
    total_pages: int


class PlatformAdministratorGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: int | None = Field(default=None, ge=1)
    external_user_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Deprecated exact-subject compatibility selector.",
    )

    @model_validator(mode="after")
    def require_exactly_one_selector(self):
        if (self.user_id is None) == (self.external_user_id is None):
            raise ValueError("Provide exactly one of user_id or external_user_id")
        if self.external_user_id is not None:
            self.external_user_id = self.external_user_id.strip()
        return self


class PlatformAdministratorGrantResponse(PlatformGrantSummary):
    action: Literal["CREATED", "REACTIVATED", "EXISTING"]


class PlatformAdministratorRevokeResponse(BaseModel):
    action: Literal["REVOKED", "ALREADY_INACTIVE"]
    administrator: PlatformGrantSummary


class PlatformUserStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ACTIVE", "DISABLED"]
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def normalize_reason(self):
        if self.reason is not None:
            self.reason = self.reason.strip() or None
        return self


class PlatformUserStatusResponse(BaseModel):
    user_id: int
    old_status: str
    status: str
    changed: bool
    verification_required: bool
    email_verified: bool
    verification_delivery_status: str | None = None
