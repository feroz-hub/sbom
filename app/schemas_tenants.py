"""Public request and response contracts for atomic tenant creation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TenantCreateRequest(BaseModel):
    """Syntax-only contract; domain normalization lives in tenant_service."""

    model_config = ConfigDict(extra="forbid")

    name: str
    slug: str
    external_iam_tenant_id: str | None = None
    # Optional at schema level so the router can return the stable Phase 7
    # machine code instead of Pydantic's generic missing-field response.
    initial_admin_user_id: int | None = None


class CreatedTenantResponse(BaseModel):
    id: int
    name: str
    slug: str
    external_iam_tenant_id: str | None
    identity_mapping: dict | None = None
    status: str
    created_at: datetime
    updated_at: datetime


class InitialTenantAdministratorResponse(BaseModel):
    user_id: int
    email: str | None
    display_name: str | None
    membership_status: str
    role: str


class TenantCreationResponse(BaseModel):
    tenant: CreatedTenantResponse
    initial_administrator: InitialTenantAdministratorResponse
