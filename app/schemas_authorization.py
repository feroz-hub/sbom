"""API contracts for the global authorization catalogue."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AuthorizationPermissionResponse(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    scope: Literal["PLATFORM", "TENANT"]
    resource: str
    action: str
    status: Literal["ACTIVE", "DISABLED"]
    is_system: bool
    is_protected: bool = False


class AuthorizationRoleSummary(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    scope: Literal["PLATFORM", "TENANT"]
    status: Literal["ACTIVE", "DISABLED", "DRAFT"]
    is_system: bool
    is_assignable: bool
    version: int
    permission_count: int
    created_at: datetime
    updated_at: datetime


class AuthorizationRoleDetail(AuthorizationRoleSummary):
    permissions: list[AuthorizationPermissionResponse]


class AuthorizationRolePage(BaseModel):
    items: list[AuthorizationRoleSummary]
    total: int
    limit: int
    offset: int


class AuthorizationPermissionPage(BaseModel):
    items: list[AuthorizationPermissionResponse]
    total: int
    limit: int
    offset: int


class AuthorizationMatrixResponse(BaseModel):
    roles: list[AuthorizationRoleDetail]


class AuthorizationRoleMetadataUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    status: Literal["ACTIVE", "DISABLED", "DRAFT"] | None = None


class AuthorizationRolePermissionsUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    permission_codes: list[str] = Field(max_length=200)
    change_reason: str | None = Field(default=None, max_length=240)

    @field_validator("permission_codes")
    @classmethod
    def validate_codes(cls, value: list[str]) -> list[str]:
        if any(not code.strip() or len(code.strip()) > 128 for code in value):
            raise ValueError("permission codes must be non-blank and at most 128 characters")
        return value
