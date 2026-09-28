"""Shared profile validation for explicit administrator Native enrollment."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .services.identity_service import normalize_email


class NativeInviteProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first_name: str = Field(min_length=1, max_length=120)
    last_name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=1, max_length=320)
    phone: str | None = Field(default=None, max_length=64)

    @field_validator("first_name", "last_name")
    @classmethod
    def nonblank_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("A name without control characters is required")
        return value

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        result = normalize_email(value)
        if not result:
            raise ValueError("Valid email required")
        return result
