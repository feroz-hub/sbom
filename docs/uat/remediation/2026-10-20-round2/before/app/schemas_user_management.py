"""Allowlisted profile edits; identity and email changes are separate flows."""

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    first_name: str | None = Field(default=None, min_length=1, max_length=120)
    last_name: str | None = Field(default=None, min_length=1, max_length=120)
    phone: str | None = Field(default=None, max_length=64)

    @field_validator("first_name", "last_name", "phone")
    @classmethod
    def validate_text(cls, value, info):
        if value is None:
            return value
        value = value.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not permitted")
        if info.field_name == "phone":
            if value and not re.fullmatch(r"\+?[0-9() .-]{3,64}", value):
                raise ValueError("Invalid phone format")
        elif not value:
            raise ValueError("Name cannot be blank")
        return value

    @model_validator(mode="after")
    def nonempty(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one profile field")
        return self
