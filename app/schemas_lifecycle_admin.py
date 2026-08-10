"""Schemas for lifecycle provider admin APIs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CacheTtlResponse(BaseModel):
    known_days: int | None = None
    unknown_hours: int | None = None
    failure_minutes: int | None = None
    deprecated_days: int | None = None


class LifecycleProviderConfigResponse(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    priority: int
    base_url: str | None = None
    feed_urls: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int
    max_retries: int
    circuit_breaker_enabled: bool
    cache_ttl: CacheTtlResponse
    health_status: Literal["healthy", "degraded", "disabled", "unknown"]
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_failure_message: str | None = None
    has_secret: bool
    secret_preview: str | None = None
    updated_at: str


class LifecycleProviderUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=1000)
    base_url: str | None = Field(default=None, max_length=512)
    feed_urls: list[str] | None = None
    config: dict[str, Any] | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=60)
    max_retries: int | None = Field(default=None, ge=0, le=10)
    circuit_breaker_enabled: bool | None = None
    cache_ttl_known_days: int | None = Field(default=None, ge=1)
    cache_ttl_unknown_hours: int | None = Field(default=None, ge=1)
    cache_ttl_failure_minutes: int | None = Field(default=None, ge=1)
    cache_ttl_deprecated_days: int | None = Field(default=None, ge=1)

    def to_service_payload(self) -> dict[str, Any]:
        data = self.model_dump(exclude_unset=True)
        if "feed_urls" in data:
            data["feed_urls_json"] = data.pop("feed_urls")
        if "config" in data:
            data["config_json"] = data.pop("config")
        return data


class LifecycleProviderSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_name: str = Field(default="api_key", min_length=1, max_length=64)  # nosec B107: secret field name, not a credential value
    secret_value: str = Field(..., min_length=1, max_length=4096)


class LifecycleProviderSecretResponse(BaseModel):
    provider_key: str
    secret_name: str
    value_preview: str | None
    updated_at: str


class LifecycleProviderTestResponse(BaseModel):
    success: bool
    status: str
    latency_ms: int
    message: str
    sample_result: dict[str, Any] | None = None
    checked_at: str


class LifecycleProviderSyncResponse(BaseModel):
    job_id: str | None = None
    status: str
    message: str
    triggered_at: str


class LifecycleVendorRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor_name: str | None = Field(default=None, max_length=128)
    product_name: str | None = Field(default=None, max_length=255)
    product_aliases: list[str] | None = None
    ecosystem: str | None = Field(default=None, max_length=64)
    version_pattern: str | None = Field(default=None, max_length=128)
    version_start: str | None = Field(default=None, max_length=64)
    version_end: str | None = Field(default=None, max_length=64)
    lifecycle_status: str | None = Field(default=None, max_length=64)
    maintenance_status: str | None = Field(default=None, max_length=128)
    eol_date: str | None = None
    eos_date: str | None = None
    eof_date: str | None = None
    deprecated: bool | None = None
    unsupported: bool | None = None
    latest_supported_version: str | None = Field(default=None, max_length=128)
    recommended_version: str | None = Field(default=None, max_length=128)
    evidence_url: str | None = Field(default=None, max_length=512)
    evidence: dict[str, Any] | None = None
    confidence: str | None = Field(default=None, max_length=32)
    enabled: bool | None = None

    @field_validator("eol_date", "eos_date", "eof_date")
    @classmethod
    def validate_date(cls, value: str | None) -> str | None:
        if value in {None, ""}:
            return value
        import datetime as _dt

        try:
            _dt.date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("date must be YYYY-MM-DD") from exc
        return value


class LifecycleVendorRecordResponse(BaseModel):
    id: int
    vendor_name: str
    product_name: str
    product_aliases: list[str] = Field(default_factory=list)
    ecosystem: str | None = None
    version_pattern: str | None = None
    version_start: str | None = None
    version_end: str | None = None
    lifecycle_status: str
    maintenance_status: str | None = None
    eol_date: str | None = None
    eos_date: str | None = None
    eof_date: str | None = None
    deprecated: bool
    unsupported: bool
    latest_supported_version: str | None = None
    recommended_version: str | None = None
    evidence_url: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: str
    enabled: bool
    created_at: str
    updated_at: str


class LifecycleVendorRecordListResponse(BaseModel):
    items: list[LifecycleVendorRecordResponse]
    total: int
    limit: int
    offset: int


class LifecycleVendorRecordImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[dict[str, Any]]


class LifecycleVendorRecordImportResponse(BaseModel):
    created: int
    errors: list[str] = Field(default_factory=list)
