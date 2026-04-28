"""Pydantic v2 request / response models for the admin router.

Important security note: ``NvdSettingsResponse`` carries a *masked*
representation of the API key — the plaintext NEVER appears on the
HTTP boundary. The masked form looks like ``"abc...xyz"`` (first three
+ last three characters) for keys longer than 8 chars; shorter keys
are reported as ``"***"``. When the key is unset the response shows
``"(not set)"`` and ``api_key_present=False``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from .domain.models import NvdSettingsSnapshot


# ---------------------------------------------------------------------------
# Settings GET / PUT
# ---------------------------------------------------------------------------


def mask_api_key(plaintext: str | None) -> str:
    """Return the human-readable masked form of an API key."""
    if not plaintext:
        return "(not set)"
    if len(plaintext) <= 8:
        return "***"
    return f"{plaintext[:3]}...{plaintext[-3:]}"


class NvdSettingsResponse(BaseModel):
    """Read-side projection — never includes plaintext API key."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    api_endpoint: str
    api_key_masked: str = Field(
        description="Masked form (first3...last3) or '(not set)'. Plaintext never returned."
    )
    api_key_present: bool
    download_feeds_enabled: bool
    page_size: int
    window_days: int
    min_freshness_hours: int
    last_modified_utc: datetime | None
    last_successful_sync_at: datetime | None
    updated_at: datetime

    @classmethod
    def from_snapshot(cls, snap: NvdSettingsSnapshot) -> NvdSettingsResponse:
        return cls(
            enabled=snap.enabled,
            api_endpoint=snap.api_endpoint,
            api_key_masked=mask_api_key(snap.api_key_plaintext),
            api_key_present=bool(snap.api_key_plaintext),
            download_feeds_enabled=snap.download_feeds_enabled,
            page_size=snap.page_size,
            window_days=snap.window_days,
            min_freshness_hours=snap.min_freshness_hours,
            last_modified_utc=snap.last_modified_utc,
            last_successful_sync_at=snap.last_successful_sync_at,
            updated_at=snap.updated_at,
        )


class NvdSettingsUpdate(BaseModel):
    """PATCH-like update payload.

    Tri-state for ``api_key``:
      * field omitted          → preserve existing value
      * ``api_key="..."``      → set to the supplied plaintext
      * ``clear_api_key=True`` → clear the stored ciphertext

    All other fields: omitted → preserve, present → set.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    api_endpoint: HttpUrl | None = None
    api_key: str | None = None
    clear_api_key: bool = False
    download_feeds_enabled: bool | None = None
    page_size: Annotated[int, Field(ge=1, le=2000)] | None = None
    window_days: Annotated[int, Field(ge=1, le=119)] | None = None
    min_freshness_hours: Annotated[int, Field(ge=0, le=24 * 365)] | None = None


# ---------------------------------------------------------------------------
# Sync trigger / status
# ---------------------------------------------------------------------------


class SyncTriggerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    status: Literal["queued"]


class SyncRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    run_kind: Literal["bootstrap", "incremental"]
    window_start: datetime
    window_end: datetime
    started_at: datetime
    finished_at: datetime | None
    status: Literal["running", "success", "failed", "aborted"]
    upserted_count: int
    error_message: str | None
