"""Domain dataclasses.

Pure value types — no I/O, no SQLAlchemy, no httpx, no Pydantic. The
domain layer must remain importable in any context (including stripped
test environments) without dragging in adapter dependencies.

All datetimes are tz-aware UTC. Construction with naive datetimes is
rejected in __post_init__ so we never silently store ambiguous time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping

# Sentinel — the maximum window NVD's API permits is 120 days; we use
# 119 days as a hard ceiling everywhere to leave headroom for clock skew
# between client and server.
MAX_WINDOW_DAYS: int = 119
_MAX_WINDOW_DELTA: timedelta = timedelta(days=MAX_WINDOW_DAYS)


VulnStatus = Literal[
    "Awaiting Analysis",
    "Undergoing Analysis",
    "Analyzed",
    "Modified",
    "Deferred",
    "Rejected",
    "Received",
    "Unknown",
]


def _ensure_utc(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be tz-aware UTC; got naive datetime {dt!r}")
    if dt.utcoffset() != timedelta(0):
        raise ValueError(
            f"{field_name} must be UTC (offset=0); got {dt.utcoffset()!r}"
        )


@dataclass(frozen=True, slots=True)
class CpeCriterion:
    """One flattened cpeMatch line from NVD's nested configurations.

    Stored alongside the verbatim CVE JSON so a GIN index can pick out
    candidate CVEs by ``criteria_stem`` (vendor:product) before the
    repository performs Python-side version-range refinement.
    """

    criteria: str
    """Full CPE 2.3 string, e.g. 'cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*'."""

    criteria_stem: str
    """Lowercased 'vendor:product' for GIN-friendly candidate filtering."""

    vulnerable: bool

    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


@dataclass(frozen=True, slots=True)
class CveRecord:
    """One CVE as the mirror knows it.

    ``raw`` is the verbatim NVD JSON so the Phase 5 facade can return it
    to legacy callers without reconstructing the original shape.
    """

    cve_id: str
    last_modified: datetime
    published: datetime
    vuln_status: str
    description_en: str | None
    score_v40: float | None
    score_v31: float | None
    score_v2: float | None
    severity_text: str | None
    vector_string: str | None
    aliases: tuple[str, ...]
    cpe_criteria: tuple[CpeCriterion, ...]
    references: tuple[str, ...]
    raw: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.cve_id:
            raise ValueError("cve_id must be non-empty")
        _ensure_utc(self.last_modified, "last_modified")
        _ensure_utc(self.published, "published")


@dataclass(frozen=True, slots=True)
class CveBatch:
    """One paginated response from NVD."""

    records: tuple[CveRecord, ...]
    start_index: int
    results_per_page: int
    total_results: int


@dataclass(frozen=True, slots=True)
class MirrorWindow:
    """Half-open ``[start, end)`` lastModified window.

    Both bounds must be tz-aware UTC. ``end - start`` must be in the
    range ``(0, 119 days]`` — NVD's API rejects windows wider than 120.
    """

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        _ensure_utc(self.start, "start")
        _ensure_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError(f"MirrorWindow.end ({self.end!r}) must be > start ({self.start!r})")
        delta = self.end - self.start
        if delta > _MAX_WINDOW_DELTA:
            raise ValueError(
                f"MirrorWindow span {delta!r} exceeds NVD ceiling of {_MAX_WINDOW_DELTA!r}"
            )


@dataclass(frozen=True, slots=True)
class MirrorWatermark:
    """Last successfully-mirrored lastModified UTC point."""

    last_modified_utc: datetime | None
    last_sync_run_id: int | None

    def __post_init__(self) -> None:
        if self.last_modified_utc is not None:
            _ensure_utc(self.last_modified_utc, "last_modified_utc")


@dataclass(frozen=True, slots=True)
class NvdSettingsSnapshot:
    """In-memory view of the persisted ``nvd_settings`` row.

    ``api_key_plaintext`` is decrypted by the repository on load and
    re-encrypted on save. It is masked or omitted on the API-write
    boundary in Phase 4.
    """

    enabled: bool
    api_endpoint: str
    api_key_plaintext: str | None
    download_feeds_enabled: bool
    page_size: int
    window_days: int
    min_freshness_hours: int
    last_modified_utc: datetime | None
    last_successful_sync_at: datetime | None
    updated_at: datetime

    def __post_init__(self) -> None:
        _ensure_utc(self.updated_at, "updated_at")
        if self.last_modified_utc is not None:
            _ensure_utc(self.last_modified_utc, "last_modified_utc")
        if self.last_successful_sync_at is not None:
            _ensure_utc(self.last_successful_sync_at, "last_successful_sync_at")


@dataclass(frozen=True, slots=True)
class FreshnessVerdict:
    """Result of comparing ``last_successful_sync_at`` to now()."""

    is_fresh: bool
    age_hours: float | None
    last_successful_sync_at: datetime | None


@dataclass(frozen=True, slots=True)
class SyncReport:
    """Outcome of one bootstrap or incremental run."""

    run_kind: Literal["bootstrap", "incremental"]
    started_at: datetime
    finished_at: datetime
    windows_completed: int
    upserts: int
    rejected_marked: int
    errors: tuple[str, ...] = field(default_factory=tuple)
    final_watermark: datetime | None = None

    def __post_init__(self) -> None:
        _ensure_utc(self.started_at, "started_at")
        _ensure_utc(self.finished_at, "finished_at")
        if self.final_watermark is not None:
            _ensure_utc(self.final_watermark, "final_watermark")


def utc_now() -> datetime:
    """Convenience helper — tz-aware UTC ``datetime.now()``."""
    return datetime.now(tz=timezone.utc)
