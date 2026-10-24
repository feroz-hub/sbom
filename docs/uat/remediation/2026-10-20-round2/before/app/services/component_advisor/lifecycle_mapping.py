"""Lifecycle statuses → advisor lifecycle buckets (FR-SCA-001, decision D-6).

The advisor reads lifecycle data that enrichment already persisted on
``SBOMComponent``; it never calls lifecycle providers (NFR-SCA-003) and does
not change the lifecycle implementation (out of scope for this workstream).

The spec's buckets are Supported / Maintenance / EOS / EOL / Unknown. The
lifecycle model has no "Maintenance" status, so D-6 maps the
"still works, winding down" statuses onto it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..lifecycle.types import (
    DEPRECATED,
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    POSSIBLY_UNMAINTAINED,
    SUPPORTED,
    UNSUPPORTED,
    canonical_status,
)


class LifecycleBucket(str, Enum):
    SUPPORTED = "SUPPORTED"
    MAINTENANCE = "MAINTENANCE"
    EOS = "EOS"
    EOL = "EOL"
    UNKNOWN = "UNKNOWN"


_STATUS_TO_BUCKET = {
    SUPPORTED: LifecycleBucket.SUPPORTED,
    EOL_SOON: LifecycleBucket.MAINTENANCE,
    DEPRECATED: LifecycleBucket.MAINTENANCE,
    POSSIBLY_UNMAINTAINED: LifecycleBucket.MAINTENANCE,
    EOS: LifecycleBucket.EOS,
    EOF: LifecycleBucket.EOS,
    EOL: LifecycleBucket.EOL,
    UNSUPPORTED: LifecycleBucket.EOL,
}

#: Buckets the "EOL / EOS Components" KPI counts.
END_OF_LIFE_BUCKETS = frozenset({LifecycleBucket.EOS, LifecycleBucket.EOL})


def lifecycle_bucket(status: str | None) -> LifecycleBucket:
    """Bucket for a raw stored lifecycle status; unknown/null → UNKNOWN."""
    return _STATUS_TO_BUCKET.get(canonical_status(status), LifecycleBucket.UNKNOWN)


@dataclass(frozen=True)
class LifecycleView:
    bucket: LifecycleBucket
    status: str
    effective_date: str | None
    checked_at: str | None
    is_stale: bool
    source: str | None
    manual_override: bool


def _effective_date(status: str, row: Any) -> str | None:
    if status in (EOL, UNSUPPORTED):
        return getattr(row, "eol_date", None)
    if status == EOS:
        return getattr(row, "eos_date", None)
    if status == EOF:
        return getattr(row, "eof_date", None) or getattr(row, "eos_date", None)
    if status == EOL_SOON:
        return getattr(row, "eol_date", None)
    return None


def lifecycle_view(rows: Iterable[Any]) -> LifecycleView:
    """One lifecycle answer for a unique version seen in several SBOMs.

    Occurrences of one version are enriched independently, so they can
    disagree. A manual override wins; otherwise the most recently checked
    occurrence wins (ISO timestamps sort lexically). With no row, UNKNOWN.
    """
    candidates = list(rows)
    if not candidates:
        return LifecycleView(LifecycleBucket.UNKNOWN, "Unknown", None, None, False, None, False)

    def rank(row: Any) -> tuple[int, str]:
        return (1 if getattr(row, "lifecycle_manual_override", False) else 0, getattr(row, "lifecycle_checked_at", None) or "")

    chosen = max(candidates, key=rank)
    status = canonical_status(getattr(chosen, "lifecycle_status", None))
    return LifecycleView(
        bucket=_STATUS_TO_BUCKET.get(status, LifecycleBucket.UNKNOWN),
        status=status,
        effective_date=_effective_date(status, chosen),
        checked_at=getattr(chosen, "lifecycle_checked_at", None),
        is_stale=bool(getattr(chosen, "lifecycle_is_stale", False)),
        source=getattr(chosen, "lifecycle_source", None),
        manual_override=bool(getattr(chosen, "lifecycle_manual_override", False)),
    )


__all__ = ["END_OF_LIFE_BUCKETS", "LifecycleBucket", "LifecycleView", "lifecycle_bucket", "lifecycle_view"]
