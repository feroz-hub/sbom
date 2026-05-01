"""Shared types and constants for the metrics layer.

Kept tiny — anything that's actually a query goes in a domain module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..services.analysis_service import SUCCESSFUL_RUN_STATUSES

# Re-export under a name that matches the spec ("completed" reads more
# clearly outside the routing layer than "successful").
COMPLETED_RUN_STATUSES = SUCCESSFUL_RUN_STATUSES

KevScope = Literal["run", "latest_per_sbom"]

SEVERITY_KEYS: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")


@dataclass(frozen=True)
class NetChangeResult:
    """Result of ``findings.net_change(window_days)`` per spec §3.7.

    ``is_first_period`` is the lock for Bug 5: when no successful run completed
    strictly before ``today − window_days``, the comparison is undefined and
    the FE renders "first scan this week" instead of ``+N / −0``.
    """

    added: int
    resolved: int
    is_first_period: bool
    window_days: int


@dataclass(frozen=True)
class TrendPoint:
    """One day of the daily-distinct-active series. Severity values are
    distinct ``(vuln_id, component_name, component_version)`` tuples in the
    latest successful run of each SBOM as-of-end-of-day, grouped by severity.
    """

    date: str  # YYYY-MM-DD
    critical: int
    high: int
    medium: int
    low: int
    unknown: int
    total: int
