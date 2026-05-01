"""Pydantic response schemas for the dashboard endpoints.

Locks the v2 wire format defined in ``docs/dashboard-redesign.md`` §9. The
older endpoints (``/dashboard/stats``, ``/dashboard/severity``) intentionally
keep their untyped dict shape — they're being decommissioned in a follow-up
release per §9.4 of that doc and adding response models now would just
duplicate the contract that's about to disappear.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------


class SeverityCounts(BaseModel):
    """Severity bucket counts in the latest-successful-run-per-SBOM scope.

    ``unknown`` is a *data-quality* signal (no CVSS score in our feeds) and is
    rendered separately in the hero pill — not as a fifth "severity tier."
    See ``docs/terminology.md``.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


# ---------------------------------------------------------------------------
# /dashboard/lifetime — "Your Analyzer, So Far" cumulative panel
# ---------------------------------------------------------------------------


class LifetimeMetrics(BaseModel):
    """Lifetime / cumulative counts. These only go up over time — by design.

    The "Your Analyzer, So Far" panel exists to answer the user's implicit
    question "has the tool been working for me?". Surfacing deltas would
    distract from that story; see ``docs/dashboard-redesign.md`` §6 for the
    rationale and the explicit anti-pattern list.
    """

    sboms_scanned_total: int = 0
    projects_total: int = 0
    runs_executed_total: int = 0
    runs_executed_this_week: int = 0
    # Distinct ``(vuln_id, component_name, component_version)`` tuples ever
    # detected — across all runs, not the latest-successful-run scope. This
    # is intentionally broader than the in-scope KPIs the hero shows.
    findings_surfaced_total: int = 0
    # Findings present in run N but absent from run N+1 of the same SBOM,
    # summed across all consecutive successful run pairs. Expensive query;
    # cached in-process for 15 minutes.
    findings_resolved_total: int = 0
    # ISO-8601 timestamp string (matches the storage format on
    # ``analysis_run.started_on``). ``None`` until the first successful run.
    first_run_at: str | None = None
    days_monitoring: int = 0
    schema_version: int = 1


# ---------------------------------------------------------------------------
# /dashboard/trend — fixed v2 shape (zero-filled, annotations, ref line)
# ---------------------------------------------------------------------------


class TrendDataPoint(BaseModel):
    """One day's severity breakdown. ``unknown`` is first-class in v2 (it
    used to be silently dropped — see ``docs/dashboard-v2-audit.md`` §3.3)."""

    date: str  # YYYY-MM-DD
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total: int = 0


class TrendAnnotation(BaseModel):
    """Event marker overlaid on the trend chart.

    ``count`` lets the frontend stack multiple events on the same day with a
    single ▼ marker that opens to a list when there are more than three.
    """

    date: str  # YYYY-MM-DD
    kind: Literal["sbom_uploaded", "remediation", "kev_first_seen"]
    label: str
    count: int = 1


class FindingsTrendResponse(BaseModel):
    """v2 response shape for ``GET /dashboard/trend``.

    ``points`` is the canonical field; ``series`` is a one-release alias kept
    so the v1 frontend (under feature flag) continues to render until Phase 4
    ships. Both arrays carry the same data — the alias is removed in the
    follow-up cleanup release per the redesign doc §9.2.
    """

    days: int
    points: list[TrendDataPoint] = Field(default_factory=list)
    series: list[TrendDataPoint] = Field(default_factory=list)
    annotations: list[TrendAnnotation] = Field(default_factory=list)
    avg_total: float = 0.0
    earliest_run_date: str | None = None
    schema_version: int = 1


# ---------------------------------------------------------------------------
# /dashboard/posture — extended in v2 with headline_state and primary_action
# ---------------------------------------------------------------------------


HeadlineState = Literal[
    "no_data",
    "clean",
    "kev_present",
    "criticals_no_kev",
    "high_only",
    "low_volume",
]

PrimaryAction = Literal[
    "upload",
    "review_kev",
    "review_critical",
    "view_top_sboms",
]


class DashboardPostureResponse(BaseModel):
    """v2 posture envelope.

    Adds the fields the v2 hero needs to render without a second round-trip:
    ``total_findings``, ``distinct_vulnerabilities`` (previously on
    ``/dashboard/stats``), ``net_7day_*`` (new), and the server-computed
    ``headline_state`` + ``primary_action`` rules. Original fields preserved
    so v1 consumers (sidebar, sparkline) keep working unchanged.
    """

    # Original v1 fields — preserved for back-compat.
    severity: SeverityCounts
    kev_count: int = 0
    fix_available_count: int = 0
    last_successful_run_at: str | None = None
    total_sboms: int = 0
    total_active_projects: int = 0

    # New in v2 — see ``docs/dashboard-redesign.md`` §9.3.
    total_findings: int = 0
    distinct_vulnerabilities: int = 0
    net_7day_added: int = 0
    net_7day_resolved: int = 0
    headline_state: HeadlineState = "no_data"
    primary_action: PrimaryAction = "upload"
    schema_version: int = 1
