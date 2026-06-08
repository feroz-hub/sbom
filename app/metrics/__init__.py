"""Canonical dashboard metrics — the single source of truth.

Every numeric field rendered on the dashboard, run-detail, or lifetime
surface MUST be backed by a function in this module. Inline SQL for metrics
in router files is forbidden; see [docs/dashboard-metrics-spec.md] §8.

Module organisation matches the spec catalog:

* ``findings``  — per-run, latest-state, lifetime, daily-distinct
* ``kev``       — single canonical KEV-membership metric (parameterised scope)
* ``epss``      — high-EPSS ("likely exploited") count (parameterised scope)
* ``quality``   — needs-review / not-verified match count (parameterised scope)
* ``runs``      — run counts, distinct-dates, first-completed
* ``windows``   — added/resolved/net change over time windows
* ``sboms``     — portfolio counts (sbom, project)

Helpers (``_helpers``, ``cache``, ``base``) are private to this package.
"""

from __future__ import annotations

from .age import AGE_BUCKETS, findings_age_distribution
from .base import COMPLETED_RUN_STATUSES, NetChangeResult, TrendPoint
from .epss import findings_high_epss_in_scope
from .findings import (
    findings_daily_distinct_active,
    findings_distinct_active_as_of,
    findings_distinct_lifetime,
    findings_in_run_severity_distribution,
    findings_in_run_total,
    findings_latest_per_sbom_distinct_vulnerabilities,
    findings_latest_per_sbom_fix_available,
    findings_latest_per_sbom_severity_distribution,
    findings_latest_per_sbom_total,
)
from .kev import findings_kev_in_scope
from .quality import findings_needs_review_in_scope
from .runs import (
    RunsAggregate,
    runs_aggregate,
    runs_completed_lifetime,
    runs_completed_this_week,
    runs_distinct_dates_with_data,
    runs_first_completed_at,
    runs_total_lifetime,
)
from .sboms import (
    applications_scanned_total,
    projects_active_total,
    projects_total,
    sboms_analysed_total,
    sboms_total,
)
from .trend import findings_trend
from .windows import findings_net_change

__all__ = [
    # base
    "COMPLETED_RUN_STATUSES",
    "NetChangeResult",
    "TrendPoint",
    # findings
    "findings_in_run_total",
    "findings_in_run_severity_distribution",
    "findings_latest_per_sbom_total",
    "findings_latest_per_sbom_severity_distribution",
    "findings_latest_per_sbom_distinct_vulnerabilities",
    "findings_latest_per_sbom_fix_available",
    "findings_distinct_lifetime",
    "findings_distinct_active_as_of",
    "findings_daily_distinct_active",
    # kev
    "findings_kev_in_scope",
    # epss / quality / age
    "findings_high_epss_in_scope",
    "findings_needs_review_in_scope",
    "findings_age_distribution",
    "AGE_BUCKETS",
    # runs
    "runs_total_lifetime",
    "runs_completed_lifetime",
    "runs_completed_this_week",
    "runs_distinct_dates_with_data",
    "runs_first_completed_at",
    "runs_aggregate",
    "RunsAggregate",
    # trend / windows
    "findings_trend",
    "findings_net_change",
    # sboms / projects
    "sboms_total",
    "sboms_analysed_total",
    "applications_scanned_total",
    "projects_total",
    "projects_active_total",
]
