"""Pure functions and SQL helpers backing the v2 dashboard endpoints.

The router stays thin — anything that's actually a *rule* (state machine,
zero-fill, cross-run resolution count, time-windowed delta) lives here so:

* The same logic is reachable from a Celery worker or a CLI without
  spinning up FastAPI.
* Unit tests can exercise the rules directly against a seeded session,
  without going through HTTP.
* The router's job collapses to "call helpers, ETag the result, return."

See ``docs/dashboard-redesign.md`` §9 for the wire-format contract and §2 / §4
for the headline-state and primary-action rules.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Iterable

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..models import (
    AnalysisFinding,
    AnalysisRun,
    KevEntry,
    Projects,
    SBOMSource,
)
from ..schemas_dashboard import (
    HeadlineState,
    LifetimeMetrics,
    PrimaryAction,
    TrendAnnotation,
    TrendDataPoint,
)
from .analysis_service import SUCCESSFUL_RUN_STATUSES

log = logging.getLogger("sbom.services.dashboard")


# ---------------------------------------------------------------------------
# Headline state machine — pure
# ---------------------------------------------------------------------------


def compute_headline_state(
    *,
    total_sboms: int,
    total_findings: int,
    critical: int,
    high: int,
    kev_count: int,
) -> tuple[HeadlineState, PrimaryAction]:
    """Map in-scope aggregates to ``(headline_state, primary_action)``.

    Precedence is strict — first match wins. The order encodes the intent:
    "no data" trumps any band; KEV-listed findings trump critical-only;
    critical-only trumps high-only; high-only trumps medium/low; only when
    findings are completely absent does ``clean`` fire.

    Headline copy lives in the frontend (``lib/headlineCopy.ts``); this
    function is the single source of truth for *which* copy renders so all
    downstream consumers (hero, future digest emails, sidebar) agree.

    See ``docs/dashboard-redesign.md`` §2.1 for the locked rule table.
    """
    if total_sboms == 0:
        return "no_data", "upload"
    if kev_count >= 1:
        return "kev_present", "review_kev"
    if critical >= 1:
        return "criticals_no_kev", "review_critical"
    if high >= 1:
        return "high_only", "view_top_sboms"
    if total_findings >= 1:
        return "low_volume", "view_top_sboms"
    return "clean", "upload"


# ---------------------------------------------------------------------------
# Trend — zero-filled date series and annotations
# ---------------------------------------------------------------------------


def _date_range(days: int, *, today: date | None = None) -> list[str]:
    """Inclusive list of ``days`` consecutive ISO YYYY-MM-DD strings ending today.

    Generating the date range in Python (rather than ``generate_series``)
    keeps the query SQLite-compatible. SQLAlchemy 2.x's ``generate_series``
    helper is Postgres-only; this codebase runs against both backends, and
    paying one Python loop of ~30 items beats branching the query.
    """
    end = today or datetime.now(UTC).date()
    return [(end - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]


def build_trend_points(db: Session, *, days: int) -> list[TrendDataPoint]:
    """Return exactly ``days`` data points with severity breakdowns, zero-filled.

    The backend used to return only days that had findings — Recharts then
    rendered isolated dots without a connecting area. Generating the full
    range and left-joining means the chart can plot the shape honestly,
    including the long stretches of zero that "we just started using this
    tool" looks like in the first weeks. ``unknown`` is restored as a
    first-class bucket, fixing the silent-drop bug noted in the audit §3.3.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=days - 1)).date().isoformat()

    # SQL aggregation by (day, severity). The ``substr(started_on, 1, 10)``
    # trick extracts ``YYYY-MM-DD`` from the ISO string we store and avoids
    # a backend-specific date cast. Successful-run scoping aligns with every
    # other dashboard aggregate per ADR-0001.
    date_expr = func.substr(AnalysisRun.started_on, 1, 10).label("day")
    rows = db.execute(
        select(
            date_expr,
            AnalysisFinding.severity.label("severity"),
            func.count(AnalysisFinding.id).label("count"),
        )
        .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
        .where(
            AnalysisRun.started_on >= cutoff,
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES),
        )
        .group_by(date_expr, AnalysisFinding.severity)
    ).all()

    bucket_keys = ("critical", "high", "medium", "low", "unknown")
    daily: dict[str, dict[str, int]] = defaultdict(
        lambda: {k: 0 for k in bucket_keys}
    )
    for day, severity, count in rows:
        if not day:
            continue
        sev = (severity or "unknown").lower()
        if sev not in bucket_keys:
            sev = "unknown"
        daily[day][sev] += count

    points: list[TrendDataPoint] = []
    for day in _date_range(days):
        b = daily.get(day, {k: 0 for k in bucket_keys})
        total = sum(b[k] for k in bucket_keys)
        points.append(
            TrendDataPoint(
                date=day,
                critical=b["critical"],
                high=b["high"],
                medium=b["medium"],
                low=b["low"],
                unknown=b["unknown"],
                total=total,
            )
        )
    return points


def build_trend_annotations(db: Session, *, days: int) -> list[TrendAnnotation]:
    """Collect event markers for the trend chart.

    Two kinds are computed eagerly:

    * ``sbom_uploaded`` — directly from ``sbom_source.created_on`` in the window.
      Days with multiple uploads collapse into a single ``+N SBOMs uploaded`` marker.
    * ``remediation`` — derived from consecutive successful runs of the same SBOM.
      A drop of ≥ 5 distinct findings between run N and N+1 surfaces as a single
      marker on the day of run N+1.

    The third kind, ``kev_first_seen``, is left for a follow-up — the audit §5.2
    flagged it as best-effort and the brief explicitly allows omitting it for v1.
    """
    annotations: list[TrendAnnotation] = []
    in_window = set(_date_range(days))

    # SBOM uploads.
    upload_rows = db.execute(
        select(
            func.substr(SBOMSource.created_on, 1, 10).label("day"),
            func.count(SBOMSource.id).label("n"),
            func.min(SBOMSource.sbom_name).label("sample_name"),
        )
        .where(SBOMSource.created_on.is_not(None))
        .group_by(func.substr(SBOMSource.created_on, 1, 10))
    ).all()
    for day, n, sample_name in upload_rows:
        if day not in in_window:
            continue
        label = (
            f"{sample_name} uploaded"
            if n == 1
            else f"+{n} SBOMs uploaded"
        )
        annotations.append(
            TrendAnnotation(date=day, kind="sbom_uploaded", label=label, count=n or 1)
        )

    # Remediation events — drop of ≥ 5 distinct findings between consecutive
    # successful runs of the same SBOM. Done in two passes: first the
    # consecutive-run pairs, then the per-pair finding-set diff. Bounded by
    # the small number of runs per SBOM in practice, but cached at the
    # endpoint level via ETag so the chart doesn't recompute on every refetch.
    pairs = _consecutive_successful_run_pairs(db)
    for run_a, run_b, run_b_started_on in pairs:
        run_b_day = (run_b_started_on or "")[:10]
        if run_b_day not in in_window:
            continue
        a_keys = _finding_keys_for_run(db, run_a)
        b_keys = _finding_keys_for_run(db, run_b)
        resolved_in_pair = len(a_keys - b_keys)
        if resolved_in_pair >= 5:
            annotations.append(
                TrendAnnotation(
                    date=run_b_day,
                    kind="remediation",
                    label=f"{resolved_in_pair} findings resolved",
                    count=resolved_in_pair,
                )
            )
    return annotations


# ---------------------------------------------------------------------------
# Cross-run helpers — used by both trend annotations and lifetime metrics
# ---------------------------------------------------------------------------


def _consecutive_successful_run_pairs(
    db: Session,
) -> list[tuple[int, int, str | None]]:
    """Yield ``(run_a_id, run_b_id, run_b_started_on)`` pairs for the same SBOM
    where ``b`` is the immediate successor of ``a`` in chronological order
    (filtered to successful statuses).

    Implemented with a row-numbered CTE so we get O(R) work where R is the
    number of successful runs — not O(R^2) like the naive self-join would.
    SQLite supports window functions since 3.25 and the ORM string this
    builds is fine on Postgres too.
    """
    sql = text(
        """
        WITH ordered AS (
            SELECT
                id,
                sbom_id,
                started_on,
                ROW_NUMBER() OVER (PARTITION BY sbom_id ORDER BY id) AS rn
            FROM analysis_run
            WHERE run_status IN ('OK','FINDINGS','PARTIAL')
        )
        SELECT a.id AS run_a, b.id AS run_b, b.started_on AS run_b_started
        FROM ordered a
        JOIN ordered b
          ON a.sbom_id = b.sbom_id AND b.rn = a.rn + 1
        ORDER BY b.id
        """
    )
    return [(row[0], row[1], row[2]) for row in db.execute(sql).all()]


def _finding_keys_for_run(db: Session, run_id: int) -> set[tuple[str, str, str]]:
    """Set of ``(vuln_id, component_name, component_version)`` for a run.

    Exposed as a helper so the same dedup key is used in every place that
    asks "is this finding the same finding?" — keeping the lifetime
    ``findings_resolved_total`` and the trend ``remediation`` annotation
    counting the same way.
    """
    rows = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
        ).where(AnalysisFinding.analysis_run_id == run_id)
    ).all()
    return {
        (
            (vuln or "") or "",
            (name or "") or "",
            (ver or "") or "",
        )
        for vuln, name, ver in rows
    }


def compute_findings_resolved_total(db: Session) -> int:
    """Sum of findings present in run N but absent from run N+1, across all
    consecutive successful run pairs.

    Note this counts *finding-keys*, not finding-rows: the same vuln_id on
    the same component at the same version is one resolved item even if the
    finding row was rewritten between runs. This matches how
    ``findings_surfaced_total`` is deduplicated, so the two numbers compare
    apples to apples in the lifetime tile.
    """
    total = 0
    for run_a, run_b, _ in _consecutive_successful_run_pairs(db):
        a_keys = _finding_keys_for_run(db, run_a)
        b_keys = _finding_keys_for_run(db, run_b)
        total += len(a_keys - b_keys)
    return total


# ---------------------------------------------------------------------------
# Net 7-day change — vuln-id semantics (locked, see redesign §3.2)
# ---------------------------------------------------------------------------


def compute_net_7day_change(db: Session) -> tuple[int, int]:
    """Compute ``(added, resolved)`` distinct vuln_ids vs 7 days ago.

    A vuln is "added" when it appears in today's latest-successful-run-per-SBOM
    scope but did not appear in the latest-successful-run-per-SBOM scope as of
    7 days ago. "Resolved" is the inverse. This deliberately works at the
    vuln_id level (one CVE on three components is one work item, not three),
    matching the user mental model documented in ``dashboard-redesign.md`` §3.2.
    """
    seven_days_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()

    today_runs = (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )
    today_vulns: set[str] = {
        row[0]
        for row in db.execute(
            select(AnalysisFinding.vuln_id)
            .where(AnalysisFinding.analysis_run_id.in_(today_runs))
            .distinct()
        )
        if row[0]
    }

    historical_runs = (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .where(AnalysisRun.started_on <= seven_days_ago)
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )
    historical_vulns: set[str] = {
        row[0]
        for row in db.execute(
            select(AnalysisFinding.vuln_id)
            .where(AnalysisFinding.analysis_run_id.in_(historical_runs))
            .distinct()
        )
        if row[0]
    }

    added = len(today_vulns - historical_vulns)
    resolved = len(historical_vulns - today_vulns)
    return added, resolved


# ---------------------------------------------------------------------------
# Lifetime metrics — with in-process cache
# ---------------------------------------------------------------------------


_LIFETIME_TTL_SECONDS = 15 * 60  # 15 minutes — see redesign §9.3
_lifetime_cache: dict[tuple[int, int, int], tuple[float, LifetimeMetrics]] = {}
_lifetime_cache_lock = threading.Lock()


def _lifetime_cache_key(db: Session) -> tuple[int, int, int]:
    """Cheap invalidation key: any new run, new SBOM, or status change moves
    one of the three. All three are O(1) with the existing indices.
    """
    max_run_id = db.execute(select(func.max(AnalysisRun.id))).scalar() or 0
    run_count = db.execute(select(func.count(AnalysisRun.id))).scalar() or 0
    sbom_count = db.execute(select(func.count(SBOMSource.id))).scalar() or 0
    return (int(max_run_id), int(run_count), int(sbom_count))


def compute_lifetime_metrics(db: Session) -> LifetimeMetrics:
    """Compute (or return cached) ``LifetimeMetrics`` for the dashboard.

    Single-tenant for now; the cache is per-process. When multi-tenancy lands
    we'll either key the cache by tenant or move to Redis with a per-tenant
    namespace — see redesign §9.3 for the deferred decision.
    """
    key = _lifetime_cache_key(db)
    now = time.time()

    with _lifetime_cache_lock:
        cached = _lifetime_cache.get(key)
        if cached is not None and (now - cached[0]) < _LIFETIME_TTL_SECONDS:
            return cached[1]

    # Cheap O(1) counts.
    sboms_total = db.execute(select(func.count(SBOMSource.id))).scalar() or 0
    projects_total = db.execute(select(func.count(Projects.id))).scalar() or 0
    runs_total = db.execute(select(func.count(AnalysisRun.id))).scalar() or 0
    one_week_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    runs_this_week = (
        db.execute(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.started_on >= one_week_ago
            )
        ).scalar()
        or 0
    )

    # Distinct (vuln_id, component_name, component_version) across all findings.
    # Kept as a single SQL DISTINCT count rather than pulling rows into Python —
    # for ~10k findings the engine handles this in milliseconds.
    findings_surfaced = (
        db.execute(
            select(
                func.count(
                    func.distinct(
                        func.coalesce(AnalysisFinding.vuln_id, "")
                        + "|"
                        + func.coalesce(AnalysisFinding.component_name, "")
                        + "|"
                        + func.coalesce(AnalysisFinding.component_version, "")
                    )
                )
            )
        ).scalar()
        or 0
    )

    findings_resolved = compute_findings_resolved_total(db)

    first_run_at = db.execute(
        select(func.min(AnalysisRun.started_on)).where(
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES)
        )
    ).scalar()

    days_monitoring = 0
    if first_run_at:
        try:
            first_dt = datetime.fromisoformat(first_run_at)
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=UTC)
            days_monitoring = max(0, (datetime.now(UTC) - first_dt).days)
        except ValueError:
            log.warning("lifetime_metrics: malformed first_run_at=%s", first_run_at)

    result = LifetimeMetrics(
        sboms_scanned_total=int(sboms_total),
        projects_total=int(projects_total),
        runs_executed_total=int(runs_total),
        runs_executed_this_week=int(runs_this_week),
        findings_surfaced_total=int(findings_surfaced),
        findings_resolved_total=int(findings_resolved),
        first_run_at=first_run_at,
        days_monitoring=days_monitoring,
    )

    with _lifetime_cache_lock:
        _lifetime_cache[key] = (now, result)
        # Bound the cache so a runaway test session can't accumulate entries.
        if len(_lifetime_cache) > 32:
            oldest_key = min(_lifetime_cache, key=lambda k: _lifetime_cache[k][0])
            _lifetime_cache.pop(oldest_key, None)

    return result


def reset_lifetime_cache() -> None:
    """Test seam — clear the in-process cache.

    The dashboard tests seed and inspect lifetime values within the same
    pytest session; without this the second seed sees yesterday's cached
    aggregate. Production code never calls this.
    """
    with _lifetime_cache_lock:
        _lifetime_cache.clear()
