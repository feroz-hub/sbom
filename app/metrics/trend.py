"""findings.trend — granular, app-filterable trend with fix series.

Extends the day-only ``findings_daily_distinct_active`` for the manager
dashboard's trend chart:

* **granularity** — day / week / month / year period buckets (each point is an
  as-of-end-of-period distinct-active snapshot, same semantics as the daily
  chart, just sampled at period ends).
* **application filter** — restrict to runs of the chosen projects.
* **fix series (overlay)** — ``fix_available`` (distinct active findings with a
  fixed version, from the same snapshot) and ``resolved`` (findings present in
  run N but gone in run N+1, summed per period from consecutive run pairs).

One ``analysis_run`` query and one ``analysis_finding`` query regardless of
period count. Memoised 15 min like the daily trend.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun
from ._helpers import finding_key
from .base import COMPLETED_RUN_STATUSES, SEVERITY_KEYS
from .cache import memoize_with_ttl

Granularity = str  # "day" | "week" | "month" | "year"

# Default number of period points per granularity.
_PERIOD_COUNT = {"day": 30, "week": 12, "month": 12, "year": 5}


class TrendSeriesPoint:
    """One period: severity buckets + fix-available + resolved counts."""

    __slots__ = (*SEVERITY_KEYS, "date", "total", "fix_available", "resolved")

    def __init__(self, date_: str) -> None:
        self.date = date_
        for k in SEVERITY_KEYS:
            setattr(self, k, 0)
        self.total = 0
        self.fix_available = 0
        self.resolved = 0

    def as_dict(self) -> dict:
        d = {"date": self.date, "total": self.total}
        for k in SEVERITY_KEYS:
            d[k] = getattr(self, k)
        d["fix_available"] = self.fix_available
        d["resolved"] = self.resolved
        return d


def _last_n_month_ends(today: date, n: int) -> list[date]:
    ends: list[date] = []
    y, m = today.year, today.month
    for _ in range(n):
        last = date(y, 12, 31) if m == 12 else date(y, m + 1, 1) - timedelta(days=1)
        ends.append(min(last, today))
        m -= 1
        if m == 0:
            m, y = 12, y - 1
    return list(reversed(ends))


def _period_end_dates(granularity: Granularity, today: date) -> list[date]:
    n = _PERIOD_COUNT.get(granularity, 30)
    if granularity == "week":
        return [today - timedelta(days=7 * i) for i in range(n - 1, -1, -1)]
    if granularity == "month":
        return _last_n_month_ends(today, n)
    if granularity == "year":
        return list(
            reversed([min(date(today.year - i, 12, 31), today) for i in range(n)])
        )
    # day (default)
    return [today - timedelta(days=i) for i in range(n - 1, -1, -1)]


def _has_fix(fixed_versions: str | None) -> bool:
    if not fixed_versions:
        return False
    s = fixed_versions.strip()
    return s not in ("", "[]")


def _assign_period(d: date, period_ends: list[date]) -> int | None:
    """Index of the first period whose end is >= ``d`` (the bucket ``d`` falls
    in); ``None`` if ``d`` is after the last period end (shouldn't happen for
    in-window dates) or before the window starts."""
    for i, end in enumerate(period_ends):
        if d <= end:
            return i
    return None


def findings_trend(
    db: Session,
    *,
    granularity: Granularity = "day",
    application_ids: list[int] | None = None,
    today: date | None = None,
) -> list[dict]:
    """findings.trend — see module docstring. Returns one dict per period."""
    today = today or datetime.now(UTC).date()
    app_key = tuple(sorted(application_ids)) if application_ids else ()

    def _compute() -> list[dict]:
        return _trend_uncached(db, granularity, application_ids, today)

    return memoize_with_ttl(
        name="findings.trend",
        ttl_seconds=15 * 60,
        db=db,
        key_extra=(granularity, app_key, today.isoformat()),
        compute=_compute,
    )


def _trend_uncached(
    db: Session,
    granularity: Granularity,
    application_ids: list[int] | None,
    today: date,
) -> list[dict]:
    period_ends = _period_end_dates(granularity, today)
    window_start = period_ends[0] if period_ends else today

    # 1. Completed runs (optionally app-filtered), grouped per SBOM in id order.
    run_q = select(
        AnalysisRun.id, AnalysisRun.sbom_id, AnalysisRun.completed_on
    ).where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
    if application_ids:
        run_q = run_q.where(AnalysisRun.project_id.in_(application_ids))

    sbom_runs: dict[int, list[tuple[date, int]]] = defaultdict(list)
    for run_id, sbom_id, completed_on in db.execute(run_q).all():
        if not completed_on:
            continue
        try:
            d = date.fromisoformat(completed_on[:10])
        except ValueError:
            continue
        sbom_runs[sbom_id].append((d, run_id))
    for timeline in sbom_runs.values():
        timeline.sort(key=lambda x: x[1])  # by run_id (monotonic per ADR-0001)

    # 2. Which runs we must load findings for: the as-of-latest run per SBOM at
    #    each period end, plus both runs of any consecutive pair whose later run
    #    landed inside the window (for the resolved series).
    runs_needed: set[int] = set()
    day_to_runs: dict[int, list[int]] = {}
    for idx, end in enumerate(period_ends):
        latest_per_sbom: list[int] = []
        for timeline in sbom_runs.values():
            best: int | None = None
            for run_date, run_id in timeline:
                if run_date <= end and (best is None or run_id > best):
                    best = run_id
            if best is not None:
                latest_per_sbom.append(best)
                runs_needed.add(best)
        day_to_runs[idx] = latest_per_sbom

    resolved_pairs: list[tuple[int, int, int]] = []  # (run_a, run_b, period_idx)
    for timeline in sbom_runs.values():
        for (_da, ra), (db_, rb) in zip(timeline, timeline[1:], strict=False):
            if db_ < window_start:
                continue
            pidx = _assign_period(db_, period_ends)
            if pidx is None:
                continue
            resolved_pairs.append((ra, rb, pidx))
            runs_needed.add(ra)
            runs_needed.add(rb)

    # 3. One findings query for every needed run.
    keys_by_run: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    sev_by_run: dict[int, dict[tuple[str, str, str], str]] = defaultdict(dict)
    fix_keys_by_run: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
    if runs_needed:
        rows = db.execute(
            select(
                AnalysisFinding.analysis_run_id,
                AnalysisFinding.vuln_id,
                AnalysisFinding.component_name,
                AnalysisFinding.component_version,
                AnalysisFinding.severity,
                AnalysisFinding.fixed_versions,
            ).where(AnalysisFinding.analysis_run_id.in_(runs_needed))
        ).all()
        for run_id, vuln, comp, ver, sev, fixed in rows:
            key = finding_key(vuln, comp, ver)
            keys_by_run[run_id].add(key)
            if key not in sev_by_run[run_id]:
                sev_by_run[run_id][key] = (sev or "unknown")
            if _has_fix(fixed):
                fix_keys_by_run[run_id].add(key)

    # 4. Per-period severity + fix-available snapshot (distinct-active).
    points = [TrendSeriesPoint(end.isoformat()) for end in period_ends]
    for idx in range(len(period_ends)):
        seen_sev: dict[tuple[str, str, str], str] = {}
        fixed_keys: set[tuple[str, str, str]] = set()
        for run_id in day_to_runs.get(idx, []):
            for key, sev in sev_by_run.get(run_id, {}).items():
                if key not in seen_sev:
                    seen_sev[key] = sev
            fixed_keys |= fix_keys_by_run.get(run_id, set())
        pt = points[idx]
        for sev in seen_sev.values():
            bucket = (sev or "unknown").lower()
            if bucket not in SEVERITY_KEYS:
                bucket = "unknown"
            setattr(pt, bucket, getattr(pt, bucket) + 1)
        pt.total = len(seen_sev)
        # fix_available counts only keys that are still active in this snapshot.
        pt.fix_available = len(fixed_keys & set(seen_sev.keys()))

    # 5. Resolved per period from consecutive pairs.
    for run_a, run_b, pidx in resolved_pairs:
        resolved = len(keys_by_run.get(run_a, set()) - keys_by_run.get(run_b, set()))
        points[pidx].resolved += resolved

    return [p.as_dict() for p in points]


__all__ = ["findings_trend"]
