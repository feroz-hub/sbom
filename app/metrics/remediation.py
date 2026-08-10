"""remediation.summary — MTTR, SLA countdowns, and fix velocity.

Derives finding *lifecycles* from the locked run-timeline semantics the
trend module already uses (ADR-0001 monotonic run ids): walk each SBOM's
successful runs in id order, tracking distinct ``finding_key`` tuples —

* first run containing a key  → the key's **first_seen** (per active period)
* first subsequent run missing it → **resolved** (duration = date delta)
* present in the SBOM's latest run → **active**, age = today − first_seen
* resolved then seen again → **reopened** (a new period; counted)

Convention B identity (``finding_key``), Convention A activeness (latest
run per SBOM). Cross-SBOM the same key dedupes to its *oldest* active
period — the conservative read for SLA breaches.

SLA budgets default to CISA BOD-19-02-flavoured remediation windows
(critical 7d / high 30d / medium 90d / low 180d, unknown treated as
medium). They parameterise the function so a future settings surface can
override without touching this module.

One ``analysis_run`` query + one ``analysis_finding`` query, memoised
15 min — same budget class as the trend chart.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun
from ._helpers import finding_key
from .base import COMPLETED_RUN_STATUSES
from .cache import memoize_with_ttl

# Remediation windows (days) per severity bucket. ``unknown`` borrows the
# medium budget — unknown severity is a data-quality signal, not "safe".
DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "unknown": 90,
}

# "Due soon" = inside the last quarter of the budget but not yet overdue.
_DUE_SOON_FRACTION = 0.75
# Worst-offender list cap.
_TOP_OFFENDERS = 8
# Fix-velocity look-back window (days).
_VELOCITY_WINDOW_DAYS = 30


def sla_state(age_days: int, sla_days: int) -> str:
    """``ok`` | ``due_soon`` | ``overdue``. Pure function, unit-tested."""
    if age_days > sla_days:
        return "overdue"
    if age_days >= sla_days * _DUE_SOON_FRACTION:
        return "due_soon"
    return "ok"


def remediation_summary(
    db: Session,
    *,
    sla_days: dict[str, int] | None = None,
    today: date | None = None,
) -> dict:
    """remediation.summary — see module docstring. Memoised 15 min."""
    end = today or datetime.now(UTC).date()
    budgets = {**DEFAULT_SLA_DAYS, **(sla_days or {})}
    budget_key = tuple(sorted(budgets.items()))

    return memoize_with_ttl(
        name="remediation.summary",
        ttl_seconds=15 * 60,
        db=db,
        key_extra=(end.isoformat(), budget_key),
        compute=lambda: _summary_uncached(db, budgets, end),
    )


def _summary_uncached(db: Session, budgets: dict[str, int], today: date) -> dict:
    # 1. Successful runs grouped per SBOM, in monotonic id order.
    runs = db.execute(
        select(
            AnalysisRun.id,
            AnalysisRun.sbom_id,
            AnalysisRun.sbom_name,
            AnalysisRun.completed_on,
        )
        .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        .order_by(AnalysisRun.sbom_id, AnalysisRun.id)
    ).all()

    sbom_timelines: dict[int, list[tuple[date, int]]] = defaultdict(list)
    sbom_names: dict[int, str] = {}
    all_run_ids: set[int] = set()
    for run_id, sbom_id, sbom_name, completed_on in runs:
        if not completed_on:
            continue
        try:
            d = date.fromisoformat(completed_on[:10])
        except ValueError:
            continue
        sbom_timelines[sbom_id].append((d, run_id))
        sbom_names[sbom_id] = sbom_name or f"SBOM {sbom_id}"
        all_run_ids.add(run_id)

    payload_empty: dict = {
        "mttr_days": {},
        "resolved_total": 0,
        "reopened_total": 0,
        "sla": {
            "budgets_days": budgets,
            "overdue": 0,
            "due_soon": 0,
            "ok": 0,
            "by_severity_overdue": {},
            "worst_offenders": [],
        },
        "velocity": {
            "window_days": _VELOCITY_WINDOW_DAYS,
            "new_findings": 0,
            "resolved_findings": 0,
            "net": 0,
        },
        "schema_version": 1,
    }
    if not all_run_ids:
        return payload_empty

    # 2. One findings query across every successful run.
    keys_by_run: dict[int, dict[tuple[str, str, str], str]] = defaultdict(dict)
    rows = db.execute(
        select(
            AnalysisFinding.analysis_run_id,
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.severity,
        ).where(AnalysisFinding.analysis_run_id.in_(all_run_ids))
    ).all()
    for run_id, vuln, comp, ver, sev in rows:
        key = finding_key(vuln, comp, ver)
        if key not in keys_by_run[run_id]:
            keys_by_run[run_id][key] = (sev or "unknown").lower()

    # 3. Walk each SBOM timeline: open/close finding periods.
    durations_by_sev: dict[str, list[int]] = defaultdict(list)
    resolved_total = 0
    reopened_total = 0
    resolved_in_window = 0
    new_in_window: set[tuple[str, str, str]] = set()
    window_start = today - timedelta(days=_VELOCITY_WINDOW_DAYS)
    # Cross-SBOM active dedup: key → (first_seen, severity, sbom_name); keep oldest.
    active: dict[tuple[str, str, str], tuple[date, str, str]] = {}

    for sbom_id, timeline in sbom_timelines.items():
        open_periods: dict[tuple[str, str, str], tuple[date, str]] = {}
        seen_before: set[tuple[str, str, str]] = set()
        for run_date, run_id in timeline:
            present = keys_by_run.get(run_id, {})
            for key, sev in present.items():
                if key not in open_periods:
                    if key in seen_before:
                        reopened_total += 1
                    open_periods[key] = (run_date, sev)
                    seen_before.add(key)
                    if run_date >= window_start:
                        new_in_window.add(key)
            for key in list(open_periods):
                if key not in present:
                    first_seen, sev = open_periods.pop(key)
                    duration = max(0, (run_date - first_seen).days)
                    durations_by_sev[_bucket(sev)].append(duration)
                    resolved_total += 1
                    if run_date >= window_start:
                        resolved_in_window += 1
        name = sbom_names.get(sbom_id, f"SBOM {sbom_id}")
        for key, (first_seen, sev) in open_periods.items():
            existing = active.get(key)
            if existing is None or first_seen < existing[0]:
                active[key] = (first_seen, sev, name)

    # 4. MTTR per severity (mean over resolved periods) + overall.
    mttr: dict[str, float | int | None] = {}
    all_durations: list[int] = []
    for sev in ("critical", "high", "medium", "low", "unknown"):
        ds = durations_by_sev.get(sev, [])
        mttr[sev] = round(sum(ds) / len(ds), 1) if ds else None
        all_durations.extend(ds)
    mttr["overall"] = round(sum(all_durations) / len(all_durations), 1) if all_durations else None

    # 5. SLA classification of the active (deduped) set.
    counts = {"overdue": 0, "due_soon": 0, "ok": 0}
    overdue_by_sev: dict[str, int] = defaultdict(int)
    offenders: list[dict] = []
    for key, (first_seen, sev, sbom_name) in active.items():
        bucket = _bucket(sev)
        budget = budgets.get(bucket, budgets["medium"])
        age = max(0, (today - first_seen).days)
        state = sla_state(age, budget)
        counts[state] += 1
        if state == "overdue":
            overdue_by_sev[bucket] += 1
            vuln_id, comp, ver = key
            offenders.append(
                {
                    "vuln_id": vuln_id,
                    "component_name": comp,
                    "component_version": ver,
                    "severity": bucket,
                    "sbom_name": sbom_name,
                    "age_days": age,
                    "sla_days": budget,
                    "days_over": age - budget,
                    "first_seen": first_seen.isoformat(),
                }
            )
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "unknown": 3, "low": 4}
    offenders.sort(key=lambda o: (severity_rank.get(o["severity"], 5), -o["days_over"]))

    return {
        "mttr_days": mttr,
        "resolved_total": resolved_total,
        "reopened_total": reopened_total,
        "sla": {
            "budgets_days": budgets,
            "overdue": counts["overdue"],
            "due_soon": counts["due_soon"],
            "ok": counts["ok"],
            "by_severity_overdue": dict(overdue_by_sev),
            "worst_offenders": offenders[:_TOP_OFFENDERS],
        },
        "velocity": {
            "window_days": _VELOCITY_WINDOW_DAYS,
            "new_findings": len(new_in_window),
            "resolved_findings": resolved_in_window,
            "net": len(new_in_window) - resolved_in_window,
        },
        "schema_version": 1,
    }


def _bucket(sev: str | None) -> str:
    s = (sev or "unknown").lower()
    return s if s in DEFAULT_SLA_DAYS else "unknown"


__all__ = ["remediation_summary", "sla_state", "DEFAULT_SLA_DAYS"]
