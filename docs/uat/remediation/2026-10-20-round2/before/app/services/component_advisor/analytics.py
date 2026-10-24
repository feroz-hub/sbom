"""Secure Component Advisor effectiveness analytics (FR-SCA-024, US-SCA-17).

Analytical only: these numbers describe how the advisor is used and how risk
enters the portfolio. They never feed back into classification, trust,
ranking or eligibility.

* Recommendation outcomes over a window — generated, recommended, accepted,
  rejected, deferred, more evidence requested, closed — from the append-only
  event log, so they count decisions actually taken.
* Reuse of tenant-observed candidates — of the accepted recommendations,
  how many chose a version already present in the tenant's active SBOMs.
* Newly introduced High / Critical components — current High / Critical
  unique versions bucketed by the month their first eligible occurrence was
  recorded.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from ...metrics.component_advisor import advisor_first_seen, advisor_recommendation_analytics
from ..dashboard_scope import DashboardScope
from .classification import RiskClassification
from .intelligence_service import cached_snapshot

_NEW_RISK = (RiskClassification.CRITICAL, RiskClassification.HIGH)


def _months(now: datetime, count: int) -> list[str]:
    out, year, month = [], now.year, now.month
    for _ in range(count):
        out.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return list(reversed(out))


def recommendation_analytics(db: Session, scope: DashboardScope, *, months: int = 12, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    since = now - timedelta(days=round(months * 30.4375))
    counts = advisor_recommendation_analytics(db, tenant_id=scope.tenant_id, since=since)
    actions = counts["actions"]
    accepted_sources = counts["accepted_by_candidate_source"]
    accepted_total = sum(accepted_sources.values())

    snapshot = cached_snapshot(db, scope)
    risky = [v for v in snapshot.versions if v.classification in _NEW_RISK]
    first_seen = advisor_first_seen(
        db, tenant_id=scope.tenant_id, component_ids=[ref["component_id"] for v in risky for ref in v.references],
    )
    window = _months(now, months)
    series = {month: Counter() for month in window}
    unknown_date = 0
    for version in risky:
        dates = sorted(d for d in (first_seen.get(ref["component_id"]) for ref in version.references) if d)
        month = dates[0][:7] if dates else None
        if month is None:
            unknown_date += 1
        elif month in series:
            series[month][version.classification.value] += 1

    return {
        "window": {"months": months, "since": since.date().isoformat(), "until": now.date().isoformat()},
        "recommendations": {
            "generated": actions.get("CREATED", 0),
            "recommended": actions.get("RECOMMENDED", 0),
            "accepted": actions.get("ACCEPTED", 0),
            "rejected": actions.get("REJECTED", 0),
            "deferred": actions.get("DEFERRED", 0),
            "more_evidence_requested": actions.get("MORE_EVIDENCE_REQUESTED", 0),
            "closed": actions.get("CLOSED", 0),
            "by_trigger": counts["by_trigger"],
        },
        "tenant_observed_reuse": {
            "accepted_total": accepted_total,
            "accepted_tenant_observed": accepted_sources.get("TENANT_OBSERVED", 0),
            "accepted_external": accepted_sources.get("EXTERNAL", 0),
            "accepted_manual": accepted_sources.get("MANUAL", 0),
            "tenant_observed_share": round(accepted_sources.get("TENANT_OBSERVED", 0) / accepted_total, 4) if accepted_total else None,
        },
        "new_high_critical_components": {
            "series": [{"month": month, "critical": series[month]["CRITICAL"], "high": series[month]["HIGH"]} for month in window],
            "current_high_critical_versions": len(risky),
            "without_first_seen_date": unknown_date,
            "basis": "Current High/Critical unique versions by the month their first eligible occurrence was recorded",
        },
        "analytical_only": True,
    }


__all__ = ["recommendation_analytics"]
