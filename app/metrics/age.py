"""findings.age_distribution — "Vulnerability by Age".

Buckets findings in the latest-successful-run-per-SBOM scope by how old the
*vulnerability* is (``now - published_on``, the CVE publish date), with an
optional **observation window on the scan (run) date** — "of what we detected
in this period, how old is it?".

``published_on`` is the only date a finding carries; a null/unparseable value
lands in the ``unknown`` bucket. Parsing is date-only (first 10 chars) so it's
robust across the ISO variants different sources emit and DB-backend agnostic.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun
from ._helpers import latest_run_per_sbom_subquery
from .cache import memoize_with_ttl

# Bucket keys. ``le_30d`` = published within 30 days (youngest); ``gt_365`` =
# older than a year; ``unknown`` = no usable published_on.
AGE_BUCKETS: tuple[str, ...] = ("le_30d", "d31_90", "d91_365", "gt_365", "unknown")


def _bucket_for(published_on: str | None, today: date) -> str:
    if not published_on or len(published_on) < 10:
        return "unknown"
    try:
        published = date.fromisoformat(published_on[:10])
    except ValueError:
        return "unknown"
    days = max(0, (today - published).days)  # future-dated → treat as youngest
    if days <= 30:
        return "le_30d"
    if days <= 90:
        return "d31_90"
    if days <= 365:
        return "d91_365"
    return "gt_365"


def findings_age_distribution(
    db: Session,
    *,
    window: tuple[str | None, str | None] | None = None,
    project_id: int | None = None,
    sbom_id: int | None = None,
    today: date | None = None,
) -> dict[str, int]:
    """findings.age_distribution — counts per CVE-age bucket.

    Scope is the latest successful run per SBOM. Optional narrowing filters:
      * ``window`` — ``(start_iso, end_iso)`` on the run's ``started_on`` (scan
        date); either side may be ``None`` for an open bound.
      * ``project_id`` — only that application's (project's) runs.
      * ``sbom_id`` — only that SBOM's (latest) run.

    ``project_id`` filters on ``AnalysisRun.project_id`` (reliably set from the
    SBOM's project at run creation). Returns a dict keyed by :data:`AGE_BUCKETS`.
    """
    today = today or datetime.now(UTC).date()

    def _compute() -> dict[str, int]:
        latest = latest_run_per_sbom_subquery()
        # Join the run row only when we need to filter on it (scan-date window,
        # project, or single SBOM). Scope stays latest-successful-run-per-SBOM;
        # the filters narrow which of those runs contribute.
        if window is not None or project_id is not None or sbom_id is not None:
            q = (
                select(AnalysisFinding.published_on)
                .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
                .where(AnalysisFinding.analysis_run_id.in_(latest))
            )
            if window is not None:
                start_iso, end_iso = window
                if start_iso:
                    q = q.where(AnalysisRun.started_on >= start_iso)
                if end_iso:
                    q = q.where(AnalysisRun.started_on <= end_iso)
            if project_id is not None:
                q = q.where(AnalysisRun.project_id == project_id)
            if sbom_id is not None:
                q = q.where(AnalysisRun.sbom_id == sbom_id)
        else:
            q = select(AnalysisFinding.published_on).where(
                AnalysisFinding.analysis_run_id.in_(latest)
            )

        buckets = {k: 0 for k in AGE_BUCKETS}
        for (published_on,) in db.execute(q).all():
            buckets[_bucket_for(published_on, today)] += 1
        return buckets

    start_key, end_key = window if window else ("all", "all")
    return memoize_with_ttl(
        name="findings.age_distribution",
        ttl_seconds=5 * 60,
        db=db,
        key_extra=(today.isoformat(), start_key or "", end_key or "", project_id or 0, sbom_id or 0),
        compute=_compute,
    )


__all__ = ["findings_age_distribution", "AGE_BUCKETS"]
