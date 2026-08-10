"""findings.needs_review_in_scope — match-quality / not-verified count.

A finding "needs review" when its match was a *conservative keep* rather than
a verified hit: ``match_reason`` is present and != ``'matched'`` (the
version-unparseable / and-node-ambiguous / ecosystem-unsupported /
no-configurations reasons). This is exactly the set the run-detail
"not verified" filter shows, which the dashboard reaches via the ``?review=1``
drill-down — so the dashboard count and the drilled-in list reconcile.

Rows with a null/empty ``match_reason`` (flag-off scans, non-NVD sources) are
NOT counted — there's nothing to second-guess, mirroring the frontend
``MatchReasonFilter`` 'not_verified' predicate.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding
from ._helpers import latest_run_per_sbom_subquery
from .base import KevScope
from .cache import memoize_with_ttl

# ``match_reason`` value denoting a verified hit; any other non-null value is a
# conservative keep an analyst should eyeball.
_VERIFIED_REASON = "matched"


def findings_needs_review_in_scope(db: Session, *, scope: KevScope, run_id: int | None = None) -> int:
    """findings.needs_review_in_scope — count of low-confidence / not-verified findings.

    Scopes mirror :func:`app.metrics.findings_kev_in_scope`.
    """
    if scope == "run":
        if run_id is None:
            raise ValueError("run_id is required when scope='run'")
        return _needs_review_count(db, AnalysisFinding.analysis_run_id == run_id)
    if scope == "latest_per_sbom":
        return memoize_with_ttl(
            name="findings.needs_review_in_scope.latest_per_sbom",
            ttl_seconds=5 * 60,
            db=db,
            compute=lambda: _needs_review_count(
                db,
                AnalysisFinding.analysis_run_id.in_(latest_run_per_sbom_subquery()),
            ),
        )
    raise ValueError(f"unknown scope: {scope!r}")


def _needs_review_count(db: Session, scope_clause) -> int:
    return (
        db.execute(
            select(func.count(AnalysisFinding.id)).where(
                scope_clause,
                AnalysisFinding.match_reason.is_not(None),
                AnalysisFinding.match_reason != "",
                AnalysisFinding.match_reason != _VERIFIED_REASON,
            )
        ).scalar()
        or 0
    )


__all__ = ["findings_needs_review_in_scope"]
