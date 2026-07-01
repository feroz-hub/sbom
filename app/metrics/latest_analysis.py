"""Per-SBOM *latest analysis* snapshot metrics (Convention A — latest state).

These back the ``latest_analysis`` block on SBOM list/detail responses: for a
given SBOM (or set of SBOMs) the most recent ``analysis_run`` plus that run's
aggregate **risk score** (Σ of finding scores).

Note the predicate deliberately differs from
``_helpers.latest_run_per_sbom_subquery``:

* "latest" here is ``MAX(analysis_run.id)`` **regardless of run status** — the
  UI must surface the newest run even when it ERROR'd, to show its status.
* the universe is an **explicit, tenant-scoped set of SBOM ids** (whatever the
  router is serialising), not the active-HEAD/completed-only dashboard universe.

Keeping the risk-score / latest-run aggregation here — not inline in the
router — is the rule enforced by
``tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics``.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun


def _risk_score_stmt(run_id_clause):
    """SELECT COALESCE(SUM(finding.score), 0.0) for the given run-id clause."""
    return select(func.coalesce(func.sum(AnalysisFinding.score), 0.0)).where(run_id_clause)


def latest_run_with_risk_for_sbom(
    db: Session,
    *,
    sbom_id: int,
    tenant_id: int,
) -> tuple[AnalysisRun, float] | None:
    """Latest run (any status) for one SBOM and its aggregate risk score.

    Returns ``(run, risk_score)`` or ``None`` when the SBOM has no runs.
    """
    run = (
        db.execute(
            select(AnalysisRun)
            .where(
                AnalysisRun.sbom_id == sbom_id,
                AnalysisRun.tenant_id == tenant_id,
            )
            .order_by(AnalysisRun.id.desc())
        )
        .scalars()
        .first()
    )
    if run is None:
        return None
    risk_score = db.execute(
        _risk_score_stmt(
            (AnalysisFinding.analysis_run_id == run.id) & (AnalysisFinding.tenant_id == tenant_id),
        )
    ).scalar_one()
    return run, float(risk_score or 0.0)


def latest_runs_with_risk_by_sbom_id(
    db: Session,
    *,
    sbom_ids: list[int],
    tenant_id: int,
) -> dict[int, tuple[AnalysisRun, float]]:
    """Latest run (any status) + risk score for each of ``sbom_ids``.

    Keyed by ``sbom_id``. One round-trip: latest-run-id per SBOM joined to a
    grouped Σ(score) subquery (outer-joined so a run with zero findings still
    yields ``risk_score = 0.0``).
    """
    if not sbom_ids:
        return {}

    latest_run_ids = (
        select(func.max(AnalysisRun.id).label("run_id"))
        .where(AnalysisRun.tenant_id == tenant_id, AnalysisRun.sbom_id.in_(sbom_ids))
        .group_by(AnalysisRun.sbom_id)
        .subquery()
    )
    risk_by_run = (
        select(
            AnalysisFinding.analysis_run_id.label("run_id"),
            func.coalesce(func.sum(AnalysisFinding.score), 0.0).label("risk_score"),
        )
        .where(AnalysisFinding.tenant_id == tenant_id)
        .where(AnalysisFinding.analysis_run_id.in_(select(latest_run_ids.c.run_id)))
        .group_by(AnalysisFinding.analysis_run_id)
        .subquery()
    )
    rows = db.execute(
        select(AnalysisRun, risk_by_run.c.risk_score)
        .join(latest_run_ids, latest_run_ids.c.run_id == AnalysisRun.id)
        .outerjoin(risk_by_run, risk_by_run.c.run_id == AnalysisRun.id)
        .where(AnalysisRun.tenant_id == tenant_id)
    ).all()
    return {int(run.sbom_id): (run, float(risk_score or 0.0)) for run, risk_score in rows}


def list_runs_for_sbom(
    db: Session,
    *,
    sbom_id: int,
    tenant_id: int,
    limit: int,
    offset: int,
) -> list[AnalysisRun]:
    """Paginated ``analysis_run`` rows for one SBOM, newest first (by id)."""
    return list(
        db.execute(
            select(AnalysisRun)
            .where(AnalysisRun.sbom_id == sbom_id, AnalysisRun.tenant_id == tenant_id)
            .order_by(AnalysisRun.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )


__all__ = [
    "latest_run_with_risk_for_sbom",
    "latest_runs_with_risk_by_sbom_id",
    "list_runs_for_sbom",
]
