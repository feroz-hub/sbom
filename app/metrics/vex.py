"""VEX metrics — analyser-finding reads backing the VEX evidence surfaces.

These are the finding-shaped queries the VEX services need. They live here
rather than in ``app/services/lifecycle/vex_provider.py`` because router and
service code must not query ``AnalysisFinding`` / ``AnalysisRun`` directly; see
``docs/metric-conventions.md`` and the architectural test
``tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics``.

Two conventions live here, deliberately:

* **Convention C (total raw rows)** — :func:`vex_component_findings` and
  :func:`vex_sbom_finding_pairs`. The component VEX panel and the
  manual-decision picker show every run's detection as history, so these are
  not latest-state scoped. Do not "fix" them to Convention A.
* **Convention A (latest state)** — :func:`vex_current_findings_for_sbom` and
  :func:`latest_successful_run_id_for_sbom`. This is what the VEX
  investigation queue reconciles against, and the fix for GAP-008: current
  product state, not every vulnerability ever detected.

See ``docs/requirements/vex-dashboard-investigation.md`` and
``docs/metric-conventions.md``.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, SBOMComponent
from .base import COMPLETED_RUN_STATUSES


def vex_component_findings(
    db: Session, *, tenant_id: int, sbom_id: int, component_id: int
) -> list[AnalysisFinding]:
    """Analyser findings for one tenant/SBOM/component, newest row first.

    Spans every analysis run for the SBOM (Convention C) — the VEX component
    view lists each detection as evidence rather than a current-state count.
    """
    return list(
        db.scalars(
            select(AnalysisFinding)
            .join(AnalysisRun)
            .where(
                AnalysisFinding.tenant_id == tenant_id,
                AnalysisFinding.component_id == component_id,
                AnalysisRun.tenant_id == tenant_id,
                AnalysisRun.sbom_id == sbom_id,
            )
            .order_by(AnalysisFinding.id.desc())
        ).all()
    )


def vex_sbom_finding_pairs(db: Session, *, sbom_id: int) -> list[tuple[int | None, str | None]]:
    """``(component_id, vuln_id)`` pairs for every finding in an SBOM.

    Feeds the ``vulnerability_options`` list that the manual-decision form
    offers, so it is intentionally unfiltered by run.
    """
    return [
        (component_id, vuln_id)
        for component_id, vuln_id in db.execute(
            select(AnalysisFinding.component_id, AnalysisFinding.vuln_id)
            .join(SBOMComponent, SBOMComponent.id == AnalysisFinding.component_id)
            .where(SBOMComponent.sbom_id == sbom_id)
        ).all()
    ]


def latest_successful_run_id_for_sbom(db: Session, *, tenant_id: int, sbom_id: int) -> int | None:
    """Latest successful ``analysis_run.id`` for one SBOM, or ``None``.

    Convention A. ``MAX(id)`` rather than ``MAX(completed_on)``, matching
    :func:`app.metrics._helpers.latest_run_per_sbom_subquery` and ADR-0001:
    ``id`` is monotonic with the writer's serialisation and NOT NULL, while
    ``completed_on`` can drift for long-running scans.
    """
    return db.execute(
        select(func.max(AnalysisRun.id)).where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.sbom_id == sbom_id,
            AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES),
        )
    ).scalar()


def vex_current_findings_for_sbom(
    db: Session, *, tenant_id: int, sbom_id: int
) -> tuple[int | None, list[AnalysisFinding]]:
    """Findings from the latest successful run for one SBOM (Convention A).

    This is the input the VEX investigation queue reconciles against, and the
    fix for GAP-008: the queue represents current product state, not every
    vulnerability ever detected. Returns ``(run_id, findings)`` so callers can
    record ``last_analysis_run_id`` without a second query; ``(None, [])``
    when the SBOM has never completed a run.
    """
    run_id = latest_successful_run_id_for_sbom(db, tenant_id=tenant_id, sbom_id=sbom_id)
    if run_id is None:
        return None, []
    findings = list(
        db.scalars(
            select(AnalysisFinding)
            .where(
                AnalysisFinding.tenant_id == tenant_id,
                AnalysisFinding.analysis_run_id == run_id,
            )
            .order_by(AnalysisFinding.id)
        ).all()
    )
    return run_id, findings


def vex_run_query_error_count(db: Session, *, tenant_id: int, run_id: int) -> int:
    """``query_error_count`` for a run — evidence for AnalyzerDetectionState.

    A provider failure is not a negative determination (VEX-REC-004), so the
    engine needs to know whether the run had source errors before it can call
    anything NOT_DETECTED.
    """
    return (
        db.execute(
            select(AnalysisRun.query_error_count).where(
                AnalysisRun.tenant_id == tenant_id, AnalysisRun.id == run_id
            )
        ).scalar()
        or 0
    )


__all__ = [
    "latest_successful_run_id_for_sbom",
    "vex_component_findings",
    "vex_current_findings_for_sbom",
    "vex_run_query_error_count",
    "vex_sbom_finding_pairs",
]
