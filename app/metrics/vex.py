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

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, SBOMComponent, VexInvestigation
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


def vex_run_source_summary(db: Session, *, tenant_id: int, run_id: int) -> list[dict]:
    """Per-source outcome for a run, from ``analysis_run.raw_report``.

    Each entry carries ``source``, ``status`` and sometimes ``reason`` —
    e.g. ``{"source": "GITHUB", "status": "skipped",
    "reason": "missing_credentials"}``. This is what lets the engine tell a
    provider that was never consulted (SOURCE_UNAVAILABLE) from one that was
    consulted and failed (SOURCE_ERROR), which VEX-REC-004 requires and a bare
    ``query_error_count`` cannot express.

    Returns ``[]`` when the run has no parseable report; callers treat that as
    "no per-source evidence", never as "all sources succeeded".
    """
    raw = db.execute(
        select(AnalysisRun.raw_report).where(
            AnalysisRun.tenant_id == tenant_id, AnalysisRun.id == run_id
        )
    ).scalar()
    if not raw:
        return []
    try:
        report = json.loads(raw)
    except (TypeError, ValueError):
        return []
    summary = (report.get("analysis_metadata") or {}).get("source_summary")
    return [entry for entry in summary or [] if isinstance(entry, dict)]


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


#: Reconciliation states that put a context in the review queue (VEX-DASH-003).
_NEEDS_REVIEW = ("CONFLICT_REVIEW_REQUIRED", "REVALIDATION_REQUIRED")


def _current_contexts(tenant_id: int, sbom_ids):
    """Base predicate for every VEX context metric.

    ``is_current`` is what makes these *current operational state*: contexts
    retired by a later run stay queryable as history but never contribute to
    tiles or the queue (VEX-DASH-005, VEX-INV-002). ``sbom_ids`` is the
    dashboard's eligible-SBOM scope, passed in rather than re-derived, so the
    tiles and the investigation table cannot drift apart (VEX-DASH-004).
    """
    return (
        VexInvestigation.tenant_id == tenant_id,
        VexInvestigation.is_current.is_(True),
        VexInvestigation.sbom_id.in_(sbom_ids),
    )


def vex_context_counts(db: Session, *, tenant_id: int, sbom_ids) -> dict[str, int]:
    """Effective-status and reconciliation-status counts over current contexts.

    Convention A — one row per current vulnerability context, which is the
    reconciled union of analyser findings and mapped VEX assertions after
    deduplication (VEX-DASH-001).

    The mapped-context invariant (VEX-DASH-002) holds by construction here:
    ``total_contexts`` counts contexts whose component resolved, and every such
    context has exactly one of the four effective statuses. Unresolved mappings
    are counted separately and excluded from the total so they cannot deflate
    a disposition count and make risk look smaller than it is.
    """
    predicate = _current_contexts(tenant_id, sbom_ids)
    unresolved_predicate = VexInvestigation.reconciliation_status == "UNRESOLVED_MAPPING"

    status_rows = db.execute(
        select(VexInvestigation.effective_status, func.count())
        .where(*predicate, ~unresolved_predicate)
        .group_by(VexInvestigation.effective_status)
    ).all()
    reconciliation_rows = db.execute(
        select(VexInvestigation.reconciliation_status, func.count())
        .where(*predicate)
        .group_by(VexInvestigation.reconciliation_status)
    ).all()

    by_status = {str(k): int(v) for k, v in status_rows}
    by_reconciliation = {str(k): int(v) for k, v in reconciliation_rows}

    affected = by_status.get("AFFECTED", 0)
    not_affected = by_status.get("NOT_AFFECTED", 0)
    fixed = by_status.get("FIXED", 0)
    under_investigation = by_status.get("UNDER_INVESTIGATION", 0)

    return {
        "total_contexts": affected + not_affected + fixed + under_investigation,
        "affected_count": affected,
        "not_affected_count": not_affected,
        "fixed_count": fixed,
        "under_investigation_count": under_investigation,
        "matched_count": by_reconciliation.get("MATCHED", 0),
        "analyzer_only_count": by_reconciliation.get("ANALYZER_ONLY", 0),
        "vex_only_count": by_reconciliation.get("VEX_ONLY", 0),
        "conflict_review_count": by_reconciliation.get("CONFLICT_REVIEW_REQUIRED", 0),
        "revalidation_required_count": by_reconciliation.get("REVALIDATION_REQUIRED", 0),
        "unresolved_mapping_count": by_reconciliation.get("UNRESOLVED_MAPPING", 0),
        "needs_review_count": sum(by_reconciliation.get(k, 0) for k in _NEEDS_REVIEW),
    }


def vex_top_affected_components(
    db: Session, *, tenant_id: int, sbom_ids, limit: int = 10
) -> list[tuple[int | None, str, str]]:
    """Components carrying AFFECTED contexts, most affected first.

    Deterministically ordered — the previous implementation sliced whatever
    dict iteration happened to yield, so "top" was arbitrary.
    """
    rows = db.execute(
        select(
            VexInvestigation.component_id,
            VexInvestigation.canonical_vulnerability_id,
            VexInvestigation.effective_status,
        )
        .where(
            *_current_contexts(tenant_id, sbom_ids),
            VexInvestigation.effective_status == "AFFECTED",
        )
        .order_by(VexInvestigation.component_id, VexInvestigation.canonical_vulnerability_id)
        .limit(limit)
    ).all()
    return [(r[0], str(r[1]), str(r[2])) for r in rows]


def vex_severity_filter_clause(severity: str):
    """EXISTS predicate matching contexts whose analyser finding has ``severity``.

    Severity lives on ``AnalysisFinding``, never on the context — VEX does not
    rewrite it (VEX-DATA-005) — so filtering needs a correlated subquery back
    to the findings. It belongs here rather than in the router because routers
    may not query AnalysisFinding directly (``docs/metric-conventions.md``).

    A VEX-only context has no analyser finding and therefore no severity, so
    it is correctly excluded whenever a severity filter is applied.
    """
    return (
        select(AnalysisFinding.id)
        .where(
            AnalysisFinding.component_id == VexInvestigation.component_id,
            AnalysisFinding.tenant_id == VexInvestigation.tenant_id,
            func.upper(AnalysisFinding.vuln_id) == VexInvestigation.canonical_vulnerability_id,
            func.lower(AnalysisFinding.severity) == severity.strip().lower(),
        )
        .exists()
    )


__all__ = [
    "latest_successful_run_id_for_sbom",
    "vex_severity_filter_clause",
    "vex_context_counts",
    "vex_top_affected_components",
    "vex_component_findings",
    "vex_current_findings_for_sbom",
    "vex_run_query_error_count",
    "vex_run_source_summary",
    "vex_sbom_finding_pairs",
]
