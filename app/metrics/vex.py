"""VEX metrics — analyser-finding reads backing the VEX evidence surfaces.

These are the finding-shaped queries the VEX services need. They live here
rather than in ``app/services/lifecycle/vex_provider.py`` because router and
service code must not query ``AnalysisFinding`` / ``AnalysisRun`` directly; see
``docs/metric-conventions.md`` and the architectural test
``tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics``.

Both functions below are **Convention C (total raw rows)**: they return the raw
evidence rows for a component or SBOM, not a latest-state count, because the
VEX evidence panel deliberately shows every run's finding as history. The VEX
investigation queue introduced by the VEX Dashboard & Investigation workstream
will use Convention A instead (latest successful run per eligible SBOM, via
:func:`app.metrics._helpers.latest_run_per_sbom_subquery`) — see GAP-008 in
``docs/requirements/vex-dashboard-investigation.md``. Do not "fix" the scope
here; that change belongs to PR-2 of that workstream, together with its tests.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, SBOMComponent


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


__all__ = ["vex_component_findings", "vex_sbom_finding_pairs"]
