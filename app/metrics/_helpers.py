"""Shared SQL building blocks. The only place these clauses live.

Spec §3.5. Inline copies of the latest-run-per-SBOM CTE or the KEV-alias
predicate at metric call sites are forbidden — the consistency tests in
Phase 5 grep for the shapes.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import ScalarSelect, func, select

from ..models import AnalysisRun
from ..services.vulnerability_ids import cves_for_finding
from .base import COMPLETED_RUN_STATUSES


def active_head_sbom_ids_subquery() -> ScalarSelect:
    """Scalar subquery of active HEAD version sbom_source.ids."""
    from ..models import SBOMSource

    return (
        select(SBOMSource.id)
        .where(SBOMSource.is_active.is_(True))
        .where(
            ~SBOMSource.id.in_(select(SBOMSource.parent_id).where(SBOMSource.parent_id.is_not(None)).scalar_subquery())
        )
        .scalar_subquery()
    )


def latest_run_per_sbom_subquery() -> ScalarSelect:
    """Scalar subquery: latest *successful* ``analysis_run.id`` per SBOM.

    ``MAX(id)`` over ``MAX(completed_on)`` because ``id`` is monotonic with
    the writer's serialisation per ADR-0001 and is ``NOT NULL``, while
    ``completed_on`` can drift for long-running scans.
    """
    return (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        .where(AnalysisRun.sbom_id.in_(active_head_sbom_ids_subquery()))
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )


def latest_run_per_sbom_as_of_subquery(as_of_iso: str) -> ScalarSelect:
    """Scalar subquery: latest successful run per SBOM completed on or before ``as_of_iso``.

    Filters by ``completed_on`` (not ``started_on``) — a run that started
    before the as-of date but completed after has not yet contributed to
    the as-of snapshot.
    """
    return (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
        .where(AnalysisRun.completed_on <= as_of_iso)
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )


def is_kev_listed(vuln_id: str | None, aliases: str | None, kev_set: set[str]) -> bool:
    """True iff any CVE id from ``vuln_id ∪ parsed(aliases)`` is in ``kev_set``.

    The single KEV-membership predicate. Run-detail and dashboard both call
    this; that consolidation is the lock for Bug 1.
    """
    for cve in cves_for_finding(vuln_id, aliases):
        if cve in kev_set:
            return True
    return False


def finding_key(
    vuln_id: str | None,
    component_name: str | None,
    component_version: str | None,
) -> tuple[str, str, str]:
    """The locked (vuln_id, component_name, component_version) dedup tuple.

    Used by ``findings.distinct_lifetime``, ``findings.distinct_active_as_of``,
    ``findings.daily_distinct_active``, ``findings.net_change``, and the
    legacy ``compute_findings_resolved_total`` helper. **One definition.**
    """
    return ((vuln_id or ""), (component_name or ""), (component_version or ""))


def collect_kev_candidates(rows: Iterable) -> tuple[list[tuple[int, list[str]]], set[str]]:
    """Walk finding rows and parse out every CVE-like alias.

    Returns ``(per_row_cves, all_cves)`` so the caller can issue a single
    KEV lookup for ``all_cves`` and then test each row's ``cves`` against
    the resulting set. Avoids per-row queries.

    Each row must expose ``id``, ``vuln_id``, and ``aliases``.
    """
    per_row: list[tuple[int, list[str]]] = []
    all_cves: set[str] = set()
    for r in rows:
        cves = cves_for_finding(r.vuln_id, r.aliases)
        per_row.append((r.id, cves))
        all_cves.update(cves)
    return per_row, all_cves


__all__ = [
    "latest_run_per_sbom_subquery",
    "latest_run_per_sbom_as_of_subquery",
    "cves_for_finding",
    "is_kev_listed",
    "finding_key",
    "collect_kev_candidates",
]
