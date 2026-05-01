"""findings.kev_in_scope — single canonical KEV-membership metric.

Spec §3.3. **The lock for Bug 1.** Run-detail and dashboard both call this;
they must agree.

The implementation reads candidate finding rows once, parses ``vuln_id``
and ``aliases`` to collect every CVE-like string, batch-fetches the KEV
overlap, and counts finding-rows whose set intersects the KEV catalog.

Returning row-count (not distinct-CVE-count) keeps the dashboard tile
matching the run-detail badge "{N} KEV", which is the user-facing
reconciliation users will see first.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding
from ..sources.kev import lookup_kev_set_memoized
from ._helpers import (
    collect_kev_candidates,
    is_kev_listed,
    latest_run_per_sbom_subquery,
)
from .base import KevScope
from .cache import memoize_with_ttl


def findings_kev_in_scope(
    db: Session, *, scope: KevScope, run_id: int | None = None
) -> int:
    """findings.kev_in_scope — see metrics-spec.md §3.3.

    Counts finding-rows in ``scope`` whose ``vuln_id`` or any parsed CVE
    alias is in the local KEV mirror. Membership predicate is the shared
    ``is_kev_listed`` helper.

    Scopes:
      * ``scope="run"`` — finding-rows in run ``run_id``.
      * ``scope="latest_per_sbom"`` — finding-rows in the latest successful
        run of each SBOM.

    Reconciliation (spec invariant I3):
      ``findings_kev_in_scope(scope="latest_per_sbom") ==
       Σ over SBOMs of findings_kev_in_scope(scope="run", run_id=latest_for_sbom)``
    """
    if scope == "run":
        if run_id is None:
            raise ValueError("run_id is required when scope='run'")
        return _kev_count_for_run(db, run_id=run_id)
    if scope == "latest_per_sbom":
        return memoize_with_ttl(
            name="findings.kev_in_scope.latest_per_sbom",
            ttl_seconds=5 * 60,  # spec §6
            db=db,
            compute=lambda: _kev_count_latest_per_sbom(db),
        )
    raise ValueError(f"unknown scope: {scope!r}")


def _kev_count_for_run(db: Session, *, run_id: int) -> int:
    rows = db.execute(
        select(
            AnalysisFinding.id,
            AnalysisFinding.vuln_id,
            AnalysisFinding.aliases,
        ).where(AnalysisFinding.analysis_run_id == run_id)
    ).all()
    return _count_kev_listed(db, rows)


def _kev_count_latest_per_sbom(db: Session) -> int:
    latest = latest_run_per_sbom_subquery()
    rows = db.execute(
        select(
            AnalysisFinding.id,
            AnalysisFinding.vuln_id,
            AnalysisFinding.aliases,
        ).where(AnalysisFinding.analysis_run_id.in_(latest))
    ).all()
    return _count_kev_listed(db, rows)


def _count_kev_listed(db: Session, rows) -> int:
    """Walk rows once, parse aliases, batch KEV lookup, count matches.

    The row-walk is O(R); the KEV lookup is O(distinct CVEs). For our scale
    (~10k findings, ~1.2k KEV entries) this is well under the ETag budget.
    """
    if not rows:
        return 0
    # SQLAlchemy returns Row objects; aliases helper takes a row-like with
    # .vuln_id and .aliases — use a tiny shim to avoid attribute confusion.
    per_row, all_cves = collect_kev_candidates(
        _RowShim(r.id, r.vuln_id, r.aliases) for r in rows
    )
    if not all_cves:
        return 0
    kev_set = lookup_kev_set_memoized(db, sorted(all_cves))
    return sum(1 for _id, cves in per_row if any(c in kev_set for c in cves))


class _RowShim:
    """Tiny adapter so the helper sees ``r.vuln_id`` / ``r.aliases``.

    SQLAlchemy 2.x rows expose attributes by column-name, so this is mostly
    redundant — but constructing the shim makes the helper API explicit and
    keeps the helper unaware of SQLAlchemy row internals.
    """

    __slots__ = ("id", "vuln_id", "aliases")

    def __init__(self, id_: int, vuln_id: str | None, aliases: str | None) -> None:
        self.id = id_
        self.vuln_id = vuln_id
        self.aliases = aliases


__all__ = ["findings_kev_in_scope"]
