"""findings.high_epss_in_scope — exploitability via EPSS percentile.

The companion to ``kev.py``. KEV answers "actively exploited *now*"; EPSS
answers "*likely* to be exploited" (FIRST.org's modelled probability). A
finding counts when any of its CVEs sits at/above the high-EPSS percentile.

Structure mirrors ``findings_kev_in_scope`` exactly: collect each finding's
CVEs, batch-look-up the LOCAL ``epss_score`` mirror, count finding-rows whose
CVE set intersects the high-EPSS set. The lookup reads the cache table only —
never the FIRST.org API — so a posture render never blocks on the network.
Uncached CVEs are treated as not-high (their ``epss_score`` row is absent),
matching the scorer's documented "missing = 0" behaviour.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, EpssScore
from ._helpers import collect_kev_candidates, latest_run_per_sbom_subquery
from .base import KevScope
from .cache import memoize_with_ttl

# High-EPSS boundary as a 0..1 fraction (``epss_score.percentile`` units).
# Mirrors the frontend ``HIGH_EPSS_PERCENTILE = 90`` (expressed there in
# percent). Keep the two in sync: the dashboard tile, the ``?epss=`` drill-down,
# and this count must agree on what "likely exploited" means.
HIGH_EPSS_PERCENTILE = 0.90


def findings_high_epss_in_scope(
    db: Session, *, scope: KevScope, run_id: int | None = None
) -> int:
    """findings.high_epss_in_scope — count of findings *likely to be exploited*.

    A finding-row counts when any CVE from its ``vuln_id`` or parsed
    ``aliases`` has a cached EPSS percentile >= :data:`HIGH_EPSS_PERCENTILE`.

    Scopes mirror :func:`app.metrics.findings_kev_in_scope`:
      * ``scope="run"`` — finding-rows in run ``run_id``.
      * ``scope="latest_per_sbom"`` — finding-rows in the latest successful
        run of each SBOM (the dashboard posture scope).
    """
    if scope == "run":
        if run_id is None:
            raise ValueError("run_id is required when scope='run'")
        return _high_epss_count_for_run(db, run_id=run_id)
    if scope == "latest_per_sbom":
        return memoize_with_ttl(
            name="findings.high_epss_in_scope.latest_per_sbom",
            ttl_seconds=5 * 60,  # spec §6 — same TTL as the KEV metric
            db=db,
            compute=lambda: _high_epss_count_latest_per_sbom(db),
        )
    raise ValueError(f"unknown scope: {scope!r}")


def _high_epss_count_for_run(db: Session, *, run_id: int) -> int:
    rows = db.execute(
        select(
            AnalysisFinding.id,
            AnalysisFinding.vuln_id,
            AnalysisFinding.aliases,
        ).where(AnalysisFinding.analysis_run_id == run_id)
    ).all()
    return _count_high_epss(db, rows)


def _high_epss_count_latest_per_sbom(db: Session) -> int:
    latest = latest_run_per_sbom_subquery()
    rows = db.execute(
        select(
            AnalysisFinding.id,
            AnalysisFinding.vuln_id,
            AnalysisFinding.aliases,
        ).where(AnalysisFinding.analysis_run_id.in_(latest))
    ).all()
    return _count_high_epss(db, rows)


def _count_high_epss(db: Session, rows) -> int:
    if not rows:
        return 0
    # ``collect_kev_candidates`` is a generic CVE collector despite the name —
    # walks rows once into (per_row_cves, all_cves) so EPSS is one lookup.
    per_row, all_cves = collect_kev_candidates(
        _RowShim(r.id, r.vuln_id, r.aliases) for r in rows
    )
    if not all_cves:
        return 0
    high = _high_epss_cve_set(db, sorted(all_cves))
    if not high:
        return 0
    return sum(1 for _id, cves in per_row if any(c in high for c in cves))


def _high_epss_cve_set(db: Session, cve_ids: list[str]) -> set[str]:
    """Subset of ``cve_ids`` whose cached EPSS percentile >= threshold.

    Reads ``epss_score`` directly (a cache table, not analysis_finding/run) —
    no FIRST.org fetch. Case is normalised on both sides so a lower-cased
    cached row still matches an upper-cased candidate.
    """
    if not cve_ids:
        return set()
    rows = db.execute(
        select(func.upper(EpssScore.cve_id))
        .where(func.upper(EpssScore.cve_id).in_(cve_ids))
        .where(EpssScore.percentile.is_not(None))
        .where(EpssScore.percentile >= HIGH_EPSS_PERCENTILE)
    ).all()
    return {r[0] for r in rows}


class _RowShim:
    """Adapter so ``collect_kev_candidates`` sees ``r.vuln_id`` / ``r.aliases``."""

    __slots__ = ("id", "vuln_id", "aliases")

    def __init__(self, id_: int, vuln_id: str | None, aliases: str | None) -> None:
        self.id = id_
        self.vuln_id = vuln_id
        self.aliases = aliases


__all__ = ["findings_high_epss_in_scope", "HIGH_EPSS_PERCENTILE"]
