"""portfolio.risk_map + portfolio.risk_matrix — interactive risk geometry.

Two read-models for the dashboard's visual layer, both Convention A
(latest successful run per SBOM):

* **risk_map** — one cell per SBOM for the treemap: sized by finding
  count, coloured by the *dominant* (worst-present) severity tier. No
  invented composite score — the opaque "Risk Index" was deliberately
  retired (docs/risk-index.md); size and colour are both directly
  observable quantities.

* **risk_matrix** — one point per distinct finding for the
  impact × exploitability scatter: CVSS on one axis (impact), max EPSS
  across the finding's CVEs on the other (exploitability), KEV and
  fix-availability as point modifiers. Capped at ``limit`` points,
  keeping KEV > high-EPSS > high-CVSS first so the cap never drops the
  points that matter.

Severity counts for the map come straight off the ``analysis_run``
denormalised columns (writer-side invariant), so the treemap reconciles
with the run-detail header by construction.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, EpssScore, Projects
from ..sources.kev import lookup_kev_set_memoized
from ._helpers import cves_for_finding, finding_key, latest_run_per_sbom_subquery
from .cache import memoize_with_ttl

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def portfolio_risk_map(db: Session) -> dict:
    """portfolio.risk_map — treemap cells, one per analysed SBOM."""
    return memoize_with_ttl(
        name="portfolio.risk_map",
        ttl_seconds=5 * 60,
        db=db,
        compute=lambda: _risk_map_uncached(db),
    )


def _risk_map_uncached(db: Session) -> dict:
    latest = latest_run_per_sbom_subquery()
    rows = db.execute(
        select(
            AnalysisRun.id,
            AnalysisRun.sbom_id,
            AnalysisRun.sbom_name,
            AnalysisRun.project_id,
            AnalysisRun.total_findings,
            AnalysisRun.critical_count,
            AnalysisRun.high_count,
            AnalysisRun.medium_count,
            AnalysisRun.low_count,
            AnalysisRun.unknown_count,
            AnalysisRun.completed_on,
        ).where(AnalysisRun.id.in_(latest))
    ).all()

    project_ids = {r.project_id for r in rows if r.project_id is not None}
    project_names: dict[int, str] = {}
    if project_ids:
        for pid, pname in db.execute(
            select(Projects.id, Projects.project_name).where(Projects.id.in_(project_ids))
        ).all():
            project_names[pid] = pname

    items = []
    for r in rows:
        sev = {
            "critical": int(r.critical_count or 0),
            "high": int(r.high_count or 0),
            "medium": int(r.medium_count or 0),
            "low": int(r.low_count or 0),
            "unknown": int(r.unknown_count or 0),
        }
        dominant = next((s for s in _SEVERITY_ORDER if sev[s] > 0), "none")
        items.append(
            {
                "sbom_id": r.sbom_id,
                "run_id": r.id,
                "name": r.sbom_name or f"SBOM {r.sbom_id}",
                "project": project_names.get(r.project_id),
                "findings_total": int(r.total_findings or 0),
                **sev,
                "dominant": dominant,
                "last_analysed": r.completed_on,
            }
        )
    items.sort(key=lambda i: -i["findings_total"])
    return {"items": items, "schema_version": 1}


def portfolio_risk_matrix(db: Session, *, limit: int = 300) -> dict:
    """portfolio.risk_matrix — impact × exploitability scatter points."""
    return memoize_with_ttl(
        name="portfolio.risk_matrix",
        ttl_seconds=15 * 60,
        db=db,
        key_extra=(limit,),
        compute=lambda: _risk_matrix_uncached(db, limit),
    )


def _risk_matrix_uncached(db: Session, limit: int) -> dict:
    latest = latest_run_per_sbom_subquery()
    rows = db.execute(
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.aliases,
            AnalysisFinding.severity,
            AnalysisFinding.score,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
            AnalysisFinding.fixed_versions,
        ).where(AnalysisFinding.analysis_run_id.in_(latest))
    ).all()

    # Dedup to distinct findings (Convention B identity), keeping max CVSS.
    by_key: dict[tuple[str, str, str], dict] = {}
    all_cves: set[str] = set()
    for vuln, aliases, sev, score, comp, ver, fixed in rows:
        key = finding_key(vuln, comp, ver)
        cves = cves_for_finding(vuln, aliases)
        all_cves.update(cves)
        entry = by_key.get(key)
        cvss = float(score) if score is not None else None
        if entry is None:
            by_key[key] = {
                "vuln_id": vuln or "",
                "component": f"{comp or '?'}@{ver or '?'}",
                "severity": (sev or "unknown").lower(),
                "cvss": cvss,
                "cves": cves,
                "has_fix": _has_fix(fixed),
            }
        else:
            if cvss is not None and (entry["cvss"] is None or cvss > entry["cvss"]):
                entry["cvss"] = cvss
            entry["has_fix"] = entry["has_fix"] or _has_fix(fixed)

    cve_list = sorted(all_cves)
    epss_by_cve: dict[str, float] = {}
    if cve_list:
        for cve, epss in db.execute(
            select(func.upper(EpssScore.cve_id), EpssScore.epss)
            .where(func.upper(EpssScore.cve_id).in_(cve_list))
            .where(EpssScore.epss.is_not(None))
        ).all():
            epss_by_cve[cve] = float(epss or 0.0)
    kev_set = lookup_kev_set_memoized(db, cve_list) if cve_list else set()

    points = []
    unplotted = 0
    for entry in by_key.values():
        if entry["cvss"] is None:
            unplotted += 1
            continue
        cves = entry.pop("cves")
        entry["epss"] = round(max((epss_by_cve.get(c, 0.0) for c in cves), default=0.0), 4)
        entry["kev"] = any(c in kev_set for c in cves)
        points.append(entry)

    # KEV first, then exploitability, then impact — the cap keeps what matters.
    points.sort(key=lambda p: (not p["kev"], -p["epss"], -p["cvss"]))
    return {
        "points": points[:limit],
        "total_distinct": len(by_key),
        "unplotted_no_cvss": unplotted,
        "limit": limit,
        "schema_version": 1,
    }


def _has_fix(fixed_versions: str | None) -> bool:
    if not fixed_versions:
        return False
    return fixed_versions.strip() not in ("", "[]")


__all__ = ["portfolio_risk_map", "portfolio_risk_matrix"]
