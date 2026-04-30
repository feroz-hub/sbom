"""
Analysis runs and findings router.

Routes:
  GET /api/runs                                  list analysis runs with filtering/pagination
  GET /api/runs/{run_id}                         get single run
  GET /api/runs/{run_id}/findings                list findings with severity filter and pagination
  GET /api/runs/{run_id}/findings-enriched       list findings + per-CVE KEV/EPSS/composite risk score
"""

import json
import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, EpssScore, SBOMSource
from ..schemas import AnalysisFindingOut, AnalysisRunOut
from ..services.risk_score import (
    EPSS_AMPLIFIER,
    KEV_MULTIPLIER,
    _resolve_cvss,
)
from ..sources.kev import lookup_kev_set_memoized

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["runs"])


def _coerce_optional_int(raw: str | None) -> int | None:
    """Lenient integer coercion for optional query params.

    Accepts None, empty string, whitespace, and junk like 'NaN'/'undefined'
    (which JavaScript produces when callers carelessly serialize NaN) as
    "filter not set". Any other non-integer raises 422 via Pydantic's normal
    path, so real typos still surface — the goal is only to tolerate the
    benign empty-string case, not to mask caller bugs silently.
    """
    if raw is None:
        return None
    s = raw.strip()
    if s == "" or s.lower() in {"nan", "undefined", "null"}:
        return None
    try:
        value = int(s)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=[{"loc": ["query", "int"], "msg": f"not a valid integer: {s!r}"}],
        )
    if value < 1:
        raise HTTPException(
            status_code=422,
            detail=[{"loc": ["query", "int"], "msg": "must be >= 1"}],
        )
    return value


@router.get("/runs", response_model=list[AnalysisRunOut])
def list_analysis_runs(
    sbom_id: str | None = Query(None),
    project_id: str | None = Query(None),
    run_status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    cursor: int | None = Query(
        None,
        description="Keyset pagination: return runs with id strictly less than this value (desc by id). When set, page offset is ignored.",
    ),
    response: Response = None,
    db: Session = Depends(get_db),
):
    sbom_id = _coerce_optional_int(sbom_id)
    project_id = _coerce_optional_int(project_id)
    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 500))

    # Subquery: get sbom_name. Use an OUTER join below so that runs whose
    # parent SBOM has been deleted (orphaned runs) still appear in the list
    # — otherwise an inner join silently drops them and the user can no
    # longer access the historical findings/PDF for those runs.
    sbom_subq = db.query(SBOMSource.id.label("sbom_id"), SBOMSource.sbom_name.label("sbom_name")).subquery()

    # Base queries
    base = select(AnalysisRun)
    count = select(func.count(AnalysisRun.id))

    if sbom_id is not None:
        base = base.where(AnalysisRun.sbom_id == sbom_id)
        count = count.where(AnalysisRun.sbom_id == sbom_id)

    if project_id is not None:
        base = base.where(AnalysisRun.project_id == project_id)
        count = count.where(AnalysisRun.project_id == project_id)

    if run_status:
        from ..services.analysis_service import normalize_run_status
        norm = normalize_run_status(run_status)
        base = base.where(AnalysisRun.run_status == norm)
        count = count.where(AnalysisRun.run_status == norm)

    # Total count
    total = db.execute(count).scalar_one()

    # Main query with subquery LEFT OUTER join — preserves orphaned runs.
    stmt = (
        base.outerjoin(sbom_subq, AnalysisRun.sbom_id == sbom_subq.c.sbom_id)
        .add_columns(sbom_subq.c.sbom_name)
        .order_by(AnalysisRun.id.desc())
    )
    if cursor is not None:
        if cursor < 1:
            raise HTTPException(status_code=422, detail="cursor must be >= 1")
        stmt = stmt.where(AnalysisRun.id < cursor)
        stmt = stmt.limit(page_size)
    else:
        offset = (page - 1) * page_size
        stmt = stmt.limit(page_size).offset(offset)

    # Execute
    rows = db.execute(stmt).all()

    # Format response. Fall back to the run's own cached sbom_name (set by
    # the analytics backfill) when the live SBOMSource row has been deleted.
    items = []
    for run, sbom_name in rows:
        run_dict = {k: v for k, v in run.__dict__.items() if not k.startswith("_")}
        run_dict["sbom_name"] = sbom_name or run_dict.get("sbom_name")
        items.append(run_dict)

    # Header
    if response is not None:
        response.headers["X-Total-Count"] = str(total)
        if items and len(items) == page_size:
            last = items[-1]
            rid = last.get("id") if isinstance(last, dict) else getattr(last, "id", None)
            if rid is not None:
                response.headers["X-Next-Cursor"] = str(rid)

    return items


# -----------------------------------------------------------------------------
# Compare picker support (ADR-0008 §5 Region 1)
# -----------------------------------------------------------------------------
# Both endpoints sit BEFORE ``/runs/{run_id}`` because FastAPI matches in
# declaration order. Putting them after would route ``/runs/recent`` into the
# path-param route and fail with a 422 on the int coercion.


@router.get("/runs/recent", response_model=list)
def list_recent_runs(
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Most recent analysis runs (any status). Powers the picker's default open state."""
    from ..models import Projects
    from ..schemas_compare import RunSummary

    sbom_subq = (
        db.query(SBOMSource.id.label("sbom_id"), SBOMSource.sbom_name.label("sbom_name"))
        .subquery()
    )
    proj_subq = (
        db.query(Projects.id.label("project_id"), Projects.project_name.label("project_name"))
        .subquery()
    )
    stmt = (
        select(AnalysisRun, sbom_subq.c.sbom_name, proj_subq.c.project_name)
        .outerjoin(sbom_subq, AnalysisRun.sbom_id == sbom_subq.c.sbom_id)
        .outerjoin(proj_subq, AnalysisRun.project_id == proj_subq.c.project_id)
        .order_by(AnalysisRun.id.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).all()
    return [
        RunSummary(
            id=run.id,
            sbom_id=run.sbom_id,
            sbom_name=sbom_name or run.sbom_name,
            project_id=run.project_id,
            project_name=project_name,
            run_status=(run.run_status or "").upper(),
            completed_on=run.completed_on,
            started_on=run.started_on,
            total_findings=int(run.total_findings or 0),
            total_components=int(run.total_components or 0),
        ).model_dump()
        for run, sbom_name, project_name in rows
    ]


@router.get("/runs/search", response_model=list)
def search_runs(
    q: str = Query("", description="Substring match on sbom_name, project_name, or run id"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Picker autocomplete. Empty ``q`` falls through to the recent-runs ordering."""
    from sqlalchemy import or_

    from ..models import Projects
    from ..schemas_compare import RunSummary

    needle = (q or "").strip()
    sbom_subq = (
        db.query(SBOMSource.id.label("sbom_id"), SBOMSource.sbom_name.label("sbom_name"))
        .subquery()
    )
    proj_subq = (
        db.query(Projects.id.label("project_id"), Projects.project_name.label("project_name"))
        .subquery()
    )
    stmt = (
        select(AnalysisRun, sbom_subq.c.sbom_name, proj_subq.c.project_name)
        .outerjoin(sbom_subq, AnalysisRun.sbom_id == sbom_subq.c.sbom_id)
        .outerjoin(proj_subq, AnalysisRun.project_id == proj_subq.c.project_id)
    )
    if needle:
        like = f"%{needle}%"
        run_id_clause: list = []
        try:
            rid = int(needle)
            run_id_clause.append(AnalysisRun.id == rid)
        except ValueError:
            pass
        stmt = stmt.where(
            or_(
                sbom_subq.c.sbom_name.ilike(like),
                proj_subq.c.project_name.ilike(like),
                *run_id_clause,
            )
        )
    stmt = stmt.order_by(AnalysisRun.id.desc()).limit(limit)
    rows = db.execute(stmt).all()
    return [
        RunSummary(
            id=run.id,
            sbom_id=run.sbom_id,
            sbom_name=sbom_name or run.sbom_name,
            project_id=run.project_id,
            project_name=project_name,
            run_status=(run.run_status or "").upper(),
            completed_on=run.completed_on,
            started_on=run.started_on,
            total_findings=int(run.total_findings or 0),
            total_components=int(run.total_components or 0),
        ).model_dump()
        for run, sbom_name, project_name in rows
    ]


@router.get("/runs/{run_id}", response_model=AnalysisRunOut)
def get_analysis_run(run_id: int, db: Session = Depends(get_db)):
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return run


@router.get("/runs/{run_id}/findings", response_model=list[AnalysisFindingOut])
def list_run_findings(
    run_id: int,
    severity: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    response: Response = None,
    db: Session = Depends(get_db),
):
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    base = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
    count = select(func.count(AnalysisFinding.id)).where(AnalysisFinding.analysis_run_id == run_id)

    if severity:
        norm = severity.strip().upper()
        base = base.where(AnalysisFinding.severity == norm)
        count = count.where(AnalysisFinding.severity == norm)

    total = db.execute(count).scalar_one()

    stmt = base.order_by(AnalysisFinding.score.desc()).limit(page_size).offset(offset)
    items = db.execute(stmt).scalars().all()

    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return items


def _cve_aliases_for(finding: AnalysisFinding) -> list[str]:
    """Pull every CVE ID we can find on a finding (vuln_id + aliases JSON)."""
    ids: list[str] = []
    if finding.vuln_id:
        ids.extend(_CVE_RE.findall(finding.vuln_id))
    if finding.aliases:
        try:
            parsed = json.loads(finding.aliases)
            if isinstance(parsed, list):
                for a in parsed:
                    if isinstance(a, str):
                        ids.extend(_CVE_RE.findall(a))
        except (TypeError, ValueError):
            ids.extend(_CVE_RE.findall(finding.aliases))
    return sorted({i.upper() for i in ids if i})


@router.get("/runs/{run_id}/findings-enriched")
def list_run_findings_enriched(
    run_id: int,
    severity: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    response: Response = None,
    db: Session = Depends(get_db),
):
    """
    Findings list enriched with per-CVE KEV flag, EPSS score/percentile, and the
    composite risk score used by ``/api/sboms/{id}/risk-summary``.

    Same paging/filtering surface as ``/api/runs/{run_id}/findings``; intended
    for the next-gen findings table that surfaces exploit-likelihood signals
    inline. KEV / EPSS lookups are cached (24h DB cache + 60s in-process memo)
    so the hot path is cheap on warm caches.
    """
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    page = 1 if page < 1 else page
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    base = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)
    count = select(func.count(AnalysisFinding.id)).where(AnalysisFinding.analysis_run_id == run_id)

    if severity:
        norm = severity.strip().upper()
        base = base.where(AnalysisFinding.severity == norm)
        count = count.where(AnalysisFinding.severity == norm)

    total = db.execute(count).scalar_one()

    stmt = base.order_by(AnalysisFinding.score.desc()).limit(page_size).offset(offset)
    findings = db.execute(stmt).scalars().all()

    # Collect every CVE alias on the page so KEV/EPSS lookups are batched.
    finding_cves: dict[int, list[str]] = {f.id: _cve_aliases_for(f) for f in findings}
    all_cves: set[str] = set()
    for cves in finding_cves.values():
        all_cves.update(cves)
    cve_list = sorted(all_cves)

    kev_set: set[str] = lookup_kev_set_memoized(db, cve_list) if cve_list else set()
    # Read percentile + epss directly so we get the full row (memoized helper
    # only returns probability, no percentile).
    epss_map: dict[str, dict[str, float | None]] = {}
    if cve_list:
        rows = db.execute(
            select(EpssScore.cve_id, EpssScore.epss, EpssScore.percentile).where(
                EpssScore.cve_id.in_(cve_list)
            )
        ).all()
        for cve_id, epss_val, percentile in rows:
            epss_map[cve_id] = {"epss": epss_val, "percentile": percentile}

    items: list[dict] = []
    for f in findings:
        cves = finding_cves.get(f.id, [])
        # Per-finding EPSS = max EPSS across any CVE alias on the finding.
        epss = 0.0
        epss_percentile: float | None = None
        for c in cves:
            entry = epss_map.get(c)
            if entry is None:
                continue
            v = entry.get("epss") or 0.0
            if v > epss:
                epss = float(v)
                p = entry.get("percentile")
                epss_percentile = float(p) if p is not None else None

        in_kev = any(c in kev_set for c in cves)
        cvss = _resolve_cvss(f)
        exploit_factor = 1.0 + EPSS_AMPLIFIER * epss
        kev_multiplier = KEV_MULTIPLIER if in_kev else 1.0
        risk_score = round(cvss * exploit_factor * kev_multiplier, 2)

        items.append(
            {
                "id": f.id,
                "analysis_run_id": f.analysis_run_id,
                "component_id": f.component_id,
                "vuln_id": f.vuln_id,
                "source": f.source,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "score": f.score,
                "vector": f.vector,
                "published_on": f.published_on,
                "reference_url": f.reference_url,
                "cwe": f.cwe,
                "cpe": f.cpe,
                "component_name": f.component_name,
                "component_version": f.component_version,
                "fixed_versions": f.fixed_versions,
                "attack_vector": f.attack_vector,
                "cvss_version": f.cvss_version,
                "aliases": f.aliases,
                # Enriched fields
                "in_kev": in_kev,
                "epss": round(epss, 4),
                "epss_percentile": (
                    round(epss_percentile, 4) if epss_percentile is not None else None
                ),
                "risk_score": risk_score,
                "cve_aliases": cves,
            }
        )

    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return items
