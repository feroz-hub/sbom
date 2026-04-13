"""
Analysis runs and findings router.

Routes:
  GET /api/runs                         list analysis runs with filtering/pagination
  GET /api/runs/{run_id}                get single run
  GET /api/runs/{run_id}/findings       list findings with severity filter and pagination
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisFinding, AnalysisRun, SBOMSource
from ..schemas import AnalysisFindingOut, AnalysisRunOut

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
        norm = run_status.strip().upper()
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
