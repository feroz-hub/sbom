"""
Periodic analysis schedules — CRUD + actions router.

Endpoints
---------
Project-scope:
    POST   /api/projects/{id}/schedule    create or replace
    GET    /api/projects/{id}/schedule
    PATCH  /api/projects/{id}/schedule
    DELETE /api/projects/{id}/schedule

SBOM-scope (overrides project cascade):
    POST   /api/sboms/{id}/schedule       create or replace SBOM-level override
    GET    /api/sboms/{id}/schedule       returns inherited project schedule if no override
    PATCH  /api/sboms/{id}/schedule
    DELETE /api/sboms/{id}/schedule       removes override; SBOM falls back to cascade

Operator surface:
    GET    /api/schedules                 flat list (filter by scope/enabled)
    POST   /api/schedules/{id}/run-now    fire immediately, does NOT change next_run_at
    POST   /api/schedules/{id}/pause      enabled=false
    POST   /api/schedules/{id}/resume     enabled=true, recomputes next_run_at
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AnalysisSchedule, Projects, SBOMSource
from ..schemas import ScheduleOut, ScheduleResolved, ScheduleUpsert
from ..services.schedule_resolver import resolve_for_sbom
from ..services.scheduling import (
    ScheduleSpec,
    ScheduleValidationError,
    compute_next_run_at,
    to_iso,
    validate_spec,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["schedules"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _spec_from_payload(payload: ScheduleUpsert) -> ScheduleSpec:
    return ScheduleSpec(
        cadence=payload.cadence,
        cron_expression=payload.cron_expression,
        day_of_week=payload.day_of_week,
        day_of_month=payload.day_of_month,
        hour_utc=payload.hour_utc,
    )


def _spec_from_row(row: AnalysisSchedule) -> ScheduleSpec:
    return ScheduleSpec(
        cadence=row.cadence,
        cron_expression=row.cron_expression,
        day_of_week=row.day_of_week,
        day_of_month=row.day_of_month,
        hour_utc=row.hour_utc,
    )


def _apply_payload(row: AnalysisSchedule, payload: ScheduleUpsert, *, partial: bool) -> None:
    """Copy non-None fields from payload onto the ORM row.

    For PATCH (``partial=True``) we treat unset fields as "leave alone";
    for POST (``partial=False``) all fields are written so the result is
    fully derived from the payload.
    """
    data = payload.model_dump(exclude_unset=partial)
    for field in (
        "cadence",
        "cron_expression",
        "day_of_week",
        "day_of_month",
        "hour_utc",
        "timezone",
        "enabled",
        "min_gap_minutes",
    ):
        if field in data:
            setattr(row, field, data[field])
    if data.get("modified_by"):
        row.modified_by = data["modified_by"]


def _validate_or_422(spec: ScheduleSpec) -> None:
    try:
        validate_spec(spec)
    except ScheduleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _refresh_next_run_at(row: AnalysisSchedule) -> None:
    """Recompute next_run_at from the row's cadence and the current clock.

    Called after every create / patch / resume so the tick scanner sees a
    correct cursor without waiting for the row to drift naturally.
    """
    if not row.enabled:
        row.next_run_at = None
        return
    nxt = compute_next_run_at(_spec_from_row(row), _now())
    row.next_run_at = to_iso(nxt)


def _get_project_or_404(db: Session, project_id: int) -> Projects:
    proj = db.get(Projects, project_id)
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj


def _get_sbom_or_404(db: Session, sbom_id: int) -> SBOMSource:
    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


def _serialize(row: AnalysisSchedule) -> dict[str, Any]:
    return {
        "id": row.id,
        "scope": row.scope,
        "project_id": row.project_id,
        "sbom_id": row.sbom_id,
        "cadence": row.cadence,
        "cron_expression": row.cron_expression,
        "day_of_week": row.day_of_week,
        "day_of_month": row.day_of_month,
        "hour_utc": row.hour_utc,
        "timezone": row.timezone,
        "enabled": bool(row.enabled),
        "next_run_at": row.next_run_at,
        "last_run_at": row.last_run_at,
        "last_run_status": row.last_run_status,
        "last_run_id": row.last_run_id,
        "consecutive_failures": row.consecutive_failures or 0,
        "min_gap_minutes": row.min_gap_minutes or 60,
        "created_on": row.created_on,
        "created_by": row.created_by,
        "modified_on": row.modified_on,
        "modified_by": row.modified_by,
    }


# ---------------------------------------------------------------------------
# Project-scope endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/schedule",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_project_schedule(
    payload: ScheduleUpsert,
    project_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id)
    _validate_or_422(_spec_from_payload(payload))

    existing = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = AnalysisSchedule(
            scope="PROJECT",
            project_id=project_id,
            sbom_id=None,
            cadence=payload.cadence,
            created_on=to_iso(_now()),
            created_by=payload.modified_by,
        )
        db.add(existing)

    _apply_payload(existing, payload, partial=False)
    existing.modified_on = to_iso(_now())
    _refresh_next_run_at(existing)

    db.commit()
    db.refresh(existing)
    return _serialize(existing)


@router.get("/projects/{project_id}/schedule", response_model=ScheduleOut)
def get_project_schedule(project_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    _get_project_or_404(db, project_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this project")
    return _serialize(row)


@router.patch("/projects/{project_id}/schedule", response_model=ScheduleOut)
def patch_project_schedule(
    payload: ScheduleUpsert,
    project_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    _get_project_or_404(db, project_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No schedule configured for this project")

    _apply_payload(row, payload, partial=True)
    _validate_or_422(_spec_from_row(row))
    row.modified_on = to_iso(_now())
    _refresh_next_run_at(row)

    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/projects/{project_id}/schedule", status_code=status.HTTP_200_OK)
def delete_project_schedule(project_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    _get_project_or_404(db, project_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "PROJECT",
            AnalysisSchedule.project_id == project_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return {"status": "no_schedule"}
    db.delete(row)
    db.commit()
    return {"status": "deleted", "id": row.id}


# ---------------------------------------------------------------------------
# SBOM-scope endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/sboms/{sbom_id}/schedule",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_sbom_schedule(
    payload: ScheduleUpsert,
    sbom_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id)
    _validate_or_422(_spec_from_payload(payload))

    existing = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = AnalysisSchedule(
            scope="SBOM",
            project_id=None,
            sbom_id=sbom_id,
            cadence=payload.cadence,
            created_on=to_iso(_now()),
            created_by=payload.modified_by,
        )
        db.add(existing)

    _apply_payload(existing, payload, partial=False)
    existing.modified_on = to_iso(_now())
    _refresh_next_run_at(existing)

    db.commit()
    db.refresh(existing)
    return _serialize(existing)


@router.get("/sboms/{sbom_id}/schedule", response_model=ScheduleResolved)
def get_sbom_schedule(sbom_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """
    Return the effective schedule for an SBOM.

    UI uses ``inherited=true`` to render an "Inherits from project" badge
    and offer an "Override" button.
    """
    _get_sbom_or_404(db, sbom_id)
    row = resolve_for_sbom(db, sbom_id)
    if row is None:
        return {"inherited": False, "schedule": None}
    return {
        "inherited": row.scope == "PROJECT",
        "schedule": _serialize(row),
    }


@router.patch("/sboms/{sbom_id}/schedule", response_model=ScheduleOut)
def patch_sbom_schedule(
    payload: ScheduleUpsert,
    sbom_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    _get_sbom_or_404(db, sbom_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No SBOM-level schedule. POST a new override or rely on the "
                "project-level cascade."
            ),
        )

    _apply_payload(row, payload, partial=True)
    _validate_or_422(_spec_from_row(row))
    row.modified_on = to_iso(_now())
    _refresh_next_run_at(row)

    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.delete("/sboms/{sbom_id}/schedule", status_code=status.HTTP_200_OK)
def delete_sbom_schedule(sbom_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    _get_sbom_or_404(db, sbom_id)
    row = db.execute(
        select(AnalysisSchedule).where(
            AnalysisSchedule.scope == "SBOM",
            AnalysisSchedule.sbom_id == sbom_id,
        )
    ).scalar_one_or_none()
    if row is None:
        return {"status": "no_override"}
    db.delete(row)
    db.commit()
    return {"status": "deleted", "id": row.id}


# ---------------------------------------------------------------------------
# Operator surface — flat list + per-row actions
# ---------------------------------------------------------------------------


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(
    scope: str | None = Query(None, description="PROJECT|SBOM"),
    enabled: bool | None = Query(None),
    project_id: int | None = Query(None, ge=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    response: Response = None,
    db: Session = Depends(get_db),
):
    base = select(AnalysisSchedule)
    if scope:
        norm = scope.strip().upper()
        if norm not in {"PROJECT", "SBOM"}:
            raise HTTPException(status_code=422, detail="scope must be PROJECT or SBOM")
        base = base.where(AnalysisSchedule.scope == norm)
    if enabled is not None:
        base = base.where(AnalysisSchedule.enabled.is_(enabled))
    if project_id is not None:
        base = base.where(AnalysisSchedule.project_id == project_id)

    total_rows = db.execute(base).scalars().all()  # small table, count-by-fetch is fine
    if response is not None:
        response.headers["X-Total-Count"] = str(len(total_rows))

    offset = (page - 1) * page_size
    return [_serialize(r) for r in total_rows[offset : offset + page_size]]


def _get_schedule_or_404(db: Session, schedule_id: int) -> AnalysisSchedule:
    row = db.get(AnalysisSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return row


@router.post("/schedules/{schedule_id}/pause", response_model=ScheduleOut)
def pause_schedule(schedule_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    row = _get_schedule_or_404(db, schedule_id)
    row.enabled = False
    row.next_run_at = None  # paused → no cursor
    row.modified_on = to_iso(_now())
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/schedules/{schedule_id}/resume", response_model=ScheduleOut)
def resume_schedule(schedule_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    row = _get_schedule_or_404(db, schedule_id)
    row.enabled = True
    _refresh_next_run_at(row)
    row.modified_on = to_iso(_now())
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/schedules/{schedule_id}/run-now", status_code=status.HTTP_202_ACCEPTED)
def run_schedule_now(schedule_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    """
    Trigger the schedule's analysis fan-out immediately.

    Does NOT modify ``next_run_at`` — the regular cadence is preserved.
    Returns the list of SBOM IDs that were enqueued.
    """
    from ..workers.scheduled_analysis import analyze_sbom_async

    row = _get_schedule_or_404(db, schedule_id)

    if row.scope == "SBOM" and row.sbom_id is not None:
        target_sbom_ids = [row.sbom_id]
    elif row.scope == "PROJECT" and row.project_id is not None:
        target_sbom_ids = [
            sid
            for sid in db.execute(
                select(SBOMSource.id).where(SBOMSource.projectid == row.project_id)
            )
            .scalars()
            .all()
        ]
        # Honour SBOM-level overrides during manual fan-out too — same
        # rule as the tick: an explicit SBOM row (even paused) opts out.
        overridden = set(
            db.execute(
                select(AnalysisSchedule.sbom_id).where(
                    AnalysisSchedule.scope == "SBOM",
                    AnalysisSchedule.sbom_id.isnot(None),
                )
            )
            .scalars()
            .all()
        )
        target_sbom_ids = [sid for sid in target_sbom_ids if sid not in overridden]
    else:
        raise HTTPException(status_code=409, detail="Schedule is missing a target")

    enqueued: list[int] = []
    failed: list[int] = []
    last_error: str | None = None
    for sid in target_sbom_ids:
        try:
            analyze_sbom_async.delay(sbom_id=sid, schedule_id=row.id)
            enqueued.append(sid)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            log.exception(
                "schedule_run_now_enqueue_failed",
                extra={"schedule_id": row.id, "sbom_id": sid},
            )
            failed.append(sid)

    # If we have targets but none of them got onto the queue, the broker
    # is the most likely cause. Fail loudly with 502 — silently returning
    # 202 with an empty list misleads users into thinking the click worked.
    if target_sbom_ids and not enqueued:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "broker_unavailable",
                "message": (
                    "Could not enqueue any analyses — the task broker is unreachable. "
                    "Check that Redis/Celery is running."
                ),
                "last_error": last_error,
                "schedule_id": row.id,
                "failed_sbom_ids": failed,
            },
        )

    return {
        "status": "enqueued" if not failed else "partial",
        "schedule_id": row.id,
        "sbom_ids": enqueued,
        "failed_sbom_ids": failed,
    }
