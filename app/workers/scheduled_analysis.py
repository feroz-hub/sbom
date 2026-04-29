"""
Periodic-analysis Celery tasks.

Two tasks live here:

    tick_scheduled_analyses — fired by Beat every 15 minutes. Scans the
        analysis_schedule table for rows whose next_run_at has passed,
        enqueues an analyze_sbom_async per due SBOM, then advances each
        schedule's next_run_at.

    analyze_sbom_async — per-SBOM worker task. Loads the SBOMSource,
        delegates to the existing create_auto_report (the same path as
        the manual POST /api/sboms/{id}/analyze route), updates the
        triggering schedule's last_run_* fields.

The split keeps the tick fast and idempotent (cheap DB scan + enqueue)
and lets per-SBOM runs retry independently — a flake on one SBOM does
not stall the rest of the batch.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisRun, AnalysisSchedule, SBOMSource
from ..services.schedule_resolver import find_due_targets
from ..services.scheduling import (
    ScheduleSpec,
    compute_failure_backoff,
    compute_next_run_at,
    to_iso,
)

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _spec_from_row(row: AnalysisSchedule) -> ScheduleSpec:
    return ScheduleSpec(
        cadence=row.cadence,
        cron_expression=row.cron_expression,
        day_of_week=row.day_of_week,
        day_of_month=row.day_of_month,
        hour_utc=row.hour_utc,
    )


def _recent_run_exists(db: Session, sbom_id: int, gap_minutes: int) -> bool:
    """True if any AnalysisRun for this SBOM completed within ``gap_minutes``.

    Stops a manual click + scheduled tick from running back-to-back.
    """
    cutoff = (_now() - timedelta(minutes=gap_minutes)).isoformat()
    found = db.execute(
        select(AnalysisRun.id)
        .where(AnalysisRun.sbom_id == sbom_id)
        .where(AnalysisRun.completed_on >= cutoff)
        .limit(1)
    ).scalar_one_or_none()
    return found is not None


# ---------------------------------------------------------------------------
# Tick: fired by Beat every 15 min.
# ---------------------------------------------------------------------------


@shared_task(name="scheduled_analysis.tick", bind=True, ignore_result=True)
def tick_scheduled_analyses(self) -> dict:
    """Find due schedules, fan out per-SBOM analyze tasks, advance next_run_at."""
    from app.db import SessionLocal

    db: Session = SessionLocal()
    try:
        now = _now()
        targets = find_due_targets(db, now.isoformat())

        if not targets:
            log.info("scheduled_analysis_tick_idle")
            return {"due": 0, "enqueued": 0}

        # Snapshot of schedule rows we need to advance — fetch once, mutate
        # in place. We want next_run_at moved forward whether or not the
        # per-SBOM task ultimately succeeds, otherwise a failing schedule
        # would re-fire on the next 15-min tick.
        schedule_ids = {t.schedule_id for t in targets}
        schedules = (
            db.execute(select(AnalysisSchedule).where(AnalysisSchedule.id.in_(schedule_ids)))
            .scalars()
            .all()
        )
        schedule_by_id = {s.id: s for s in schedules}

        enqueued = 0
        for tgt in targets:
            try:
                analyze_sbom_async.delay(
                    sbom_id=tgt.sbom_id,
                    schedule_id=tgt.schedule_id,
                )
                enqueued += 1
            except Exception:
                log.exception(
                    "scheduled_analysis_enqueue_failed",
                    extra={"sbom_id": tgt.sbom_id, "schedule_id": tgt.schedule_id},
                )

        # Advance next_run_at for every schedule we touched. The per-SBOM
        # task will overwrite last_run_* on completion; we only manage the
        # forward cursor here.
        for sched in schedule_by_id.values():
            try:
                next_at = compute_next_run_at(_spec_from_row(sched), now)
                sched.next_run_at = to_iso(next_at)
                sched.modified_on = to_iso(now)
            except Exception:
                log.exception(
                    "scheduled_analysis_next_run_at_failed",
                    extra={"schedule_id": sched.id},
                )

        db.commit()
        log.info(
            "scheduled_analysis_tick_done",
            extra={"due": len(targets), "enqueued": enqueued},
        )
        return {"due": len(targets), "enqueued": enqueued}
    except Exception:
        db.rollback()
        log.exception("scheduled_analysis_tick_failed")
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Per-SBOM worker task.
# ---------------------------------------------------------------------------


@shared_task(
    name="scheduled_analysis.analyze_sbom",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
    retry_backoff=True,
    retry_backoff_max=900,
)
def analyze_sbom_async(self, sbom_id: int, schedule_id: int) -> dict:
    """Run create_auto_report for one SBOM and write back to the schedule row."""
    from app.db import SessionLocal
    from app.routers.sboms_crud import create_auto_report

    db: Session = SessionLocal()
    try:
        sched = db.get(AnalysisSchedule, schedule_id)
        sbom = db.get(SBOMSource, sbom_id)

        if sbom is None:
            log.warning("scheduled_analysis_sbom_missing", extra={"sbom_id": sbom_id})
            if sched is not None:
                sched.last_run_status = "SKIPPED"
                sched.last_run_at = to_iso(_now())
                db.commit()
            return {"status": "SKIPPED", "reason": "sbom_not_found"}

        gap_minutes = sched.min_gap_minutes if sched is not None else 60
        if _recent_run_exists(db, sbom_id, gap_minutes):
            log.info(
                "scheduled_analysis_skip_recent",
                extra={"sbom_id": sbom_id, "gap_minutes": gap_minutes},
            )
            if sched is not None:
                sched.last_run_status = "SKIPPED"
                sched.last_run_at = to_iso(_now())
                db.commit()
            return {"status": "SKIPPED", "reason": "recent_run_within_gap"}

        try:
            run = asyncio.run(create_auto_report(db, sbom))
        except Exception as exc:
            log.exception(
                "scheduled_analysis_run_failed",
                extra={"sbom_id": sbom_id, "schedule_id": schedule_id},
            )
            if sched is not None:
                sched.last_run_status = "ERROR"
                sched.last_run_at = to_iso(_now())
                sched.consecutive_failures = (sched.consecutive_failures or 0) + 1
                # Override forward-cursor with the backoff value; the tick
                # already advanced it once based on cadence, but a flapping
                # source warrants slowing down further.
                sched.next_run_at = to_iso(
                    compute_failure_backoff(sched.consecutive_failures, _now())
                )
                db.commit()
            raise self.retry(exc=exc)

        if sched is not None:
            sched.last_run_at = to_iso(_now())
            sched.last_run_status = run.run_status if run is not None else "NO_DATA"
            sched.last_run_id = run.id if run is not None else None
            sched.consecutive_failures = 0
            db.commit()

        return {
            "status": run.run_status if run is not None else "NO_DATA",
            "run_id": run.id if run is not None else None,
            "sbom_id": sbom_id,
        }
    finally:
        db.close()
