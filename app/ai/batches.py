"""CRUD helpers for the ``ai_fix_batch`` table.

Lives separately from the pipeline so the router and the worker can
share batch-creation / lookup logic without pulling in the heavyweight
generator module.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AiFixBatch
from .progress import BatchProgress
from .scope import AiFixGenerationScope

log = logging.getLogger("sbom.ai.batches")


# Hard cap on concurrently-active batches per run. The router enforces
# this with a 409 response; the limit is intentionally low (3) so a
# single run's batches don't monopolise the global provider rate-limit
# budget.
MAX_ACTIVE_BATCHES_PER_RUN = 3


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def new_batch_id() -> str:
    """Generate a new UUID4 batch identifier (36-char string with dashes)."""
    return str(uuid.uuid4())


def count_active_batches(db: Session, *, run_id: int) -> int:
    """Count batches in non-terminal states for a run.

    Used by the router to enforce the per-run concurrency cap.
    """
    rows = list(
        db.execute(
            select(AiFixBatch.id).where(
                AiFixBatch.run_id == run_id,
                AiFixBatch.status.in_(("queued", "pending", "in_progress")),
            )
        ).scalars()
    )
    return len(rows)


def create_batch(
    db: Session,
    *,
    run_id: int,
    finding_ids: list[int],
    provider_name: str,
    scope: AiFixGenerationScope | None,
    cached_count: int = 0,
    batch_id: str | None = None,
) -> AiFixBatch:
    """Persist a new ``ai_fix_batch`` row in ``queued`` state.

    The router calls this synchronously before kicking off Celery, so
    that subsequent concurrency checks see the new row. Returns the
    persisted row (refreshed from DB).
    """
    bid = batch_id or new_batch_id()
    label = (scope.label if scope and scope.label else None)
    scope_payload: dict[str, Any] | None = None
    if scope is not None:
        scope_payload = scope.model_dump(mode="json", exclude_none=True)

    row = AiFixBatch(
        id=bid,
        run_id=run_id,
        status="queued",
        scope_label=label,
        scope_json=scope_payload,
        finding_ids_json=list(finding_ids),
        provider_name=provider_name,
        total=len(finding_ids),
        cached_count=cached_count,
        generated_count=0,
        failed_count=0,
        cost_usd=0.0,
        started_at=None,
        completed_at=None,
        created_at=_now_iso(),
        last_error=None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_batch_from_progress(
    db: Session,
    *,
    batch_id: str,
    progress: BatchProgress,
) -> None:
    """Sync the durable ``ai_fix_batch`` row from a live progress snapshot.

    Best-effort: failures are logged, not raised. The progress store
    (Redis) remains the source of truth for in-flight counters; this
    table is the source of truth for "did this batch ever run, what
    was the outcome." The two converge at terminal status.
    """
    try:
        row = db.execute(
            select(AiFixBatch).where(AiFixBatch.id == batch_id)
        ).scalar_one_or_none()
        if row is None:
            log.warning("ai.batch.update.not_found: batch=%s", batch_id)
            return
        row.status = progress.status
        row.cached_count = int(progress.from_cache)
        row.generated_count = int(progress.generated)
        row.failed_count = int(progress.failed)
        row.cost_usd = float(progress.cost_so_far_usd)
        if progress.started_at and not row.started_at:
            row.started_at = progress.started_at
        if progress.status in {"complete", "failed", "cancelled", "paused_budget"}:
            if not row.completed_at:
                row.completed_at = progress.finished_at or _now_iso()
        if progress.last_error:
            row.last_error = progress.last_error[:240]
        db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("ai.batch.update.failed: batch=%s err=%s", batch_id, exc)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass


def get_batch(db: Session, *, run_id: int, batch_id: str) -> AiFixBatch | None:
    return db.execute(
        select(AiFixBatch).where(
            AiFixBatch.id == batch_id,
            AiFixBatch.run_id == run_id,
        )
    ).scalar_one_or_none()


def list_batches_for_run(
    db: Session,
    *,
    run_id: int,
) -> list[AiFixBatch]:
    """Return all batches for a run, newest-first."""
    return list(
        db.execute(
            select(AiFixBatch)
            .where(AiFixBatch.run_id == run_id)
            .order_by(AiFixBatch.created_at.desc())
        ).scalars()
    )


def latest_batch_for_run(db: Session, *, run_id: int) -> AiFixBatch | None:
    """Return the most-recently-created batch for a run, or None.

    Used by the deprecated single-batch endpoints to map ``run_id`` →
    most-recent batch during the 30-day deprecation window.
    """
    return db.execute(
        select(AiFixBatch)
        .where(AiFixBatch.run_id == run_id)
        .order_by(AiFixBatch.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def deserialize_finding_ids(raw: Any) -> list[int]:
    """Accept either a Python list or a JSON-encoded string.

    SQLite returns JSON columns as Python lists when SQLAlchemy is
    configured with the JSON type; some legacy test paths store strings.
    """
    if isinstance(raw, list):
        return [int(x) for x in raw]
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
            if isinstance(obj, list):
                return [int(x) for x in obj]
        except json.JSONDecodeError:
            pass
    return []


__all__ = [
    "MAX_ACTIVE_BATCHES_PER_RUN",
    "count_active_batches",
    "create_batch",
    "deserialize_finding_ids",
    "get_batch",
    "latest_batch_for_run",
    "list_batches_for_run",
    "new_batch_id",
    "update_batch_from_progress",
]
