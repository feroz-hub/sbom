"""``SyncRunRepositoryPort`` implementation backed by SQLAlchemy."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import NvdSyncRunRow
from ..domain.models import MirrorWindow


class SqlAlchemySyncRunRepository:
    """Audit log for bootstrap / incremental runs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def begin(self, *, run_kind: str, window: MirrorWindow) -> int:
        if run_kind not in {"bootstrap", "incremental"}:
            raise ValueError(f"unknown run_kind {run_kind!r}")
        row = NvdSyncRunRow(
            run_kind=run_kind,
            window_start=window.start,
            window_end=window.end,
            status="running",
            upserted_count=0,
        )
        self._session.add(row)
        self._session.flush()
        assert row.id is not None  # populated by autoincrement
        return int(row.id)

    def finish(
        self,
        run_id: int,
        *,
        status: str,
        upserts: int,
        error: str | None,
    ) -> None:
        if status not in {"running", "success", "failed", "aborted"}:
            raise ValueError(f"unknown status {status!r}")
        row = self._session.get(NvdSyncRunRow, run_id)
        if row is None:
            raise LookupError(f"sync_run id={run_id} not found")
        row.status = status
        row.upserted_count = upserts
        row.error_message = error
        row.finished_at = datetime.now(tz=timezone.utc)
        self._session.flush()

    def latest(self, limit: int = 10) -> Sequence[Mapping[str, object]]:
        stmt = (
            select(NvdSyncRunRow)
            .order_by(NvdSyncRunRow.started_at.desc())
            .limit(max(1, int(limit)))
        )
        rows = self._session.execute(stmt).scalars().all()
        return [
            {
                "id": r.id,
                "run_kind": r.run_kind,
                "window_start": _ensure_utc(r.window_start),
                "window_end": _ensure_utc(r.window_end),
                "started_at": _ensure_utc(r.started_at),
                "finished_at": _ensure_utc(r.finished_at),
                "status": r.status,
                "upserted_count": r.upserted_count,
                "error_message": r.error_message,
            }
            for r in rows
        ]


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
