"""Phase 3.4 — SqlAlchemySyncRunRepository tests on SQLite."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.nvd_mirror.adapters.sync_run_repository import SqlAlchemySyncRunRepository
from app.nvd_mirror.domain.models import MirrorWindow

UTC = timezone.utc


@pytest.fixture()
def session() -> Session:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    from app.db import Base
    import app.nvd_mirror.db.models  # noqa: F401

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()
        Path(path).unlink(missing_ok=True)


def _window() -> MirrorWindow:
    return MirrorWindow(
        start=datetime(2024, 4, 1, tzinfo=UTC),
        end=datetime(2024, 4, 16, tzinfo=UTC),
    )


def test_begin_inserts_running_row(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    rid = repo.begin(run_kind="bootstrap", window=_window())
    session.commit()
    assert rid > 0
    runs = repo.latest()
    assert len(runs) == 1
    assert runs[0]["status"] == "running"
    assert runs[0]["run_kind"] == "bootstrap"
    assert runs[0]["finished_at"] is None


def test_finish_records_status_upserts_and_finished_at(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    rid = repo.begin(run_kind="incremental", window=_window())
    session.commit()
    repo.finish(rid, status="success", upserts=42, error=None)
    session.commit()
    rows = repo.latest()
    assert rows[0]["status"] == "success"
    assert rows[0]["upserted_count"] == 42
    assert rows[0]["finished_at"] is not None
    assert rows[0]["error_message"] is None


def test_finish_with_error_message(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    rid = repo.begin(run_kind="bootstrap", window=_window())
    session.commit()
    repo.finish(rid, status="failed", upserts=0, error="connection refused")
    session.commit()
    rows = repo.latest()
    assert rows[0]["status"] == "failed"
    assert rows[0]["error_message"] == "connection refused"


def test_begin_rejects_unknown_run_kind(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    with pytest.raises(ValueError, match="unknown run_kind"):
        repo.begin(run_kind="garbage", window=_window())


def test_finish_rejects_unknown_status(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    rid = repo.begin(run_kind="bootstrap", window=_window())
    session.commit()
    with pytest.raises(ValueError, match="unknown status"):
        repo.finish(rid, status="weird", upserts=0, error=None)


def test_finish_unknown_id_raises(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    with pytest.raises(LookupError):
        repo.finish(99999, status="success", upserts=0, error=None)


def test_latest_orders_by_started_at_desc(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    ids: list[int] = []
    for i in range(3):
        ids.append(
            repo.begin(
                run_kind="bootstrap",
                window=MirrorWindow(
                    start=datetime(2024, 4, 1 + i, tzinfo=UTC),
                    end=datetime(2024, 4, 1 + i, tzinfo=UTC) + timedelta(days=1),
                ),
            )
        )
        session.commit()
    rows = repo.latest(limit=3)
    # Most recent first.
    seen_ids = [r["id"] for r in rows]
    assert seen_ids == list(reversed(ids))


def test_latest_respects_limit(session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(session)
    for i in range(5):
        repo.begin(
            run_kind="bootstrap",
            window=MirrorWindow(
                start=datetime(2024, 4, 1 + i, tzinfo=UTC),
                end=datetime(2024, 4, 1 + i, tzinfo=UTC) + timedelta(days=1),
            ),
        )
        session.commit()
    rows = repo.latest(limit=2)
    assert len(rows) == 2
