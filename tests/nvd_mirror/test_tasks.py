"""Phase 4 — orchestration helpers in tasks module.

We test ``run_mirror_sync`` (pure) and ``assert_no_run_in_flight``.
The Celery-bound ``mirror_nvd`` body is exercised end-to-end via the
API tests in ``test_api.py``.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.nvd_mirror.adapters.sync_run_repository import SqlAlchemySyncRunRepository
from app.nvd_mirror.application._window_walker import HISTORICAL_FLOOR
from app.nvd_mirror.db.models import NvdSyncRunRow
from app.nvd_mirror.domain.models import MirrorWindow
from app.nvd_mirror.tasks import (
    MirrorAlreadyRunningError,
    assert_no_run_in_flight,
    run_mirror_sync,
)

from ._fakes import (
    FakeCveRepository,
    FakeNvdRemote,
    FakeSettingsRepository,
    FakeSyncRunRepository,
    FixedClock,
    batch,
    make_record,
    make_snapshot,
)


UTC = timezone.utc


def _no_commit() -> None:
    return None


# --- run_mirror_sync ------------------------------------------------------


@pytest.mark.asyncio
async def test_run_mirror_sync_no_op_when_disabled() -> None:
    snap = make_snapshot(enabled=False, last_modified_utc=None)
    settings_repo = FakeSettingsRepository(snap)
    cve_repo = FakeCveRepository()
    sync_run_repo = FakeSyncRunRepository()
    remote = FakeNvdRemote()
    clock = FixedClock(datetime(2024, 6, 1, tzinfo=UTC))

    report = await run_mirror_sync(
        settings_repo=settings_repo,
        cve_repo=cve_repo,
        sync_run_repo=sync_run_repo,
        remote=remote,
        clock=clock,
        commit=_no_commit,
    )
    assert report.windows_completed == 0
    assert report.upserts == 0
    assert remote.call_count == 0
    assert sync_run_repo.runs == []


@pytest.mark.asyncio
async def test_run_mirror_sync_dispatches_to_bootstrap_on_no_watermark() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(
        enabled=True, window_days=30, last_modified_utc=None
    )
    rec = make_record("CVE-1", last_modified=target - timedelta(seconds=1))
    remote = FakeNvdRemote({(HISTORICAL_FLOOR, target): [batch([rec])]})

    report = await run_mirror_sync(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=FakeCveRepository(),
        sync_run_repo=FakeSyncRunRepository(),
        remote=remote,
        clock=FixedClock(target),
        commit=_no_commit,
        now=target,
    )
    assert report.run_kind == "bootstrap"
    assert report.windows_completed == 1


@pytest.mark.asyncio
async def test_run_mirror_sync_dispatches_to_incremental_when_watermark_present() -> None:
    target = datetime(2024, 6, 1, tzinfo=UTC)
    waterline = target - timedelta(days=10)
    snap = make_snapshot(
        enabled=True, window_days=30, last_modified_utc=waterline
    )
    rec = make_record("CVE-NEW", last_modified=target - timedelta(seconds=1))
    remote = FakeNvdRemote({(waterline, target): [batch([rec])]})

    report = await run_mirror_sync(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=FakeCveRepository(),
        sync_run_repo=FakeSyncRunRepository(),
        remote=remote,
        clock=FixedClock(target),
        commit=_no_commit,
        now=target,
    )
    assert report.run_kind == "incremental"
    assert report.windows_completed == 1


# --- assert_no_run_in_flight ----------------------------------------------


@pytest.fixture()
def real_session() -> Session:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    from app.db import Base
    import app.nvd_mirror.db.models  # noqa: F401

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    SL = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SL()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()
        Path(path).unlink(missing_ok=True)


def test_assert_no_run_in_flight_passes_when_empty(real_session: Session) -> None:
    assert_no_run_in_flight(real_session)  # should not raise


def test_assert_no_run_in_flight_passes_when_only_finished(real_session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(real_session)
    rid = repo.begin(
        run_kind="bootstrap",
        window=MirrorWindow(
            start=datetime(2024, 4, 1, tzinfo=UTC),
            end=datetime(2024, 4, 2, tzinfo=UTC),
        ),
    )
    repo.finish(rid, status="success", upserts=10, error=None)
    real_session.commit()
    assert_no_run_in_flight(real_session)  # finished doesn't block


def test_assert_no_run_in_flight_raises_when_running(real_session: Session) -> None:
    repo = SqlAlchemySyncRunRepository(real_session)
    repo.begin(
        run_kind="bootstrap",
        window=MirrorWindow(
            start=datetime(2024, 4, 1, tzinfo=UTC),
            end=datetime(2024, 4, 2, tzinfo=UTC),
        ),
    )
    real_session.commit()
    with pytest.raises(MirrorAlreadyRunningError, match="still 'running'"):
        assert_no_run_in_flight(real_session)


# --- task registration ----------------------------------------------------


def test_mirror_nvd_task_registered_on_celery_app() -> None:
    from app.workers.celery_app import celery_app

    assert "nvd_mirror.mirror_nvd" in celery_app.tasks
    # Beat schedule wired.
    assert "nvd-mirror-hourly" in celery_app.conf.beat_schedule
