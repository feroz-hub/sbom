"""Roadmap #2 PR-E — expiry-sweep tests.

Covers the brief's three sweep scenarios:
  (a) Rows past ``expires_at`` are deleted (controlled clock).
  (b) Fresh rows are kept.
  (c) Beat schedule registers the task — mirrors PR-#4's
      ``test_mirror_nvd_task_registered_on_celery_app`` pattern.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from app.db import Base
from app.models import SourceResponseCache
from app.services.source_response_cache import SourceResponseCacheRepository
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_T0 = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def db() -> Iterator[Session]:
    engine = create_engine("sqlite:///:memory:")
    SourceResponseCache.__table__.create(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.remove(SourceResponseCache.__table__)
        engine.dispose()


def _frozen_clock(now: datetime):
    return lambda: now


# ---------------------------------------------------------------------------
# (a) Expired rows are deleted
# ---------------------------------------------------------------------------


def test_delete_expired_removes_rows_past_expires_at(db: Session) -> None:
    # Write at T0 with TTL=1h; sweep at T0+2h. Row should be deleted.
    write_repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    write_repo.set("OSV", "pkg:npm/lodash@1.0.0", {"vulns": []}, ttl_seconds=3600)

    sweep_repo = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(hours=2))
    )
    deleted = sweep_repo.delete_expired()
    assert deleted == 1

    assert db.query(SourceResponseCache).all() == []


def test_delete_expired_handles_many_rows(db: Session) -> None:
    write_repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    # Write 50 rows with TTL=1h.
    for i in range(50):
        write_repo.set(
            "OSV",
            f"pkg:npm/example-{i}@1.0.0",
            {"vulns": [], "i": i},
            ttl_seconds=3600,
        )
    assert db.query(SourceResponseCache).count() == 50

    sweep_repo = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(hours=2))
    )
    deleted = sweep_repo.delete_expired()
    assert deleted == 50
    assert db.query(SourceResponseCache).count() == 0


# ---------------------------------------------------------------------------
# (b) Fresh rows kept
# ---------------------------------------------------------------------------


def test_delete_expired_keeps_fresh_rows(db: Session) -> None:
    write_repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    # Two rows, both TTL=1h. Sweep at T0+30min — both fresh.
    write_repo.set("OSV", "pkg:npm/a@1.0.0", {"vulns": [], "tag": "a"}, ttl_seconds=3600)
    write_repo.set("OSV", "pkg:npm/b@1.0.0", {"vulns": [], "tag": "b"}, ttl_seconds=3600)

    sweep_repo = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(minutes=30))
    )
    deleted = sweep_repo.delete_expired()
    assert deleted == 0
    assert db.query(SourceResponseCache).count() == 2


def test_delete_expired_keeps_fresh_drops_only_stale(db: Session) -> None:
    """Mixed: one fresh, one stale at sweep time."""
    write_repo_t0 = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    write_repo_t0.set("OSV", "pkg:npm/stale@1.0.0", {"tag": "stale"}, ttl_seconds=3600)

    # The fresh row is written at T0+5h with TTL=2h → expires at T0+7h.
    write_repo_t5 = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(hours=5))
    )
    write_repo_t5.set(
        "OSV", "pkg:npm/fresh@1.0.0", {"tag": "fresh"}, ttl_seconds=2 * 3600
    )

    # Sweep at T0+6h: stale expired at T0+1h (already gone), fresh
    # expires at T0+7h (still good).
    sweep_repo = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(hours=6))
    )
    deleted = sweep_repo.delete_expired()
    assert deleted == 1

    keys = {r.component_key for r in db.query(SourceResponseCache).all()}
    assert keys == {"pkg:npm/fresh@1.0.0"}


def test_delete_expired_on_empty_table_is_noop(db: Session) -> None:
    sweep_repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    assert sweep_repo.delete_expired() == 0


def test_delete_expired_zero_or_negative_batch_size_is_noop(db: Session) -> None:
    write_repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
    write_repo.set("OSV", "pkg:npm/lodash@1.0.0", {}, ttl_seconds=3600)
    sweep_repo = SourceResponseCacheRepository(
        db, clock=_frozen_clock(_T0 + timedelta(hours=2))
    )
    assert sweep_repo.delete_expired(batch_size=0) == 0
    assert sweep_repo.delete_expired(batch_size=-5) == 0
    # Row is still there.
    assert db.query(SourceResponseCache).count() == 1


# ---------------------------------------------------------------------------
# (c) Beat schedule registers the task
# ---------------------------------------------------------------------------


def test_source_cache_sweep_task_registered_on_celery_app() -> None:
    """Mirrors tests/nvd_mirror/test_tasks.py:test_mirror_nvd_task_registered."""
    # Importing the worker module triggers the @shared_task registration.
    import app.workers.source_cache  # noqa: F401
    from app.workers.celery_app import celery_app

    assert "source_cache.sweep_expired" in celery_app.tasks
    # Beat schedule wired.
    assert "source-cache-sweep" in celery_app.conf.beat_schedule
    entry = celery_app.conf.beat_schedule["source-cache-sweep"]
    assert entry["task"] == "source_cache.sweep_expired"
