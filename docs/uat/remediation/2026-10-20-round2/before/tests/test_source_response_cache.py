"""Unit tests for ``app.services.source_response_cache`` (roadmap #2, PR-A).

Pure storage-layer tests:
  * ``set`` then ``get`` round-trips the payload.
  * A read after TTL expiry returns ``None`` (controlled clock).
  * A miss returns ``None``.
  * ``set`` is last-write-wins on PK collision.
  * Different ``(source, component_key)`` tuples don't collide.

Uses an in-memory SQLite + a minimal metadata bind (only the
``source_response_cache`` table) so the test stays decoupled from the
rest of the schema and from the FastAPI startup path.
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

_T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def db() -> Iterator[Session]:
    engine = create_engine("sqlite:///:memory:")
    # Create only the table we need — keeps the in-memory schema
    # decoupled from the rest of ``app.models`` (FKs in other tables
    # don't cascade in here).
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


def _advancing_clock(times: list[datetime]):
    """Returns successive instants per call; raises if exhausted so a
    bug calling ``clock()`` more times than expected fails loudly."""
    it = iter(times)
    return lambda: next(it)


# ---------------------------------------------------------------------------
# Set → get round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_set_then_get_returns_payload(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        payload = {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}], "totalCount": 1}
        repo.set("OSV", "pkg:npm/lodash@4.17.20", payload, ttl_seconds=3600)

        got = repo.get("OSV", "pkg:npm/lodash@4.17.20")
        assert got == payload

    def test_set_accepts_list_payload(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        payload = [{"id": "GHSA-1"}, {"id": "GHSA-2"}]
        repo.set("GITHUB", "pkg:npm/lodash@4.17.20", payload, ttl_seconds=3600)
        assert repo.get("GITHUB", "pkg:npm/lodash@4.17.20") == payload

    def test_set_accepts_long_purl_within_512_chars(self, db: Session) -> None:
        # Realistic-ish: scoped npm + version with build metadata.
        long_purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0?classifier=sources"
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("NVD", long_purl, {"ok": True}, ttl_seconds=3600)
        assert repo.get("NVD", long_purl) == {"ok": True}


# ---------------------------------------------------------------------------
# TTL — controlled clock
# ---------------------------------------------------------------------------


class TestTTL:
    def test_read_before_expiry_returns_payload(self, db: Session) -> None:
        # Write at T0, read at T0 + 1h. TTL = 2h.
        clock = _advancing_clock([_T0, _T0 + timedelta(hours=1)])
        repo = SourceResponseCacheRepository(db, clock=clock)
        repo.set("OSV", "pkg:pypi/requests@2.31.0", {"a": 1}, ttl_seconds=2 * 3600)
        assert repo.get("OSV", "pkg:pypi/requests@2.31.0") == {"a": 1}

    def test_read_after_expiry_returns_none(self, db: Session) -> None:
        # Write at T0 with TTL = 1h; read at T0 + 2h. Expired.
        clock = _advancing_clock([_T0, _T0 + timedelta(hours=2)])
        repo = SourceResponseCacheRepository(db, clock=clock)
        repo.set("OSV", "pkg:pypi/requests@2.31.0", {"a": 1}, ttl_seconds=3600)
        assert repo.get("OSV", "pkg:pypi/requests@2.31.0") is None

    def test_read_at_exact_expiry_returns_none(self, db: Session) -> None:
        # ``now >= expires`` triggers miss; the boundary is the miss side.
        clock = _advancing_clock([_T0, _T0 + timedelta(seconds=3600)])
        repo = SourceResponseCacheRepository(db, clock=clock)
        repo.set("OSV", "x", {"a": 1}, ttl_seconds=3600)
        assert repo.get("OSV", "x") is None

    def test_zero_ttl_is_a_silent_no_op(self, db: Session) -> None:
        # Caller passed ttl_seconds=0 — repository declines to cache.
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "x", {"a": 1}, ttl_seconds=0)
        assert repo.get("OSV", "x") is None

    def test_negative_ttl_is_a_silent_no_op(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "x", {"a": 1}, ttl_seconds=-1)
        assert repo.get("OSV", "x") is None


# ---------------------------------------------------------------------------
# Miss
# ---------------------------------------------------------------------------


class TestMiss:
    def test_get_with_no_row_returns_none(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        assert repo.get("OSV", "pkg:pypi/never-stored@1.0.0") is None

    def test_get_returns_none_when_expires_at_is_corrupt(self, db: Session) -> None:
        # Write a row directly with a garbage expires_at; the repository
        # should treat it as a miss rather than raise.
        db.add(
            SourceResponseCache(
                source="OSV",
                component_key="pkg:npm/corrupt@1.0.0",
                payload={"a": 1},
                fetched_at="2026-06-03T12:00:00+00:00",
                expires_at="not-a-real-iso-timestamp",
            )
        )
        db.commit()
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        assert repo.get("OSV", "pkg:npm/corrupt@1.0.0") is None


# ---------------------------------------------------------------------------
# Overwrite
# ---------------------------------------------------------------------------


class TestOverwrite:
    def test_set_overwrites_existing_payload(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "k", {"v": 1}, ttl_seconds=3600)
        repo.set("OSV", "k", {"v": 2}, ttl_seconds=3600)
        assert repo.get("OSV", "k") == {"v": 2}

    def test_overwrite_extends_ttl_from_new_write(self, db: Session) -> None:
        # First write with TTL=1h at T0 → would expire at T0+1h.
        # Overwrite at T0+30min with TTL=2h → new expiry is T0+2h30m.
        # Read at T0+1h30m should HIT (new TTL is in force).
        t_write_1 = _T0
        t_write_2 = _T0 + timedelta(minutes=30)
        t_read = _T0 + timedelta(minutes=90)
        clock = _advancing_clock([t_write_1, t_write_2, t_read])
        repo = SourceResponseCacheRepository(db, clock=clock)
        repo.set("OSV", "k", {"v": 1}, ttl_seconds=3600)
        repo.set("OSV", "k", {"v": 2}, ttl_seconds=2 * 3600)
        assert repo.get("OSV", "k") == {"v": 2}


# ---------------------------------------------------------------------------
# Key isolation
# ---------------------------------------------------------------------------


class TestKeyIsolation:
    def test_different_sources_do_not_collide(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "pkg:npm/lodash@4.17.20", {"src": "OSV"}, ttl_seconds=3600)
        repo.set("GITHUB", "pkg:npm/lodash@4.17.20", {"src": "GITHUB"}, ttl_seconds=3600)
        assert repo.get("OSV", "pkg:npm/lodash@4.17.20") == {"src": "OSV"}
        assert repo.get("GITHUB", "pkg:npm/lodash@4.17.20") == {"src": "GITHUB"}

    def test_different_component_keys_do_not_collide(self, db: Session) -> None:
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "pkg:npm/lodash@4.17.20", {"id": "A"}, ttl_seconds=3600)
        repo.set("OSV", "pkg:npm/lodash@4.17.21", {"id": "B"}, ttl_seconds=3600)
        assert repo.get("OSV", "pkg:npm/lodash@4.17.20") == {"id": "A"}
        assert repo.get("OSV", "pkg:npm/lodash@4.17.21") == {"id": "B"}

    def test_source_is_case_sensitive(self, db: Session) -> None:
        # The repository does not normalise — case differences are
        # distinct keys. Caller decides whether to uppercase.
        repo = SourceResponseCacheRepository(db, clock=_frozen_clock(_T0))
        repo.set("OSV", "k", {"u": "upper"}, ttl_seconds=3600)
        assert repo.get("osv", "k") is None
        assert repo.get("OSV", "k") == {"u": "upper"}


# ---------------------------------------------------------------------------
# Settings field
# ---------------------------------------------------------------------------


class TestSettingsDefault:
    def test_source_cache_ttl_seconds_has_modest_default(self) -> None:
        from app.settings import Settings

        s = Settings()
        # "modest few hours" per the brief; assert it's a positive int
        # that's not absurd. Default sits at 4h; tightening or loosening
        # would update the assertion.
        assert isinstance(s.source_cache_ttl_seconds, int)
        assert 60 * 60 <= s.source_cache_ttl_seconds <= 24 * 60 * 60
