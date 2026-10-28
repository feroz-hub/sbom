"""
Regression tests for the EPSS cache persistence path.

Background: the cache previously persisted rows with ``db.merge()`` (a
SELECT-then-INSERT). When two analyses raced to cache the same brand-new CVE
in separate transactions, both saw no row and both scheduled an INSERT — the
second commit hit ``duplicate key value violates unique constraint
"pk_epss_score"``. The fix replaces the merge loop with an atomic
``INSERT .. ON CONFLICT (cve_id) DO UPDATE``.

These tests run against in-memory / file-backed SQLite (exercising the
``sqlite_insert`` branch); the Postgres branch is covered by the full suite
running against the containerised test database.
"""

from __future__ import annotations

import logging

import pytest
from app.models import EpssScore
from app.sources import epss as epss_mod
from sqlalchemy import create_engine
from sqlalchemy import insert as core_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _new_db() -> Session:
    """In-memory SQLite session with the project schema."""
    import app.models  # noqa: F401  ensures models are registered
    from app.db import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _file_sessionmaker(path: str) -> sessionmaker:
    """A sessionmaker on a *file* SQLite DB so two engines share one database."""
    import app.models  # noqa: F401
    from app.db import Base

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _stub_fetch(monkeypatch, mapping: dict[str, dict], *, record: list | None = None) -> None:
    """Stub the outbound EPSS API so tests never touch the network."""

    def fake(cve_ids):
        if record is not None:
            record.append(list(cve_ids))
        return {cve: mapping[cve] for cve in cve_ids if cve in mapping}

    monkeypatch.setattr(epss_mod, "_fetch_batch", fake)


# ---------------------------------------------------------------------
# Normalization / validation
# ---------------------------------------------------------------------


def test_normalize_cve_ids_trims_upcases_dedupes():
    assert epss_mod._normalize_cve_ids(
        ["  cve-2026-8643 ", "CVE-2026-8643", "cve-2026-8643", "", None]  # type: ignore[list-item]
    ) == ["CVE-2026-8643"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CVE-2026-8643", True),
        ("cve-2026-8643", False),  # validity is checked post-normalization (upper-cased)
        ("CVE-1999-0001", True),
        ("CVE-2024-FAKE", False),
        ("GHSA-xxxx-yyyy-zzzz", False),
        ("", False),
    ],
)
def test_is_valid_cve_id(raw, expected):
    assert epss_mod._is_valid_cve_id(raw) is expected


# ---------------------------------------------------------------------
# Insert / update
# ---------------------------------------------------------------------


def test_insert_new_cve(monkeypatch):
    db = _new_db()
    _stub_fetch(monkeypatch, {"CVE-2026-8643": {"epss": 0.5, "percentile": 0.9, "date": "2026-07-01"}})

    result = epss_mod.get_epss_scores(db, ["CVE-2026-8643"])

    assert result == {"CVE-2026-8643": 0.5}
    row = db.get(EpssScore, "CVE-2026-8643")
    assert row is not None
    assert row.epss == 0.5
    assert row.percentile == 0.9
    assert row.score_date == "2026-07-01"
    assert row.refreshed_at  # ISO timestamp set
    assert db.query(EpssScore).count() == 1


def test_update_existing_cve(monkeypatch):
    db = _new_db()
    # Seed a STALE row (refreshed long ago) so the fetch path refreshes it.
    db.add(
        EpssScore(
            cve_id="CVE-2026-8643",
            epss=0.10,
            percentile=0.20,
            score_date="2020-01-01",
            refreshed_at="2000-01-01T00:00:00+00:00",
        )
    )
    db.commit()

    _stub_fetch(monkeypatch, {"CVE-2026-8643": {"epss": 0.77, "percentile": 0.95, "date": "2026-07-02"}})
    result = epss_mod.get_epss_scores(db, ["CVE-2026-8643"])

    assert result == {"CVE-2026-8643": 0.77}
    row = db.get(EpssScore, "CVE-2026-8643")
    assert row.epss == 0.77
    assert row.percentile == 0.95
    assert row.score_date == "2026-07-02"
    # Updated in place — no duplicate row, old row preserved (not deleted+recreated).
    assert db.query(EpssScore).count() == 1


def test_same_cve_twice_in_one_batch(monkeypatch):
    """Duplicate + whitespace variants collapse to one canonical fetch + one row."""
    db = _new_db()
    fetched: list = []
    _stub_fetch(
        monkeypatch,
        {"CVE-2026-8643": {"epss": 0.42, "percentile": 0.8, "date": "2026-07-01"}},
        record=fetched,
    )

    result = epss_mod.get_epss_scores(db, ["CVE-2026-8643", "CVE-2026-8643", "  CVE-2026-8643  "])

    assert result == {"CVE-2026-8643": 0.42}
    assert fetched == [["CVE-2026-8643"]]  # fetched exactly once, deduped
    assert db.query(EpssScore).count() == 1


def test_lowercase_and_uppercase_same_cve(monkeypatch):
    """Mixed-case forms of one CVE dedupe to a single row + fetch."""
    db = _new_db()
    fetched: list = []
    _stub_fetch(
        monkeypatch,
        {"CVE-2026-8643": {"epss": 0.33, "percentile": 0.7, "date": "2026-07-01"}},
        record=fetched,
    )

    result = epss_mod.get_epss_scores(db, ["cve-2026-8643", "CVE-2026-8643"])

    assert result == {"CVE-2026-8643": 0.33}
    assert fetched == [["CVE-2026-8643"]]
    assert db.query(EpssScore).count() == 1


def test_invalid_cve_not_fetched_or_written(monkeypatch):
    """Malformed ids resolve to 0.0 in the map but are never fetched or cached."""
    db = _new_db()
    fetched: list = []
    _stub_fetch(monkeypatch, {}, record=fetched)

    result = epss_mod.get_epss_scores(db, ["CVE-2024-FAKE", "GHSA-aaaa-bbbb-cccc"])

    assert result == {"CVE-2024-FAKE": 0.0, "GHSA-AAAA-BBBB-CCCC": 0.0}
    assert fetched == []  # nothing valid to fetch
    assert db.query(EpssScore).count() == 0


# ---------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------


def test_two_concurrent_inserts_do_not_violate_pk(tmp_path):
    """
    Two independent transactions caching the same brand-new CVE must both
    succeed (last write wins) instead of the second raising a duplicate-key
    error — the exact production failure mode.
    """
    dbfile = tmp_path / "epss.db"
    session_a = _file_sessionmaker(str(dbfile))
    session_b = _file_sessionmaker(str(dbfile))
    sa, sb = session_a(), session_b()

    cve = "CVE-2026-8643"
    now = epss_mod._now_iso()
    row_a = {"cve_id": cve, "epss": 0.5, "percentile": 0.9, "score_date": "2026-07-01", "refreshed_at": now}
    row_b = {"cve_id": cve, "epss": 0.7, "percentile": 0.95, "score_date": "2026-07-02", "refreshed_at": now}

    # Sanity: the PK constraint is real — a plain duplicate INSERT (the old
    # merge-INSERT path) genuinely raises. This is what used to surface as
    # ``pk_epss_score``.
    epss_mod._persist_epss_rows(sa, [row_a], pre_existing=set())
    sb_plain = session_b()
    with pytest.raises(IntegrityError):
        sb_plain.execute(core_insert(EpssScore).values(**row_a))
        sb_plain.commit()
    sb_plain.rollback()

    # The atomic upsert path, by contrast, converges without raising.
    epss_mod._persist_epss_rows(sb, [row_b], pre_existing=set())

    verify = session_a()
    rows = verify.query(EpssScore).all()
    assert len(rows) == 1
    assert rows[0].epss == 0.7  # last writer won
    assert rows[0].score_date == "2026-07-02"


# ---------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------


def test_rollback_after_db_error(monkeypatch, caplog):
    """A failed commit rolls the session back and drops no partial row."""
    db = _new_db()
    rolled_back = {"count": 0}
    real_rollback = db.rollback

    def tracking_rollback():
        rolled_back["count"] += 1
        return real_rollback()

    def boom():
        raise RuntimeError("simulated commit failure")

    monkeypatch.setattr(db, "commit", boom)
    monkeypatch.setattr(db, "rollback", tracking_rollback)

    row = {"cve_id": "CVE-2026-8643", "epss": 0.5, "percentile": 0.9, "score_date": "2026-07-01", "refreshed_at": epss_mod._now_iso()}
    with caplog.at_level(logging.WARNING, logger="sbom.sources.epss"):
        epss_mod._persist_epss_rows(db, [row], pre_existing=set())

    assert rolled_back["count"] == 1
    assert "EPSS cache upsert failed" in caplog.text
    # The staged INSERT was rolled back — no orphan row survives.
    monkeypatch.undo()
    assert db.query(EpssScore).count() == 0


def test_analysis_continues_when_cache_write_fails(monkeypatch):
    """
    An optional cache-write failure must not break scoring: the caller still
    receives the freshly-fetched EPSS values and no exception propagates.
    """
    db = _new_db()
    _stub_fetch(monkeypatch, {"CVE-2026-8643": {"epss": 0.61, "percentile": 0.9, "date": "2026-07-01"}})

    def boom():
        raise RuntimeError("simulated commit failure")

    monkeypatch.setattr(db, "commit", boom)

    result = epss_mod.get_epss_scores(db, ["CVE-2026-8643"])

    # Score still returned from the in-memory fetch despite the failed write.
    assert result == {"CVE-2026-8643": 0.61}
    monkeypatch.undo()
    assert db.query(EpssScore).count() == 0


# ---------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------


def test_structured_upsert_logging(monkeypatch, caplog):
    db = _new_db()
    now = epss_mod._now_iso()
    inserted = {"cve_id": "CVE-2026-8643", "epss": 0.5, "percentile": 0.9, "score_date": "2026-07-01", "refreshed_at": now}
    updated = {"cve_id": "CVE-2026-0001", "epss": 0.2, "percentile": 0.3, "score_date": "2026-07-01", "refreshed_at": now}

    with caplog.at_level(logging.DEBUG, logger="sbom.sources.epss"):
        epss_mod._persist_epss_rows(db, [inserted, updated], pre_existing={"CVE-2026-0001"})

    lines = [r.getMessage() for r in caplog.records if "event=epss_cache_upsert" in r.getMessage()]
    assert any("cve_id=CVE-2026-8643" in ln and "operation=inserted" in ln for ln in lines)
    assert any("cve_id=CVE-2026-0001" in ln and "operation=updated" in ln for ln in lines)
    # Structured fields present; the full payload is not dumped.
    assert all("score_date=" in ln and "refreshed_at=" in ln for ln in lines)
