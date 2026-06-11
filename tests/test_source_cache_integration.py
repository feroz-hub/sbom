"""Integration tests for the source-response cache (roadmap #2, PR-B).

Exercises the VulDB wrap end-to-end via ``VulnDbSource.query`` with the
network call (``_post_vulndb_form``) mocked. The cache itself is the
real ``SourceResponseCacheRepository`` backed by an in-memory SQLite
schema so we can observe row writes and assert cache-hit behaviour
without bringing up the full FastAPI fixture.

Covers the brief's five scenarios:
  1. Flag OFF → fetch called every scan; no cache rows.
  2. Flag ON, re-scan → second scan calls fetch ZERO times.
  3. Reprocess-equals-live → findings are identical across scans.
  4. TTL expiry → advance the seam's clock; next scan re-fetches.
  5. Per-source isolation → VulDB-cached entry doesn't satisfy a
     different ``source`` for the same component.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.analysis import AnalysisSettings, _MultiSettings
from app.db import Base
from app.models import SourceResponseCache
from app.services.source_response_cache import SourceResponseCacheRepository
from app.sources.vulndb import VulnDbSource
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ---------------------------------------------------------------------------
# DB / SessionLocal patch
# ---------------------------------------------------------------------------


_T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def isolated_session_factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker]:
    """Spin up an in-memory SQLite with only the source_response_cache
    table, then monkeypatch ``app.db.SessionLocal`` (which the seam
    imports lazily) to return sessions bound to this engine.
    """
    engine = create_engine("sqlite:///:memory:")
    SourceResponseCache.__table__.create(bind=engine)
    Factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    import app.db as app_db

    monkeypatch.setattr(app_db, "SessionLocal", Factory)
    try:
        yield Factory
    finally:
        Base.metadata.remove(SourceResponseCache.__table__)
        engine.dispose()


@pytest.fixture()
def controlled_clock(monkeypatch: pytest.MonkeyPatch) -> dict[str, datetime]:
    """Pin the cache repository's clock to a controlled instant so TTL
    expiry is deterministic. Returns a dict whose ``now`` key tests can
    mutate to advance time.
    """
    state: dict[str, datetime] = {"now": _T0}

    original_init = SourceResponseCacheRepository.__init__

    def patched_init(self, db, *, clock=None):
        original_init(self, db, clock=lambda: state["now"])

    monkeypatch.setattr(SourceResponseCacheRepository, "__init__", patched_init)
    return state


# ---------------------------------------------------------------------------
# VulDB harness
# ---------------------------------------------------------------------------


_VULDB_OK_PAYLOAD = {
    "request": {"apikey": "valid"},
    "status": "200",
    "result": [
        {
            "entry": {"id": "12345", "title": "Synthetic VulDB finding"},
            "vulnerability": {
                "risk": {"name": "HIGH"},
                "cvss3": {"vuldb": {"basescore": 7.5}},
                "cwe": "CWE-79",
            },
            "source": {"cve": {"id": "CVE-2024-99999"}},
            "advisory": {"date": "1700000000"},
        }
    ],
}


def _settings_with(cache_on: bool, ttl_seconds: int = 4 * 3600) -> Any:
    """Build a settings stub with the fields VulnDbSource reads."""
    base = AnalysisSettings()
    return _MultiSettings(
        **{
            **base.__dict__,
            "source_cache_enabled": cache_on,
            "source_cache_ttl_seconds": ttl_seconds,
        }
    )


def _components() -> list[dict]:
    return [
        {
            "name": "log4j-core",
            "version": "2.14.0",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        }
    ]


@pytest.fixture()
def network_mock(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Mock ``_post_vulndb_form`` so we can count calls and assert no
    network is hit on cache hits.
    """
    state: dict[str, Any] = {"calls": 0}

    async def _fake_post(url, data, timeout):  # noqa: ARG001
        state["calls"] += 1
        # Deep-copy so consumers can't mutate the canned payload.
        import copy
        return copy.deepcopy(_VULDB_OK_PAYLOAD)

    import app.sources.vulndb as vulndb_mod

    monkeypatch.setattr(vulndb_mod, "_post_vulndb_form", _fake_post)
    return state


# ---------------------------------------------------------------------------
# 1. Flag OFF — every fetch is live, no cache rows written
# ---------------------------------------------------------------------------


def test_flag_off_every_scan_calls_fetch_and_writes_no_cache(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=False)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    asyncio.run(src.query(components, settings))
    asyncio.run(src.query(components, settings))

    # Two scans → two live fetches.
    assert network_mock["calls"] == 2

    # No cache rows.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
        assert rows == []


# ---------------------------------------------------------------------------
# 2. Flag ON, re-scan reuse — second scan calls fetch ZERO times
# ---------------------------------------------------------------------------


def test_flag_on_second_scan_hits_cache_and_skips_fetch(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=True)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    asyncio.run(src.query(components, settings))
    first_calls = network_mock["calls"]
    asyncio.run(src.query(components, settings))
    second_calls = network_mock["calls"]

    assert first_calls == 1, "scan 1 should have fetched exactly once"
    assert second_calls == 1, (
        f"scan 2 should not have fetched (cache hit); "
        f"total fetches now {second_calls}"
    )

    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
        assert len(rows) == 1
        assert rows[0].source == "VULNDB"
        # Canonical PURL key (Maven preserves case).
        assert rows[0].component_key == (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
        )


# ---------------------------------------------------------------------------
# 3. Reprocess-equals-live — cached scan's findings == live scan's findings
# ---------------------------------------------------------------------------


def test_cached_findings_identical_to_live_findings(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    """Cache is a transparent I/O cache — processing runs fresh on hit."""
    settings = _settings_with(cache_on=True)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    first = asyncio.run(src.query(components, settings))
    second = asyncio.run(src.query(components, settings))

    assert first["findings"] == second["findings"], (
        "cached re-scan must produce identical findings; "
        "processing is supposed to run fresh on every hit"
    )
    assert len(first["findings"]) == 1
    assert first["findings"][0]["vuln_id"] == "CVE-2024-99999"


# ---------------------------------------------------------------------------
# 4. TTL expiry — advance the clock; next scan re-fetches
# ---------------------------------------------------------------------------


def test_ttl_expiry_triggers_refetch_on_next_scan(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=True, ttl_seconds=3600)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    # Scan 1 at T0 → fetch + cache.
    controlled_clock["now"] = _T0
    asyncio.run(src.query(components, settings))
    assert network_mock["calls"] == 1

    # Scan 2 at T0 + 30min → cache hit, no fetch.
    controlled_clock["now"] = _T0 + timedelta(minutes=30)
    asyncio.run(src.query(components, settings))
    assert network_mock["calls"] == 1

    # Scan 3 at T0 + 2h → cache expired (TTL=1h), refetch.
    controlled_clock["now"] = _T0 + timedelta(hours=2)
    asyncio.run(src.query(components, settings))
    assert network_mock["calls"] == 2


# ---------------------------------------------------------------------------
# 5. Per-source isolation — a VulnDB cache row doesn't satisfy another source
# ---------------------------------------------------------------------------


def test_per_source_isolation(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    """Direct cache-layer assertion: a row under VULNDB does not
    return for a different source lookup of the same component key.
    Mirrors PR-A's key-isolation test but exercised end-to-end via
    the seam's writer.
    """
    settings = _settings_with(cache_on=True)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    asyncio.run(src.query(components, settings))

    with isolated_session_factory() as s:
        repo = SourceResponseCacheRepository(s)
        purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
        # Same key, different source → miss.
        assert repo.get("GITHUB", purl) is None
        assert repo.get("OSV", purl) is None
        # Sanity — the VULNDB row IS present.
        assert repo.get("VULNDB", purl) is not None


# ---------------------------------------------------------------------------
# Metrics emission (bonus — assert hit/miss events fire on the right paths)
# ---------------------------------------------------------------------------


def test_metrics_emitted_only_when_flag_on(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings_off = _settings_with(cache_on=False)
    settings_on = _settings_with(cache_on=True)
    src = VulnDbSource(api_key="test-key")
    components = _components()

    with caplog.at_level(logging.INFO, logger="sbom.source_cache.metrics"):
        asyncio.run(src.query(components, settings_off))
        flag_off_records = [r for r in caplog.records if r.name == "sbom.source_cache.metrics"]
        assert flag_off_records == [], (
            "flag off must emit no source_cache metrics (byte-identical path)"
        )

        asyncio.run(src.query(components, settings_on))  # miss
        asyncio.run(src.query(components, settings_on))  # hit

    metric_events = [r for r in caplog.records if r.name == "sbom.source_cache.metrics"]
    miss_events = [r for r in metric_events if getattr(r, "metric", "") == "source_cache.miss_total"]
    hit_events = [r for r in metric_events if getattr(r, "metric", "") == "source_cache.hit_total"]
    assert len(miss_events) == 1
    assert len(hit_events) == 1
    assert miss_events[0].labels == {"source": "VULNDB"}
    assert hit_events[0].labels == {"source": "VULNDB"}
