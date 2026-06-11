"""Roadmap #2 PR-E — force-refresh bypass tests.

Exercises the read-side bypass on both seam entry points
(``cached_fetch``, ``partition_by_cache``) end-to-end via the VulDB
and OSV wraps. The bypass MUST:

  1. Ignore a FRESH cached hit when ``source_cache_force_refresh=True``
     AND the cache is enabled — fetch live anyway.
  2. STILL write the fresh result so the stale entry is refreshed
     for the NEXT (non-force) scan.
  3. Be a no-op when ``source_cache_enabled=False`` — everything's
     live regardless of the bypass flag.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterator
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from typing import Any

import pytest
from app.analysis import (
    get_analysis_settings_multi,
    osv_query_by_components,
)
from app.db import Base
from app.models import SourceResponseCache
from app.services.source_response_cache import SourceResponseCacheRepository
from app.sources.vulndb import VulnDbSource
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_T0 = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# DB / clock fixtures (mirror PR-B/C/D layout).
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_session_factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker]:
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
    state: dict[str, datetime] = {"now": _T0}
    original_init = SourceResponseCacheRepository.__init__

    def patched_init(self, db, *, clock=None):
        original_init(self, db, clock=lambda: state["now"])

    monkeypatch.setattr(SourceResponseCacheRepository, "__init__", patched_init)
    return state


def _settings(*, cache_on: bool, force_refresh: bool = False) -> Any:
    base = get_analysis_settings_multi()
    return dataclass_replace(
        base,
        source_cache_enabled=cache_on,
        source_cache_force_refresh=force_refresh,
    )


# ===========================================================================
# Single-fetch seam (VulDB): cached_fetch bypass
# ===========================================================================


_VULDB_OK = {
    "request": {"apikey": "valid"},
    "status": "200",
    "result": [
        {
            "entry": {"id": "1", "title": "v1"},
            "vulnerability": {
                "risk": {"name": "HIGH"},
                "cvss3": {"vuldb": {"basescore": 7.5}},
            },
            "source": {"cve": {"id": "CVE-FR-1"}},
            "advisory": {"date": "1700000000"},
        }
    ],
}

_VULDB_REFRESHED = {
    "request": {"apikey": "valid"},
    "status": "200",
    "result": [
        {
            "entry": {"id": "2", "title": "v2-refreshed"},
            "vulnerability": {
                "risk": {"name": "HIGH"},
                "cvss3": {"vuldb": {"basescore": 8.5}},
            },
            "source": {"cve": {"id": "CVE-FR-2"}},
            "advisory": {"date": "1700000000"},
        }
    ],
}


def _vulndb_components() -> list[dict]:
    return [
        {
            "name": "log4j-core",
            "version": "2.14.0",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        }
    ]


@pytest.fixture()
def vulndb_network(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": 0, "next_payload": _VULDB_OK}

    async def _fake_post(url, data, timeout):  # noqa: ARG001
        state["calls"] += 1
        return copy.deepcopy(state["next_payload"])

    import app.sources.vulndb as vulndb_mod

    monkeypatch.setattr(vulndb_mod, "_post_vulndb_form", _fake_post)
    return state


def test_force_refresh_ignores_fresh_hit_and_overwrites(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    vulndb_network: dict[str, Any],
) -> None:
    """A force-refresh scan with a FRESH cached entry still fetches
    live AND writes the new payload, replacing the stale row."""
    src = VulnDbSource(api_key="test-key")
    components = _vulndb_components()

    # Scan 1 — normal scan, caches v1.
    vulndb_network["next_payload"] = _VULDB_OK
    asyncio.run(src.query(components, _settings(cache_on=True, force_refresh=False)))
    assert vulndb_network["calls"] == 1

    # Sanity — entry is in the cache.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
    assert len(rows) == 1

    # Scan 2 — force_refresh=True. The entry is FRESH (TTL not
    # elapsed) so the legacy semantics would skip the network. With
    # the bypass, the network IS hit, and the new result OVERWRITES
    # the cached row.
    vulndb_network["next_payload"] = _VULDB_REFRESHED
    asyncio.run(src.query(components, _settings(cache_on=True, force_refresh=True)))
    assert vulndb_network["calls"] == 2, (
        "force_refresh must IGNORE the fresh hit and fetch live"
    )

    # The cached entry now reflects the refreshed payload.
    with isolated_session_factory() as s:
        repo = SourceResponseCacheRepository(s)
        cached = repo.get(
            "VULNDB",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        )
    assert cached is not None
    # The payload's first result's CVE id is v2 = CVE-FR-2.
    first_result = (cached.get("result") or [None])[0] or {}
    source_block = first_result.get("source") or {}
    cve = (source_block.get("cve") or {}).get("id")
    assert cve == "CVE-FR-2", (
        "force_refresh must WRITE the fresh result so the stale entry "
        "is refreshed for next time"
    )


def test_no_force_refresh_uses_cached_hit(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    vulndb_network: dict[str, Any],
) -> None:
    src = VulnDbSource(api_key="test-key")
    components = _vulndb_components()

    vulndb_network["next_payload"] = _VULDB_OK
    asyncio.run(src.query(components, _settings(cache_on=True, force_refresh=False)))
    asyncio.run(src.query(components, _settings(cache_on=True, force_refresh=False)))

    # Cache hit on the second scan → ONE fetch total.
    assert vulndb_network["calls"] == 1


def test_force_refresh_is_noop_when_cache_disabled(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    vulndb_network: dict[str, Any],
) -> None:
    """``source_cache_enabled=False`` means everything's live anyway —
    the bypass changes nothing observable."""
    src = VulnDbSource(api_key="test-key")
    components = _vulndb_components()

    vulndb_network["next_payload"] = _VULDB_OK
    asyncio.run(src.query(components, _settings(cache_on=False, force_refresh=False)))
    asyncio.run(src.query(components, _settings(cache_on=False, force_refresh=True)))

    # Both scans fetched live; neither wrote a cache row.
    assert vulndb_network["calls"] == 2
    with isolated_session_factory() as s:
        assert s.query(SourceResponseCache).all() == []


# ===========================================================================
# Batch seam (OSV): partition_by_cache bypass
# ===========================================================================


_OSV_VULN = {
    "id": "OSV-FR",
    "summary": "OSV force-refresh test",
    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
}


class _OsvNet:
    def __init__(self) -> None:
        self.querybatch_calls: list[dict] = []
        self.vuln_calls: list[str] = []
        self.querybatch_results_for: dict[str, list[str]] = {}
        self.vuln_payloads: dict[str, dict] = {}

    async def fake_post(self, url, json_body=None, headers=None, timeout=None):
        if url.endswith("/v1/querybatch"):
            self.querybatch_calls.append(json_body or {})
            queries = (json_body or {}).get("queries") or []
            results = []
            for q in queries:
                purl = ((q or {}).get("package") or {}).get("purl") or ""
                ids = self.querybatch_results_for.get(purl, [])
                results.append({"vulns": [{"id": v} for v in ids]})
            return {"results": results}
        raise AssertionError(f"unexpected POST: {url}")

    async def fake_get(self, url, params=None, headers=None, timeout=None):
        marker = "/v1/vulns/"
        idx = url.find(marker)
        if idx != -1:
            vid = url[idx + len(marker) :]
            self.vuln_calls.append(vid)
            return copy.deepcopy(self.vuln_payloads.get(vid, {"id": vid}))
        raise AssertionError(f"unexpected GET: {url}")


@pytest.fixture()
def osv_net(monkeypatch: pytest.MonkeyPatch) -> _OsvNet:
    net = _OsvNet()
    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "_async_post", net.fake_post)
    monkeypatch.setattr(analysis_mod, "_async_get", net.fake_get)
    return net


def test_force_refresh_bypasses_partition_hits_on_osv(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_net: _OsvNet,
) -> None:
    """``partition_by_cache`` honours the bypass — even with cached
    rows present, every component goes into ``misses`` so querybatch
    runs for all of them."""
    osv_net.querybatch_results_for = {"pkg:npm/lodash@4.17.15": ["OSV-FR"]}
    osv_net.vuln_payloads = {"OSV-FR": _OSV_VULN}
    components = [{"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]

    # Scan 1 — caches the result.
    asyncio.run(
        osv_query_by_components(components, _settings(cache_on=True, force_refresh=False))
    )
    assert len(osv_net.querybatch_calls) == 1

    # Scan 2 — force_refresh=True. The cache row exists and is fresh,
    # but the bypass forces a re-query.
    asyncio.run(
        osv_query_by_components(components, _settings(cache_on=True, force_refresh=True))
    )
    assert len(osv_net.querybatch_calls) == 2, (
        "force_refresh must bypass partition_by_cache hits and re-query "
        "OSV's querybatch endpoint"
    )

    # And it overwrites the cache row (still one row, refreshed timestamp).
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
    assert len(rows) == 1
