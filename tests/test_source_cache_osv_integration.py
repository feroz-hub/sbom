"""Integration tests for the OSV source-response cache wrap
(roadmap #2, PR-D).

OSV's flow is partition → batched querybatch over MISSES only → hydrate
→ (conditional fallback over misses) → cache each miss's result
(including empty) → merge hits + misses → process. Far more invasive
than VulDB/GHSA; the tests exercise the brief's six scenarios
end-to-end against real ``osv_query_by_components`` with all OSV
network calls mocked (``/v1/querybatch``, ``/v1/vulns/{id}``,
``/v1/query``).
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterator
from dataclasses import replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analysis import (
    get_analysis_settings_multi,
    osv_query_by_components,
)
from app.db import Base
from app.models import SourceResponseCache
from app.services.source_response_cache import SourceResponseCacheRepository


_T0 = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Test infra: in-memory SQLite for the cache + monkeypatched SessionLocal +
# controlled clock for the cache repository.
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


# ---------------------------------------------------------------------------
# Canned OSV responses
# ---------------------------------------------------------------------------


_LODASH_VULN = {
    "id": "OSV-FAKE-LODASH",
    "summary": "lodash advisory",
    "published": "2024-01-15T12:00:00Z",
    "references": [{"url": "https://example.invalid/osv-lodash"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
    "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}],
}

_REQUESTS_VULN = {
    "id": "OSV-FAKE-REQUESTS",
    "summary": "requests advisory",
    "published": "2024-02-01T00:00:00Z",
    "references": [{"url": "https://example.invalid/osv-requests"}],
    "database_specific": {"severity": "MEDIUM"},
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
}


def _components_two_npm() -> list[dict]:
    return [
        {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
        {"name": "requests", "version": "2.20.0", "purl": "pkg:pypi/requests@2.20.0"},
    ]


def _settings_with(cache_on: bool, ttl_seconds: int = 4 * 3600) -> Any:
    base = get_analysis_settings_multi()
    return dataclass_replace(
        base,
        source_cache_enabled=cache_on,
        source_cache_ttl_seconds=ttl_seconds,
    )


# ---------------------------------------------------------------------------
# Network mock — dispatches by URL across /v1/querybatch, /v1/vulns/{id},
# /v1/query. Tests pass per-test overrides for the response payload.
# ---------------------------------------------------------------------------


class _OsvNetwork:
    """Mockable OSV transport. Counts each endpoint's hits per call."""

    def __init__(self) -> None:
        self.querybatch_calls: list[dict] = []  # request bodies
        self.query_calls: list[dict] = []
        self.vuln_calls: list[str] = []
        # Configurable per-test:
        self.querybatch_results_for: dict[str, list[str]] = {}  # purl → vuln ids
        self.vuln_payloads: dict[str, dict] = {}  # id → raw vuln dict
        self.query_payloads_for: dict[str, list[dict]] = {}  # purl → raw vulns

    async def fake_post(self, url, json_body=None, headers=None, timeout=None):
        if url.endswith("/v1/querybatch"):
            self.querybatch_calls.append(json_body or {})
            queries = (json_body or {}).get("queries") or []
            results = []
            for q in queries:
                purl = ((q or {}).get("package") or {}).get("purl") or ""
                ids = self.querybatch_results_for.get(purl, [])
                results.append({"vulns": [{"id": vid} for vid in ids]})
            return {"results": results}
        if url.endswith("/v1/query"):
            self.query_calls.append(json_body or {})
            purl = ((json_body or {}).get("package") or {}).get("purl") or ""
            return {"vulns": copy.deepcopy(self.query_payloads_for.get(purl, []))}
        raise AssertionError(f"unexpected OSV POST: {url}")

    async def fake_get(self, url, params=None, headers=None, timeout=None):
        # /v1/vulns/{id}
        marker = "/v1/vulns/"
        idx = url.find(marker)
        if idx != -1:
            vid = url[idx + len(marker) :]
            self.vuln_calls.append(vid)
            return copy.deepcopy(self.vuln_payloads.get(vid, {"id": vid}))
        raise AssertionError(f"unexpected OSV GET: {url}")


@pytest.fixture()
def osv_network(monkeypatch: pytest.MonkeyPatch) -> _OsvNetwork:
    net = _OsvNetwork()
    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "_async_post", net.fake_post)
    monkeypatch.setattr(analysis_mod, "_async_get", net.fake_get)
    return net


# ---------------------------------------------------------------------------
# Scenario 1 — Flag OFF: full live every scan, no cache rows.
# ---------------------------------------------------------------------------


def test_flag_off_full_live_flow_no_cache_writes(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=False)
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
    }
    osv_network.vuln_payloads = {"OSV-FAKE-LODASH": _LODASH_VULN}

    components = _components_two_npm()
    findings_1, _, _ = asyncio.run(osv_query_by_components(components, settings))
    findings_2, _, _ = asyncio.run(osv_query_by_components(components, settings))

    # Each scan ran a full querybatch (1 request per scan because both
    # comps fit in one batch). Hydrated once per ID per scan.
    assert len(osv_network.querybatch_calls) == 2
    assert osv_network.vuln_calls.count("OSV-FAKE-LODASH") == 2

    # No cache rows.
    with isolated_session_factory() as s:
        assert s.query(SourceResponseCache).all() == []

    # Findings identical (and non-empty) across scans for sanity.
    assert findings_1 == findings_2
    assert len(findings_1) == 1


# ---------------------------------------------------------------------------
# Scenario 2 — Re-scan reuse: second scan makes ZERO OSV network calls.
# ---------------------------------------------------------------------------


def test_rescan_reuse_zero_osv_calls(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=True)
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
    }
    osv_network.vuln_payloads = {"OSV-FAKE-LODASH": _LODASH_VULN}

    components = _components_two_npm()
    asyncio.run(osv_query_by_components(components, settings))

    # Snapshot call counts.
    qb_before = len(osv_network.querybatch_calls)
    vuln_before = len(osv_network.vuln_calls)
    query_before = len(osv_network.query_calls)

    asyncio.run(osv_query_by_components(components, settings))

    assert len(osv_network.querybatch_calls) == qb_before, (
        "querybatch should NOT have been called on the all-cached re-scan"
    )
    assert len(osv_network.vuln_calls) == vuln_before, (
        "hydration should NOT have been called on the all-cached re-scan"
    )
    assert len(osv_network.query_calls) == query_before, (
        "fallback should NOT have been called on the all-cached re-scan"
    )

    # Cache rows: one per component, both tagged querybatch.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
    keys = {r.component_key for r in rows}
    assert keys == {
        "pkg:npm/lodash@4.17.15",
        "pkg:pypi/requests@2.20.0",
    }


# ---------------------------------------------------------------------------
# Scenario 3 — PARTIAL batch: mixing cached + new components.
# ---------------------------------------------------------------------------


def test_partial_batch_only_misses_hit_querybatch(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=True)
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
        "pkg:pypi/requests@2.20.0": ["OSV-FAKE-REQUESTS"],
    }
    osv_network.vuln_payloads = {
        "OSV-FAKE-LODASH": _LODASH_VULN,
        "OSV-FAKE-REQUESTS": _REQUESTS_VULN,
    }

    # First scan caches both components.
    asyncio.run(osv_query_by_components(_components_two_npm(), settings))
    qb_before = len(osv_network.querybatch_calls)

    # Second scan: lodash (cached) + a NEW component (not cached).
    new_components = [
        _components_two_npm()[0],  # lodash — cached
        {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
    ]
    osv_network.querybatch_results_for["pkg:npm/express@4.18.0"] = []

    asyncio.run(osv_query_by_components(new_components, settings))

    # Querybatch was called ONCE more, with ONLY the express query.
    assert len(osv_network.querybatch_calls) == qb_before + 1
    new_qb = osv_network.querybatch_calls[-1]
    purls_in_batch = [
        ((q or {}).get("package") or {}).get("purl") for q in new_qb["queries"]
    ]
    assert purls_in_batch == ["pkg:npm/express@4.18.0"], (
        f"querybatch should have ONLY the miss component, got {purls_in_batch!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 4 — Empty-result caching: components with no vulns hit on re-scan.
# ---------------------------------------------------------------------------


def test_empty_results_are_cached(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=True)
    # Lodash has a vuln; requests has NONE.
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
        "pkg:pypi/requests@2.20.0": [],
    }
    osv_network.vuln_payloads = {"OSV-FAKE-LODASH": _LODASH_VULN}

    components = _components_two_npm()
    asyncio.run(osv_query_by_components(components, settings))

    # BOTH components cached, even though one is empty.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
    keys = {r.component_key for r in rows}
    assert "pkg:pypi/requests@2.20.0" in keys, (
        "empty-result component must still be cached (empty hit > re-fetch)"
    )

    qb_before = len(osv_network.querybatch_calls)
    asyncio.run(osv_query_by_components(components, settings))
    assert len(osv_network.querybatch_calls) == qb_before, (
        "re-scan must NOT re-query the empty-result component"
    )


# ---------------------------------------------------------------------------
# Scenario 5 — Reprocess-equals-live: cached findings == live findings.
# ---------------------------------------------------------------------------


def test_reprocess_equals_live_for_querybatch_path(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=True)
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
    }
    osv_network.vuln_payloads = {"OSV-FAKE-LODASH": _LODASH_VULN}

    components = _components_two_npm()
    live_findings, _, _ = asyncio.run(
        osv_query_by_components(components, settings)
    )
    cached_findings, _, _ = asyncio.run(
        osv_query_by_components(components, settings)
    )
    assert live_findings == cached_findings, (
        "cached re-scan findings must be IDENTICAL to the live scan — "
        "processing runs fresh on every hit"
    )


def test_reprocess_equals_live_for_fallback_path(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    """When querybatch returns nothing, fallback fires. Cached fallback
    payloads must replay through fallback's normaliser and yield
    identical findings.
    """
    settings = _settings_with(cache_on=True)
    # Querybatch empty → fallback fires.
    osv_network.querybatch_results_for = {}
    osv_network.query_payloads_for = {
        "pkg:npm/lodash@4.17.15": [_LODASH_VULN],
    }
    components = [{"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]

    live_findings, _, _ = asyncio.run(
        osv_query_by_components(components, settings)
    )
    cached_findings, _, _ = asyncio.run(
        osv_query_by_components(components, settings)
    )

    assert len(live_findings) == 1, (
        f"first scan should have fired fallback and produced one finding, "
        f"got {len(live_findings)}"
    )
    # Fallback's normaliser uses comp.get("name") = "lodash" directly.
    assert live_findings[0]["component_name"] == "lodash"
    assert live_findings == cached_findings, (
        "cached fallback scan must produce identical findings — replay "
        "must dispatch on source_path=fallback"
    )

    # Cache row exists with the fallback provenance tag.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
    assert len(rows) == 1
    payload = rows[0].payload
    if isinstance(payload, str):
        # SQLite TEXT JSON — should still round-trip via repo.get; we
        # only inspect for shape here, so parse.
        import json as _json
        payload = _json.loads(payload)
    assert payload.get("source_path") == "fallback"


# ---------------------------------------------------------------------------
# Scenario 6 — TTL expiry: next scan re-fetches.
# ---------------------------------------------------------------------------


def test_ttl_expiry_triggers_refetch(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    osv_network: _OsvNetwork,
) -> None:
    settings = _settings_with(cache_on=True, ttl_seconds=3600)
    osv_network.querybatch_results_for = {
        "pkg:npm/lodash@4.17.15": ["OSV-FAKE-LODASH"],
    }
    osv_network.vuln_payloads = {"OSV-FAKE-LODASH": _LODASH_VULN}
    components = [{"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]

    # Scan 1 at T0 → write cache.
    controlled_clock["now"] = _T0
    asyncio.run(osv_query_by_components(components, settings))
    assert len(osv_network.querybatch_calls) == 1

    # Scan 2 at T0+30m → cache hit.
    controlled_clock["now"] = _T0 + timedelta(minutes=30)
    asyncio.run(osv_query_by_components(components, settings))
    assert len(osv_network.querybatch_calls) == 1

    # Scan 3 at T0+2h → TTL elapsed → refetch.
    controlled_clock["now"] = _T0 + timedelta(hours=2)
    asyncio.run(osv_query_by_components(components, settings))
    assert len(osv_network.querybatch_calls) == 2
