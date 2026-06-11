"""Integration tests for the GHSA source-response cache wrap
(roadmap #2, PR-C).

Exercises ``github_query_by_components`` end-to-end with the GitHub
GraphQL transport (``_async_post``) mocked. Uses the real
``SourceResponseCacheRepository`` backed by an in-memory SQLite so
cache writes are observable.

Covers the brief's five scenarios:
  1. Flag OFF → fetch called every scan; no cache rows.
  2. Flag ON, re-scan reuse → second scan calls fetch ZERO times.
  3. Reprocess-equals-live → findings identical.
  4. Versionless-key win → two components sharing ``(eco, name)`` but
     different versions reuse one cache row across scans (the whole
     reason GHSA needs a versionless key).
  5. TTL expiry → advance the cache repository's clock; next scan
     fetches again.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterator
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.analysis import (
    get_analysis_settings_multi,
    github_query_by_components,
)
from app.db import Base
from app.models import SourceResponseCache
from app.services.source_response_cache import SourceResponseCacheRepository
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures: in-memory DB + monkeypatched SessionLocal + controlled clock
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
# GHSA harness: minimal GraphQL response with one advisory node
# ---------------------------------------------------------------------------


_GHSA_RESPONSE = {
    "data": {
        "securityVulnerabilities": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [
                {
                    "severity": "HIGH",
                    "updatedAt": "2024-04-16T01:23:45Z",
                    "advisory": {
                        "ghsaId": "GHSA-test-cccc-dddd",
                        "summary": "Synthetic advisory for the GHSA cache test.",
                        "description": "Vulnerable when used with affected components.",
                        "publishedAt": "2024-01-15T12:00:00Z",
                        "references": [{"url": "https://example.com/advisory"}],
                        "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N"},
                        "cwes": {"nodes": [{"cweId": "CWE-79", "name": "XSS"}]},
                        "identifiers": [
                            {"type": "GHSA", "value": "GHSA-test-cccc-dddd"},
                            {"type": "CVE", "value": "CVE-2024-EXAMPLE"},
                        ],
                    },
                    "vulnerableVersionRange": ">= 1.0.0, < 2.0.0",
                    "firstPatchedVersion": {"identifier": "2.0.0"},
                    "package": {"name": "lodash", "ecosystem": "NPM"},
                }
            ],
        }
    }
}


@pytest.fixture()
def network_mock(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Mock ``_async_post`` in app.analysis. Counts calls and returns a
    deep-copy of the canned GHSA response so consumers can't mutate it.
    """
    state: dict[str, Any] = {"calls": 0, "last_variables": None}

    async def _fake_post(url, json_body=None, headers=None, timeout=None):  # noqa: ARG001
        state["calls"] += 1
        if isinstance(json_body, dict):
            state["last_variables"] = (json_body.get("variables") or {}).copy()
        return copy.deepcopy(_GHSA_RESPONSE)

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "_async_post", _fake_post)
    # Force the GitHub token check to pass without env-var dependence.
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    return state


# ---------------------------------------------------------------------------
# Settings helper
# ---------------------------------------------------------------------------


def _settings_with(cache_on: bool, ttl_seconds: int = 4 * 3600) -> Any:
    """Build a ``_MultiSettings`` with the cache flag flipped — start
    from the cached singleton so every other field stays at its
    production default.
    """
    base = get_analysis_settings_multi()
    return dataclass_replace(
        base,
        source_cache_enabled=cache_on,
        source_cache_ttl_seconds=ttl_seconds,
    )


def _components_single() -> list[dict]:
    return [
        {
            "name": "lodash",
            "version": "1.5.0",
            "purl": "pkg:npm/lodash@1.5.0",
        }
    ]


def _components_two_versions_same_pkg() -> list[dict]:
    """Two components mapping to the SAME (eco, name) — different versions."""
    return [
        {"name": "lodash", "version": "1.5.0", "purl": "pkg:npm/lodash@1.5.0"},
        {"name": "lodash", "version": "1.6.0", "purl": "pkg:npm/lodash@1.6.0"},
    ]


# ---------------------------------------------------------------------------
# 1. Flag OFF → live every scan, no cache rows
# ---------------------------------------------------------------------------


def test_flag_off_every_scan_fetches_and_writes_no_cache(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=False)
    comps = _components_single()

    asyncio.run(github_query_by_components(comps, settings))
    asyncio.run(github_query_by_components(comps, settings))

    assert network_mock["calls"] == 2

    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
        assert rows == []


# ---------------------------------------------------------------------------
# 2. Flag ON, re-scan reuse → second scan calls fetch ZERO times
# ---------------------------------------------------------------------------


def test_flag_on_second_scan_hits_cache(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=True)
    comps = _components_single()

    asyncio.run(github_query_by_components(comps, settings))
    first_calls = network_mock["calls"]
    asyncio.run(github_query_by_components(comps, settings))
    second_calls = network_mock["calls"]

    assert first_calls == 1, "scan 1 should have fetched exactly once"
    assert second_calls == 1, (
        f"scan 2 should have been a cache hit; total fetches now {second_calls}"
    )

    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
        assert len(rows) == 1
        assert rows[0].source == "GITHUB"
        # Versionless PURL key (npm lowercases name).
        assert rows[0].component_key == "pkg:npm/lodash"


# ---------------------------------------------------------------------------
# 3. Reprocess-equals-live → identical findings across scans
# ---------------------------------------------------------------------------


def test_cached_findings_identical_to_live_findings(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    """The cache is a transparent I/O cache — processing runs fresh on
    every hit so #1 / #3 / #6 stay coherent.
    """
    settings = _settings_with(cache_on=True)
    comps = _components_single()

    first_findings, first_errors, _ = asyncio.run(
        github_query_by_components(comps, settings)
    )
    second_findings, second_errors, _ = asyncio.run(
        github_query_by_components(comps, settings)
    )

    assert first_errors == [] == second_errors
    assert first_findings == second_findings
    assert len(first_findings) == 1
    assert first_findings[0]["vuln_id"] == "GHSA-test-cccc-dddd"
    assert first_findings[0]["match_strategy"] == "ghsa_alias"


# ---------------------------------------------------------------------------
# 4. VERSIONLESS-KEY WIN — different versions of same package reuse one cache row
# ---------------------------------------------------------------------------


def test_versionless_key_reuse_across_versions(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    """Two SBOMs differ in version (lodash@1.5.0 vs lodash@1.6.0) but
    share the same (eco, name). The cache MUST reuse one row — that
    is the whole reason GHSA needs a versionless key.

    Scan 1 contains lodash@1.5.0 → miss → fetch → cache.
    Scan 2 contains lodash@1.6.0 → cache HIT (same versionless key).

    The existing (eco, name) dedup means a SINGLE scan with both
    versions ALREADY runs only one query; this test exercises the
    cross-scan case where the existing dedup has nothing to dedupe.
    """
    settings = _settings_with(cache_on=True)

    # Scan 1: lodash@1.5.0 only.
    asyncio.run(github_query_by_components(_components_single(), settings))
    assert network_mock["calls"] == 1

    # Scan 2: lodash@1.6.0 only — different version, same (eco, name).
    asyncio.run(
        github_query_by_components(
            [{"name": "lodash", "version": "1.6.0", "purl": "pkg:npm/lodash@1.6.0"}],
            settings,
        )
    )
    assert network_mock["calls"] == 1, (
        "scan 2 with a different version must have HIT the cache "
        "(versionless key)"
    )

    # Sanity — exactly one cache row.
    with isolated_session_factory() as s:
        rows = s.query(SourceResponseCache).all()
        assert len(rows) == 1
        assert rows[0].component_key == "pkg:npm/lodash"


def test_existing_dedup_within_single_scan_still_holds(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    """Sanity check — the pre-existing (eco, name) dedup MUST still
    fire when both versions appear in ONE scan. PR-C doesn't change
    that.
    """
    settings = _settings_with(cache_on=True)
    asyncio.run(
        github_query_by_components(_components_two_versions_same_pkg(), settings)
    )
    # Both components dedupe to one (eco, name) — one fetch, regardless
    # of the cache.
    assert network_mock["calls"] == 1


# ---------------------------------------------------------------------------
# 5. TTL expiry → advance clock, next scan re-fetches
# ---------------------------------------------------------------------------


def test_ttl_expiry_triggers_refetch(
    isolated_session_factory: sessionmaker,
    controlled_clock: dict[str, datetime],
    network_mock: dict[str, Any],
) -> None:
    settings = _settings_with(cache_on=True, ttl_seconds=3600)
    comps = _components_single()

    # Scan 1 at T0 — fetch + cache.
    controlled_clock["now"] = _T0
    asyncio.run(github_query_by_components(comps, settings))
    assert network_mock["calls"] == 1

    # Scan 2 at T0+30min — cache hit.
    controlled_clock["now"] = _T0 + timedelta(minutes=30)
    asyncio.run(github_query_by_components(comps, settings))
    assert network_mock["calls"] == 1

    # Scan 3 at T0+2h — TTL elapsed (1h), re-fetch.
    controlled_clock["now"] = _T0 + timedelta(hours=2)
    asyncio.run(github_query_by_components(comps, settings))
    assert network_mock["calls"] == 2
