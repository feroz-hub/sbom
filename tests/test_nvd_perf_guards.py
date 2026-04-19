"""
Guards for the NVD performance fix that dropped the phase from 7m49s to <30s.

Three independent changes are pinned here:

  Change 1 — sleep defaults must honour the public NVD rate limits:
              no key  → ≥ 6.0 s between calls   (5 req / 30 s)
              w/ key  → ≥ 0.6 s between calls   (50 req / 30 s)

  Change 2 — components without a CPE must be *skipped*, never routed to
              ``keywordSearch``. OSV + GHSA already cover them via PURL
              and the keyword path burns rate limit for marginal value.

  Change 3 — NVD phase must run **sequentially** (one request at a time).
              Concurrent fan-out + per-worker sleep violates NVD's *global*
              rate limit (50/30s with key) — N workers × 1/sleep req/s.
              That produces 429 piles and stalls the phase. Sequential
              (45 × 0.6s ≈ 27s) stays under the ceiling by construction.
              Also: 429 responses must honour ``Retry-After``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Change 1: sleep defaults
# ---------------------------------------------------------------------------


def test_nvd_default_sleep_with_key_is_0_6s_or_less(monkeypatch):
    """With key, NVD allows 50/30s — sleep must be <= 0.6s or we waste the key."""
    from app.analysis import get_analysis_settings

    # Defaults (env unset)
    for var in (
        "NVD_REQUEST_DELAY_WITH_KEY_SECONDS",
        "NVD_REQUEST_DELAY_WITHOUT_KEY_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    get_analysis_settings.cache_clear()

    cfg = get_analysis_settings()
    assert cfg.nvd_request_delay_with_key_seconds == pytest.approx(0.6, abs=0.01)
    assert cfg.nvd_request_delay_without_key_seconds == pytest.approx(6.0, abs=0.01)


def test_nvd_fan_out_is_sequential_not_concurrent(monkeypatch):
    """
    NVD's rate limit is a GLOBAL token bucket (50/30s with key). Concurrent
    fan-out with per-worker sleep violates the global ceiling:
        N workers × (1 / sleep_s) req/s ≫ 50/30s
    For N=10 workers and sleep=0.6s that is 16.7 req/s vs NVD's 1.67 req/s —
    10x over. All workers get 429s and stall in Retry-After backoff.

    Guard: the fan-out must issue requests one at a time. Observed by
    asserting only one inflight executor call to ``nvd_query_by_cpe`` at
    any given moment during a run.
    """
    import threading
    from app import analysis

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    # Zero the inter-request delay so the test is fast — it does not
    # affect the sequential-vs-concurrent behaviour under test.
    monkeypatch.setenv("NVD_REQUEST_DELAY_WITHOUT_KEY_SECONDS", "0.0")
    analysis.get_analysis_settings.cache_clear()

    inflight = {"n": 0, "max": 0}
    lock = threading.Lock()

    def _fake_cpe(cpe, api_key, settings=None):
        with lock:
            inflight["n"] += 1
            if inflight["n"] > inflight["max"]:
                inflight["max"] = inflight["n"]
        try:
            # Small hold so the scheduler would interleave workers if the
            # code were concurrent.
            time.sleep(0.02)
            return []
        finally:
            with lock:
                inflight["n"] -= 1

    monkeypatch.setattr(analysis, "nvd_query_by_cpe", _fake_cpe)

    components = [
        {"name": f"pkg-{i}", "version": "1.0",
         "cpe": f"cpe:2.3:a:vendor:pkg-{i}:1.0:*:*:*:*:*:*:*"}
        for i in range(8)
    ]

    findings, errors, _ = asyncio.run(
        analysis.nvd_query_by_components_async(components, _FakeMultiSettings(), nvd_api_key=None)
    )

    assert errors == []
    assert inflight["max"] == 1, (
        f"NVD fan-out must be sequential (max inflight == 1), "
        f"saw max inflight = {inflight['max']}"
    )


# ---------------------------------------------------------------------------
# Change 2: no-CPE components are SKIPPED, never keyword-searched
# ---------------------------------------------------------------------------


class _FakeMultiSettings:
    """Minimal stub of `_MultiSettings` for the fan-out path."""
    max_concurrency = 10
    nvd_api_key_env = "NVD_API_KEY"


def test_fan_out_skips_components_with_no_cpe_and_never_calls_keyword(monkeypatch, caplog):
    """
    The fan-out must:
      * skip every component that has no CPE (no keyword fallback)
      * log 'NVD: N queried, M skipped (no CPE)'
    """
    from app import analysis

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    analysis.get_analysis_settings.cache_clear()

    # Hard-fail if the keyword path is ever invoked.
    def _boom(*_a, **_kw):
        raise AssertionError("nvd_query_by_keyword must NOT be called — no-CPE components must be skipped")

    monkeypatch.setattr(analysis, "nvd_query_by_keyword", _boom)
    # Stub the CPE path so the test doesn't hit the network.
    monkeypatch.setattr(analysis, "nvd_query_by_cpe", lambda cpe, api_key, settings=None: [])

    components = [
        {"name": "axios", "version": "0.21.1", "cpe": "cpe:2.3:a:axios:axios:0.21.1:*:*:*:*:*:*:*"},
        {"name": "log4j-core", "version": "2.14.1", "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        {"name": "Microsoft.AspNetCore.Http", "version": "2.2.0"},   # no CPE
        {"name": "some-internal-pkg", "version": "1.0.0"},            # no CPE
    ]

    with caplog.at_level(logging.INFO, logger="app.analysis"):
        findings, errors, _ = asyncio.run(
            analysis.nvd_query_by_components_async(components, _FakeMultiSettings(), nvd_api_key=None)
        )

    # Skipped count log line present
    skip_lines = [r.message for r in caplog.records if "queried" in r.message and "skipped" in r.message]
    assert skip_lines, "expected a 'NVD: N queried, M skipped (no CPE)' info log"
    assert "2 queried" in skip_lines[0]
    assert "2 skipped" in skip_lines[0]

    # Did not produce errors just from missing CPE
    assert errors == []


# ---------------------------------------------------------------------------
# Change 3: Retry-After honoured on 429
# ---------------------------------------------------------------------------


def test_paginated_stops_when_total_results_exceeds_cap(monkeypatch):
    """
    Pins the runaway-pagination guard that caused a 47-minute NVD stall.
    A single CPE query that reports ``totalResults`` above
    ``nvd_max_total_results_per_query`` must stop after the first page
    rather than walk thousands of pages at 0.6s each.
    """
    import requests
    from app import analysis

    analysis.get_analysis_settings.cache_clear()
    cfg = analysis.get_analysis_settings()

    sleeps: list[float] = []
    monkeypatch.setattr(analysis.time, "sleep", lambda s: sleeps.append(s))

    call_count = {"n": 0}

    class _BigResp:
        status_code = 200
        headers: dict = {}
        def raise_for_status(self):
            return None
        def json(self):
            # 20x the cap; claim there are 10,000 total results but
            # return an empty first page so the loop must rely on
            # totalResults to decide whether to keep paginating.
            return {"vulnerabilities": [], "totalResults": 10_000, "resultsPerPage": 2000}

    def _fake_get(*_a, **_kw):
        call_count["n"] += 1
        return _BigResp()

    monkeypatch.setattr(analysis._nvd_session, "get", _fake_get)

    out = analysis._nvd_fetch_cves_paginated(
        cfg, headers={}, search_params={"cpeName": "cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"},
        delay=0.6, log_label="test",
    )

    assert out == []
    # Must stop after the first page once the cap is exceeded — no runaway.
    assert call_count["n"] == 1, (
        f"expected pagination to stop after first page when totalResults > cap, "
        f"but fetched {call_count['n']} pages"
    )


def test_nvd_query_by_cpe_caps_pages_per_query(monkeypatch):
    """
    Even when ``totalResults`` is suspiciously low, pagination must not
    exceed ``nvd_max_pages_per_query``. This catches the degenerate
    server behaviour where ``resultsPerPage`` is tiny compared to
    ``totalResults``.
    """
    from app import analysis

    monkeypatch.setenv("NVD_MAX_PAGES_PER_QUERY", "3")
    analysis.get_analysis_settings.cache_clear()
    cfg = analysis.get_analysis_settings()
    assert cfg.nvd_max_pages_per_query == 3

    monkeypatch.setattr(analysis.time, "sleep", lambda s: None)

    call_count = {"n": 0}

    class _Resp:
        status_code = 200
        headers: dict = {}
        def raise_for_status(self):
            return None
        def json(self):
            # Small under-cap total (300 < 500) but tiny page size
            # forces the loop to want many pages — page cap must trip.
            return {"vulnerabilities": [{"cve": {"id": "CVE-X"}}],
                    "totalResults": 300, "resultsPerPage": 1}

    def _fake_get(*_a, **_kw):
        call_count["n"] += 1
        return _Resp()

    monkeypatch.setattr(analysis._nvd_session, "get", _fake_get)

    out = analysis._nvd_fetch_cves_paginated(
        cfg, headers={}, search_params={"cpeName": "cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"},
        delay=0.0, log_label="test",
    )

    assert call_count["n"] == 3, (
        f"page cap should limit requests to {cfg.nvd_max_pages_per_query}, "
        f"got {call_count['n']}"
    )
    assert len(out) == 3  # one CVE per fetched page


def test_paginated_retries_honour_retry_after_header(monkeypatch):
    """
    When NVD returns 429 with ``Retry-After: N`` the next retry must sleep
    at least N seconds — not our own (smaller) linear backoff.
    """
    import requests
    from app import analysis

    analysis.get_analysis_settings.cache_clear()
    cfg = analysis.get_analysis_settings()

    # Short-circuit backoff so we don't delay tests.
    sleeps: list[float] = []
    monkeypatch.setattr(analysis.time, "sleep", lambda s: sleeps.append(s))

    # First call: 429 with Retry-After=7; second call: 200 with empty body.
    class _Resp429:
        status_code = 429
        headers = {"Retry-After": "7"}
        def raise_for_status(self):
            raise requests.HTTPError("429", response=self)
        def json(self):
            return {}

    class _Resp200:
        status_code = 200
        headers = {}
        def raise_for_status(self):
            return None
        def json(self):
            return {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}

    calls = {"n": 0}
    def _fake_get(*_a, **_kw):
        calls["n"] += 1
        return _Resp429() if calls["n"] == 1 else _Resp200()

    monkeypatch.setattr(analysis._nvd_session, "get", _fake_get)

    out = analysis._nvd_fetch_cves_paginated(
        cfg, headers={}, search_params={"cpeName": "cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"},
        delay=0.0, log_label="test",
    )
    assert out == []
    # The backoff should have been at least the server's Retry-After (7s).
    assert any(s >= 7.0 for s in sleeps), f"expected Retry-After (7s) to dominate, saw sleeps={sleeps}"
