"""Phase 6 — counter helper + integration with use cases / facade / adapter."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.nvd_mirror.application._window_walker import HISTORICAL_FLOOR
from app.nvd_mirror.application import BootstrapMirror
from app.nvd_mirror.application.facade import NvdLookupService
from app.nvd_mirror.observability import Counters, mirror_counters

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


@pytest.fixture(autouse=True)
def _reset_counters() -> None:
    """Phase 6 counters live in a process-global singleton; reset per test."""
    mirror_counters.reset()


# --- Counters class -------------------------------------------------------


def test_counters_increment_and_snapshot() -> None:
    c = Counters()
    c.increment("a")
    c.increment("a", 4)
    c.increment("b")
    snap = c.snapshot()
    assert snap == {"a": 5, "b": 1}


def test_counters_reset_clears_all() -> None:
    c = Counters()
    c.increment("x", 10)
    c.reset()
    assert c.snapshot() == {}


def test_counters_ignore_non_positive_increments() -> None:
    c = Counters()
    c.increment("x", 0)
    c.increment("x", -5)
    assert c.snapshot() == {}


def test_counters_threadsafe_under_concurrent_increments() -> None:
    c = Counters()

    def worker() -> None:
        for _ in range(1000):
            c.increment("x")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.snapshot() == {"x": 8000}


# --- Window walker increments --------------------------------------------


@pytest.mark.asyncio
async def test_window_success_counter_increments_per_window() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=70)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    w1 = (HISTORICAL_FLOOR, HISTORICAL_FLOOR + timedelta(days=30))
    w2 = (HISTORICAL_FLOOR + timedelta(days=30), HISTORICAL_FLOOR + timedelta(days=60))
    w3 = (HISTORICAL_FLOOR + timedelta(days=60), target)
    # Distinct records per window — repeating the same CVE would be a
    # no-op upsert by the idempotency contract.
    rec1 = make_record("CVE-W1", last_modified=w1[1] - timedelta(seconds=1))
    rec2 = make_record("CVE-W2", last_modified=w2[1] - timedelta(seconds=1))
    rec3 = make_record("CVE-W3", last_modified=w3[1] - timedelta(seconds=1))

    remote = FakeNvdRemote(
        {w1: [batch([rec1])], w2: [batch([rec2])], w3: [batch([rec3])]}
    )

    await BootstrapMirror(
        remote=remote,
        cve_repo=FakeCveRepository(),
        settings_repo=FakeSettingsRepository(snap),
        sync_run_repo=FakeSyncRunRepository(),
        clock=FixedClock(target),
        commit=lambda: None,
    ).execute(now=target)

    counts = mirror_counters.snapshot()
    assert counts.get("nvd.windows.success") == 3
    assert counts.get("nvd.windows.failure", 0) == 0
    assert counts.get("nvd.cves.upserted") == 3


@pytest.mark.asyncio
async def test_window_failure_counter_on_remote_error() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    remote = FakeNvdRemote(
        raise_on_nth_call=1, raise_exc=RuntimeError("boom")
    )

    await BootstrapMirror(
        remote=remote,
        cve_repo=FakeCveRepository(),
        settings_repo=FakeSettingsRepository(snap),
        sync_run_repo=FakeSyncRunRepository(),
        clock=FixedClock(target),
        commit=lambda: None,
    ).execute(now=target)

    counts = mirror_counters.snapshot()
    assert counts.get("nvd.windows.failure") == 1
    assert counts.get("nvd.windows.success", 0) == 0


# --- Facade live-fallback counter ----------------------------------------


def _live_returning(payload: list[dict]):
    def _fn(cpe, api_key, settings):  # noqa: ARG001
        return payload

    return _fn


def test_live_fallback_counter_fires_on_stale_mirror() -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=datetime.now(tz=UTC) - timedelta(hours=48),
    )
    fac = NvdLookupService(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=FakeCveRepository(),
        clock=FixedClock(datetime.now(tz=UTC)),
        live_query=_live_returning([]),
    )
    fac.query_legacy("cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*", api_key=None, settings=object())
    assert mirror_counters.snapshot().get("nvd.live_fallbacks") == 1


def test_live_fallback_counter_NOT_fired_on_disabled_mirror() -> None:
    """Disabled is the default state — counting it as a fallback would
    be misleading. Only stale/empty/raises should count."""
    snap = make_snapshot(enabled=False)
    fac = NvdLookupService(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=FakeCveRepository(),
        clock=FixedClock(datetime.now(tz=UTC)),
        live_query=_live_returning([]),
    )
    fac.query_legacy("cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*", api_key=None, settings=object())
    assert "nvd.live_fallbacks" not in mirror_counters.snapshot()


def test_live_fallback_counter_fires_on_empty_mirror() -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=datetime.now(tz=UTC) - timedelta(hours=1),
    )
    fac = NvdLookupService(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=FakeCveRepository(),
        clock=FixedClock(datetime.now(tz=UTC)),
        live_query=_live_returning([]),
    )
    fac.query_legacy("cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*", api_key=None, settings=object())
    assert mirror_counters.snapshot().get("nvd.live_fallbacks") == 1


# --- HTTP adapter 429 counter --------------------------------------------


@pytest.mark.asyncio
async def test_429_counter_increments_per_429(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity check that the 429 counter increments — fully exercised by
    the HTTP adapter contract tests; here we just verify wiring."""
    import httpx

    from app.nvd_mirror.adapters.nvd_http import (
        NvdHttpAdapter,
        _RetryableHttpError,
    )
    from app.nvd_mirror.domain.models import MirrorWindow

    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.RETRY_INITIAL_WAIT", 0.0)
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.RETRY_MAX_WAIT", 0.01)
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.SLEEP_WITH_KEY_SECONDS", 0.0)
    # Patch out the post-429 sleep so the test runs fast.
    real_sleep = asyncio.sleep
    monkeypatch.setattr(
        "app.nvd_mirror.adapters.nvd_http.asyncio.sleep",
        lambda s: real_sleep(0),
    )

    counts = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        return httpx.Response(429, headers={"Retry-After": "0"}, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="k", client=client
    )

    window = MirrorWindow(
        start=datetime(2024, 4, 1, tzinfo=UTC),
        end=datetime(2024, 4, 2, tzinfo=UTC),
    )
    with pytest.raises(_RetryableHttpError):
        async for _ in adapter.fetch_window(window, page_size=2000):
            pass
    await client.aclose()

    # Exactly one 429 increment per 429 response. Tenacity retried 5 times.
    assert mirror_counters.snapshot().get("nvd.api.429_count") == counts["calls"]
