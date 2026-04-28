"""Phase 3.1 — NvdHttpAdapter tests using httpx.MockTransport.

We avoid pulling in ``respx`` (which would expand the test-dep surface).
``httpx.MockTransport`` is built into httpx itself and is enough to
exercise pagination, retry, Retry-After, and 120-day enforcement.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from app.nvd_mirror.adapters.nvd_http import (
    NvdHttpAdapter,
    NvdRemoteError,
    _RetryableHttpError,
)
from app.nvd_mirror.domain.models import MirrorWindow


UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# Patch the inter-request sleep AND the tenacity backoff to zero so tests
# are fast.
@pytest.fixture(autouse=True)
def _zero_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.SLEEP_WITH_KEY_SECONDS", 0.0)
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.SLEEP_WITHOUT_KEY_SECONDS", 0.0)
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.RETRY_INITIAL_WAIT", 0.01)
    monkeypatch.setattr("app.nvd_mirror.adapters.nvd_http.RETRY_MAX_WAIT", 0.05)


def _make_window() -> MirrorWindow:
    return MirrorWindow(
        start=datetime(2024, 4, 1, tzinfo=UTC),
        end=datetime(2024, 4, 16, tzinfo=UTC),
    )


# --- happy path -----------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_window_yields_one_batch_for_single_page() -> None:
    payload = _load("cve_log4j_window.json")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    batches = []
    async for b in adapter.fetch_window(_make_window(), page_size=2000):
        batches.append(b)

    assert len(batches) == 1
    assert batches[0].total_results == 2
    assert {r.cve_id for r in batches[0].records} == {"CVE-2021-44228", "CVE-2099-REJECT"}
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_paginates_until_exhausted() -> None:
    page1 = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-A",
                    "lastModified": "2024-04-15T00:00:00.000",
                    "published": "2024-01-01T00:00:00.000",
                    "vulnStatus": "Analyzed",
                }
            }
        ],
    }
    page2 = {
        "resultsPerPage": 1,
        "startIndex": 1,
        "totalResults": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-B",
                    "lastModified": "2024-04-16T00:00:00.000",
                    "published": "2024-01-02T00:00:00.000",
                    "vulnStatus": "Analyzed",
                }
            }
        ],
    }

    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.params.get("startIndex", 0))
        calls.append(idx)
        return httpx.Response(200, json=page1 if idx == 0 else page2)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    cve_ids: list[str] = []
    async for b in adapter.fetch_window(_make_window(), page_size=1):
        cve_ids.extend(r.cve_id for r in b.records)

    assert cve_ids == ["CVE-A", "CVE-B"]
    assert calls == [0, 1]
    await client.aclose()


# --- retry behaviour ------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_window_retries_on_429_then_succeeds() -> None:
    payload = _load("cve_log4j_window.json")
    counts = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        if counts["calls"] == 1:
            return httpx.Response(
                429, json={}, headers={"Retry-After": "0"}
            )
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    batches = [b async for b in adapter.fetch_window(_make_window(), page_size=2000)]
    assert len(batches) == 1
    assert counts["calls"] == 2  # 1 retry + success
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_retries_on_503_then_succeeds() -> None:
    payload = _load("cve_log4j_window.json")
    counts = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        if counts["calls"] == 1:
            return httpx.Response(503, json={})
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    batches = [b async for b in adapter.fetch_window(_make_window(), page_size=2000)]
    assert len(batches) == 1
    assert counts["calls"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counts = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        return httpx.Response(429, json={}, headers={"Retry-After": "0"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    with pytest.raises(_RetryableHttpError):
        async for _ in adapter.fetch_window(_make_window(), page_size=2000):
            pass
    # 5 attempts per the constant.
    assert counts["calls"] == 5
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_does_not_retry_400() -> None:
    counts = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        return httpx.Response(400, json={"detail": "bad request"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )
    with pytest.raises(httpx.HTTPStatusError):
        async for _ in adapter.fetch_window(_make_window(), page_size=2000):
            pass
    assert counts["calls"] == 1  # not retried
    await client.aclose()


# --- 429 with Retry-After honoured ----------------------------------------


@pytest.mark.asyncio
async def test_fetch_window_honours_retry_after_header() -> None:
    counts = {"calls": 0}
    sleeps: list[float] = []

    real_sleep = asyncio.sleep

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        await real_sleep(0)

    def handler(request: httpx.Request) -> httpx.Response:
        counts["calls"] += 1
        if counts["calls"] == 1:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={})
        return httpx.Response(200, json=_load("cve_empty_window.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="key", client=client
    )

    import app.nvd_mirror.adapters.nvd_http as adapter_mod

    orig_sleep = adapter_mod.asyncio.sleep
    adapter_mod.asyncio.sleep = fake_sleep
    try:
        async for _ in adapter.fetch_window(_make_window(), page_size=2000):
            pass
    finally:
        adapter_mod.asyncio.sleep = orig_sleep

    # First sleep is the 3-second Retry-After honour.
    assert 3.0 in sleeps
    await client.aclose()


# --- request shape --------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_window_sends_api_key_header() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(dict(request.headers))
        return httpx.Response(200, json=_load("cve_empty_window.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0",
        api_key="my-key-1234",
        client=client,
    )
    async for _ in adapter.fetch_window(_make_window(), page_size=2000):
        pass
    assert seen_headers.get("apikey") == "my-key-1234"
    assert seen_headers.get("user-agent", "").startswith("SBOM-Analyzer-NvdMirror")
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_omits_api_key_header_when_unset() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(dict(request.headers))
        return httpx.Response(200, json=_load("cve_empty_window.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key=None, client=client
    )
    async for _ in adapter.fetch_window(_make_window(), page_size=2000):
        pass
    assert "apikey" not in seen_headers
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_sends_lastmod_dates_in_iso_format() -> None:
    seen_params: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.update(dict(request.url.params))
        return httpx.Response(200, json=_load("cve_empty_window.json"))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="k", client=client
    )
    async for _ in adapter.fetch_window(_make_window(), page_size=2000):
        pass
    assert "lastModStartDate" in seen_params
    assert "lastModEndDate" in seen_params
    assert seen_params["lastModStartDate"].startswith("2024-04-01")
    assert seen_params["lastModEndDate"].startswith("2024-04-16")
    assert seen_params["resultsPerPage"] == "2000"
    assert seen_params["startIndex"] == "0"
    await client.aclose()


# --- 120-day enforcement (defense-in-depth at adapter boundary) -----------


def test_window_construction_rejects_overlong_window() -> None:
    """The adapter relies on MirrorWindow's invariant. Verify that here."""
    with pytest.raises(ValueError, match="exceeds NVD ceiling"):
        MirrorWindow(
            start=datetime(2024, 1, 1, tzinfo=UTC),
            end=datetime(2024, 6, 1, tzinfo=UTC),  # > 119 days
        )


# --- short-circuit guards -------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_window_short_circuits_on_unexpected_empty_page() -> None:
    """Page with zero records but totalResults > 0 must not loop forever."""
    payload = {
        "resultsPerPage": 100,
        "startIndex": 0,
        "totalResults": 1000,
        "vulnerabilities": [],  # empty despite total > 0
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0", api_key="k", client=client
    )
    pages = 0
    async for _ in adapter.fetch_window(_make_window(), page_size=100):
        pages += 1
    assert pages == 1  # short-circuited
    await client.aclose()


@pytest.mark.asyncio
async def test_fetch_window_caps_pages_per_window() -> None:
    """Defensive cap prevents runaway pagination."""

    def handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.params.get("startIndex", 0))
        # Always return one record and a fake total > what we'll ever fetch.
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 1,
                "startIndex": idx,
                "totalResults": 999_999,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": f"CVE-X-{idx}",
                            "lastModified": "2024-04-15T00:00:00.000",
                            "published": "2024-01-01T00:00:00.000",
                            "vulnStatus": "Analyzed",
                        }
                    }
                ],
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adapter = NvdHttpAdapter(
        api_endpoint="https://nvd.test/cves/2.0",
        api_key="k",
        client=client,
        max_pages_per_window=5,
    )
    pages = 0
    async for _ in adapter.fetch_window(_make_window(), page_size=1):
        pages += 1
    assert pages == 5  # capped
    await client.aclose()


# --- aclose ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_aclose_closes_owned_client() -> None:
    adapter = NvdHttpAdapter(api_endpoint="https://nvd.test/cves/2.0")
    assert adapter._owns_client is True
    await adapter.aclose()
    assert adapter._client.is_closed
