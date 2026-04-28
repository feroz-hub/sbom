"""``NvdRemotePort`` implementation backed by httpx + tenacity.

Behaviour (matches Phase 1 design §8):
  * httpx.AsyncClient, configurable timeout (default 60 s).
  * Sequential pagination (concurrency = 1) — see Phase 0 §G bug-fix g.
  * Inter-request sleep depending on API key presence:
      no key  -> ~6.5 s   (5 req / 30 s public limit)
      w/ key  -> ~0.7 s   (50 req / 30 s authenticated limit)
  * Tenacity retry on transient 429/503/timeouts: max 5 attempts,
    exponential-jitter wait, ``Retry-After`` honoured for 429s.
  * 120-day window upper bound is enforced by ``MirrorWindow``
    ``__post_init__``; this adapter only guards page count to avoid
    runaway pagination.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from ..domain.mappers import map_batch
from ..domain.models import CveBatch, MirrorWindow

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS: float = 60.0
DEFAULT_USER_AGENT: str = "SBOM-Analyzer-NvdMirror/2.0"

# NVD's published rate limits with safety margin.
SLEEP_WITH_KEY_SECONDS: float = 0.7
SLEEP_WITHOUT_KEY_SECONDS: float = 6.5

# Tenacity retry tuning.
RETRY_MAX_ATTEMPTS: int = 5
RETRY_INITIAL_WAIT: float = 2.0
RETRY_MAX_WAIT: float = 60.0

# Per-window page cap. NVD's totalResults can spike during full mirrors;
# 120 days * a few thousand CVEs / 2000 page_size = at most 50 pages
# under realistic volume. 200 leaves headroom for bursts and prevents
# infinite-loop bugs from stalling a window forever.
DEFAULT_MAX_PAGES_PER_WINDOW: int = 200


class _RetryableHttpError(Exception):
    """Internal sentinel — wraps 429/503 so tenacity's retry sees it."""

    def __init__(self, status_code: int, retry_after: float | None = None) -> None:
        super().__init__(f"NVD HTTP {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after


_RETRYABLE_HTTPX_EXCS = (
    httpx.TimeoutException,
    httpx.RemoteProtocolError,
    httpx.ConnectError,
    httpx.ReadError,
)


class NvdHttpAdapter:
    """``NvdRemotePort`` backed by the live NVD REST 2.0 API."""

    def __init__(
        self,
        *,
        api_endpoint: str,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        max_pages_per_window: int = DEFAULT_MAX_PAGES_PER_WINDOW,
    ) -> None:
        self._endpoint = api_endpoint
        self._api_key = (api_key or "").strip() or None
        self._timeout_seconds = timeout_seconds
        self._user_agent = user_agent
        self._max_pages_per_window = max_pages_per_window

        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            headers={"User-Agent": user_agent},
        )

    # ---- public API (NvdRemotePort) -------------------------------------

    async def fetch_window(
        self, window: MirrorWindow, *, page_size: int
    ) -> AsyncIterator[CveBatch]:
        """Yields one ``CveBatch`` per paginated NVD response page.

        NOTE on type: ``async def`` with ``yield`` returns
        ``AsyncGenerator``, which is a subtype of ``AsyncIterator`` —
        satisfies the port contract.
        """
        # Belt-and-braces: MirrorWindow.__post_init__ already enforces
        # the 119-day ceiling; this guard makes intent explicit at the
        # adapter boundary.
        if not isinstance(window, MirrorWindow):  # pragma: no cover (type guard)
            raise TypeError(f"window must be MirrorWindow, got {type(window).__name__}")

        sleep_seconds = self._inter_request_sleep_seconds()
        start_index = 0
        page_count = 0

        while True:
            params = self._build_params(window, page_size=page_size, start_index=start_index)
            response_json = await self._do_get(params)
            batch = map_batch(response_json)
            yield batch

            page_count += 1
            consumed = batch.start_index + len(batch.records)
            if consumed >= batch.total_results:
                return
            if len(batch.records) == 0:
                # Defensive: empty page but not at end. Avoid infinite loop.
                log.warning(
                    "nvd_remote_empty_page_short_circuit",
                    extra={"start_index": start_index, "total": batch.total_results},
                )
                return
            if page_count >= self._max_pages_per_window:
                log.warning(
                    "nvd_remote_max_pages_reached",
                    extra={
                        "page_count": page_count,
                        "consumed": consumed,
                        "total": batch.total_results,
                    },
                )
                return

            start_index = consumed
            if sleep_seconds > 0:
                await asyncio.sleep(sleep_seconds)

    async def aclose(self) -> None:
        """Close the underlying httpx client if we own it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> NvdHttpAdapter:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # ---- internals ------------------------------------------------------

    def _build_params(
        self, window: MirrorWindow, *, page_size: int, start_index: int
    ) -> dict[str, Any]:
        return {
            "lastModStartDate": _format_iso(window.start),
            "lastModEndDate": _format_iso(window.end),
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }

    def _inter_request_sleep_seconds(self) -> float:
        return SLEEP_WITH_KEY_SECONDS if self._api_key else SLEEP_WITHOUT_KEY_SECONDS

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": self._user_agent}
        if self._api_key:
            h["apiKey"] = self._api_key
        return h

    async def _do_get(self, params: dict[str, Any]) -> dict[str, Any]:
        """One GET, retried under tenacity on transient errors."""
        try:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception_type(
                    (_RetryableHttpError, *_RETRYABLE_HTTPX_EXCS)
                ),
                wait=wait_exponential_jitter(
                    initial=RETRY_INITIAL_WAIT, max=RETRY_MAX_WAIT
                ),
                stop=stop_after_attempt(RETRY_MAX_ATTEMPTS),
                reraise=True,
            ):
                with attempt:
                    response = await self._client.get(
                        self._endpoint, params=params, headers=self._headers()
                    )
                    if response.status_code == 429:
                        retry_after = _retry_after_seconds(response)
                        if retry_after and retry_after > 0:
                            log.info(
                                "nvd_remote_429_sleeping",
                                extra={"retry_after": retry_after},
                            )
                            await asyncio.sleep(retry_after)
                        raise _RetryableHttpError(429, retry_after)
                    if response.status_code in {502, 503, 504}:
                        raise _RetryableHttpError(response.status_code)
                    response.raise_for_status()
                    return response.json()
        except RetryError as exc:  # pragma: no cover — reraise=True covers normal path
            raise NvdRemoteError(
                f"NVD remote exhausted retries ({RETRY_MAX_ATTEMPTS}): {exc}"
            ) from exc
        # Unreachable: tenacity will either return inside attempt or raise.
        raise NvdRemoteError("NVD remote returned no response")  # pragma: no cover


class NvdRemoteError(RuntimeError):
    """Raised when the NVD remote exhausts retries or hits a non-retryable status."""


def _format_iso(dt: Any) -> str:
    """NVD wants ISO-8601 with millisecond precision and a UTC offset."""
    # ``isoformat`` yields '+00:00'; NVD accepts that. Truncate fractional
    # microseconds to milliseconds to stay under NVD's documented format.
    iso = dt.isoformat(timespec="milliseconds")
    return iso


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
