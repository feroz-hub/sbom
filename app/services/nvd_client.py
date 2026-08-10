"""Bounded NVD HTTP client with TLS verification, rate limiting and no blind retries."""

from __future__ import annotations

import email.utils
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

import certifi
import requests

from ..settings import Settings, get_settings

MAX_CVE_IDS_PER_REQUEST = 100


class NvdProviderError(RuntimeError):
    cache_status = "failed"
    opens_circuit_immediately = False

    def __init__(self, message: str, *, http_status: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.http_status = http_status
        self.retry_after = retry_after


class NvdRateLimitedError(NvdProviderError):
    cache_status = "rate_limited"


class NvdTemporarilyUnavailableError(NvdProviderError):
    cache_status = "failed"


class NvdTimeoutError(NvdProviderError):
    cache_status = "timeout"


class NvdSslError(NvdProviderError):
    opens_circuit_immediately = True


def get_ca_bundle() -> str:
    """Resolve the verified CA bundle without host-specific hardcoding."""

    return os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or certifi.where()


def build_headers(settings: Settings | None = None) -> dict[str, str]:
    cfg = settings or get_settings()
    headers = {"User-Agent": "SBOM-Analyzer/enterprise-2.0", "Accept": "application/json"}
    if cfg.nvd_api_key.strip():
        headers["apiKey"] = cfg.nvd_api_key.strip()
    return headers


def build_nvd_params_for_cve_batch(cve_ids: list[str]) -> dict[str, str]:
    normalized = list(dict.fromkeys(str(item).strip().upper() for item in cve_ids if str(item).strip()))
    if not normalized:
        raise ValueError("At least one CVE ID is required")
    if len(normalized) > MAX_CVE_IDS_PER_REQUEST:
        raise ValueError("NVD cveIds requests are limited to 100 identifiers")
    return {"cveIds": ",".join(normalized)}


def build_nvd_params_for_cpe(cpe_name: str) -> dict[str, str]:
    value = (cpe_name or "").strip()
    if not value.lower().startswith("cpe:2.3:"):
        raise ValueError("A valid CPE 2.3 name is required")
    return {"cpeName": value}


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return max(0.0, (parsed - (now or datetime.now(UTC))).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def classify_nvd_error(exc: BaseException) -> str:
    if isinstance(exc, NvdProviderError):
        return exc.cache_status
    if isinstance(exc, requests.exceptions.SSLError):
        return "failed"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    return "failed"


class _ProcessRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self, delay: float) -> None:
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next_allowed - now)
            if sleep_for:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = now + max(0.0, delay)

    def defer(self, seconds: float | None) -> None:
        if seconds is None:
            return
        with self._lock:
            self._next_allowed = max(self._next_allowed, time.monotonic() + max(0.0, seconds))


_RATE_LIMITER = _ProcessRateLimiter()


class NvdClient:
    def __init__(self, settings: Settings | None = None, session: requests.Session | None = None) -> None:
        self.settings = settings or get_settings()
        self.session = session or requests.Session()
        self.session.verify = get_ca_bundle()

    def request_nvd(self, params: dict[str, str]) -> dict[str, Any]:
        cfg = self.settings
        delay = (
            cfg.nvd_min_delay_with_api_key_seconds
            if cfg.nvd_api_key.strip()
            else cfg.nvd_min_delay_without_api_key_seconds
        )
        _RATE_LIMITER.wait(delay)
        try:
            response = self.session.get(
                cfg.nvd_base_url,
                params=params,
                headers=build_headers(cfg),
                timeout=(cfg.nvd_connect_timeout_seconds, cfg.nvd_read_timeout_seconds),
            )
        except requests.exceptions.SSLError as exc:
            raise NvdSslError(f"NVD TLS verification failed: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            raise NvdTimeoutError(f"NVD request timed out: {exc}") from exc
        except requests.RequestException as exc:
            raise NvdProviderError(f"NVD request failed: {exc}") from exc

        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        if response.status_code in {429, 502, 503, 504}:
            _RATE_LIMITER.defer(retry_after)
        if response.status_code == 429:
            raise NvdRateLimitedError("NVD rate limit reached", http_status=429, retry_after=retry_after)
        if response.status_code in {502, 503, 504}:
            raise NvdTemporarilyUnavailableError(
                f"NVD temporarily unavailable (HTTP {response.status_code})",
                http_status=response.status_code,
                retry_after=retry_after,
            )
        if response.status_code == 404:
            return {"vulnerabilities": [], "totalResults": 0}
        try:
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise NvdProviderError(
                f"NVD returned HTTP {response.status_code}", http_status=response.status_code
            ) from exc
        except ValueError as exc:
            raise NvdProviderError("NVD returned invalid JSON", http_status=response.status_code) from exc
        return payload if isinstance(payload, dict) else {"vulnerabilities": []}


def request_nvd(params: dict[str, str], settings: Settings | None = None) -> dict[str, Any]:
    return NvdClient(settings=settings).request_nvd(params)
