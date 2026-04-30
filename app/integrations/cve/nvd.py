"""
NVD source client (CVE 2.0 API).

NVD is the authoritative source for CVSS v3.1 / v4.0 vectors and CWE IDs.
We use it as a complement to OSV / GHSA, not the primary, because the
unauthenticated rate limit is harsh (5 req / 30s) and OSV / GHSA cover the
common case faster.

Auth: optional ``nvd_api_key`` setting. With the key the limit is 50/30s.

Throttle: a single asyncio.Lock + monotonic timestamp ensures the
configured min spacing between calls is honoured even under fan-out load.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, ClassVar

import httpx

from ...http_client import get_async_http_client
from ...settings import get_settings
from .base import CircuitBreaker, FetchOutcome, FetchResult
from .identifiers import IdKind

log = logging.getLogger("sbom.integrations.cve.nvd")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    """Async NVD client with explicit per-process throttle."""

    name = "nvd"
    accepted_kinds: ClassVar[frozenset[IdKind]] = frozenset({IdKind.CVE})

    def __init__(self) -> None:
        s = get_settings()
        self._api_key = (s.nvd_api_key or "").strip()
        self._connect_timeout = s.cve_http_connect_timeout
        self._read_timeout = s.cve_http_read_timeout
        self._retries = s.cve_http_retries
        self._breaker = CircuitBreaker(
            threshold=s.cve_circuit_breaker_threshold,
            reset_seconds=s.cve_circuit_breaker_reset_seconds,
        )
        self._throttle_seconds = (
            s.cve_nvd_auth_throttle_seconds if self._api_key else s.cve_nvd_unauth_throttle_seconds
        )
        self._lock = asyncio.Lock()
        self._last_call_at: float = 0.0

    async def _throttle(self) -> None:
        async with self._lock:
            elapsed = time.monotonic() - self._last_call_at
            if elapsed < self._throttle_seconds:
                await asyncio.sleep(self._throttle_seconds - elapsed)
            self._last_call_at = time.monotonic()

    async def fetch(self, cve_id: str) -> FetchResult:
        # NVD's CVE 2.0 API only accepts canonical CVE-* identifiers. The
        # aggregator filters by ``accepted_kinds`` before calling .fetch(),
        # so callers should never reach here with a non-CVE id. Keeping a
        # defensive guard is cheap and protects against direct-call misuse.
        if not cve_id.upper().startswith("CVE-"):
            return FetchResult(source=self.name, outcome=FetchOutcome.DISABLED)
        if not self._breaker.allow():
            return FetchResult(source=self.name, outcome=FetchOutcome.CIRCUIT_OPEN)
        await self._throttle()

        timeout = httpx.Timeout(connect=self._connect_timeout, read=self._read_timeout, write=5.0, pool=5.0)
        client = get_async_http_client()
        headers = {"User-Agent": "sbom-analyzer-cve-modal"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        t0 = time.perf_counter()
        last_exc: BaseException | None = None
        for attempt in range(self._retries + 1):
            try:
                resp = await client.get(
                    _NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < self._retries:
                    continue
                break
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code >= 500:
                last_exc = httpx.HTTPStatusError(
                    f"nvd {resp.status_code}", request=resp.request, response=resp
                )
                if attempt < self._retries:
                    continue
                break
            if resp.status_code == 429:
                # Throttle exceeded — flag failure and move on.
                self._breaker.record_failure()
                return FetchResult(
                    source=self.name,
                    outcome=FetchOutcome.ERROR,
                    error="rate-limited",
                    latency_ms=latency_ms,
                )
            if resp.status_code >= 400:
                self._breaker.record_failure()
                return FetchResult(
                    source=self.name,
                    outcome=FetchOutcome.ERROR,
                    error=f"http {resp.status_code}",
                    latency_ms=latency_ms,
                )
            try:
                payload = resp.json()
            except ValueError as exc:
                self._breaker.record_failure()
                return FetchResult(source=self.name, outcome=FetchOutcome.ERROR, error=str(exc), latency_ms=latency_ms)

            vulnerabilities = payload.get("vulnerabilities") or []
            if not vulnerabilities:
                self._breaker.record_success()
                log.info("nvd not_found", extra={"cve_id": cve_id, "latency_ms": latency_ms})
                return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND, latency_ms=latency_ms)

            cve_block = vulnerabilities[0].get("cve") or {}
            data = _parse(cve_block)
            self._breaker.record_success()
            log.info(
                "nvd ok",
                extra={"cve_id": cve_id, "latency_ms": latency_ms, "status_code": resp.status_code},
            )
            return FetchResult(source=self.name, outcome=FetchOutcome.OK, data=data, latency_ms=latency_ms)

        self._breaker.record_failure()
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return FetchResult(
            source=self.name,
            outcome=FetchOutcome.ERROR,
            error=str(last_exc) if last_exc else "unknown",
            latency_ms=latency_ms,
        )


def _parse(cve: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    descriptions = cve.get("descriptions") or []
    summary = ""
    for d in descriptions:
        if isinstance(d, dict) and (d.get("lang") == "en") and isinstance(d.get("value"), str):
            summary = d["value"].strip()
            break
    if summary:
        out["summary"] = summary

    out["published"] = cve.get("published") or None
    out["modified"] = cve.get("lastModified") or None

    metrics = cve.get("metrics") or {}
    v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if v3:
        m = v3[0].get("cvssData") or {}
        if isinstance(m.get("baseScore"), (int, float)):
            out["cvss_v3_score"] = float(m["baseScore"])
        if isinstance(m.get("vectorString"), str):
            out["cvss_v3_vector"] = m["vectorString"]
        if isinstance(m.get("attackVector"), str):
            out["attack_vector"] = m["attackVector"]
        if isinstance(m.get("attackComplexity"), str):
            out["attack_complexity"] = m["attackComplexity"]
        if isinstance(m.get("privilegesRequired"), str):
            out["privileges_required"] = m["privilegesRequired"]
        if isinstance(m.get("userInteraction"), str):
            out["user_interaction"] = m["userInteraction"]

    v4 = metrics.get("cvssMetricV40") or []
    if v4:
        m = v4[0].get("cvssData") or {}
        if isinstance(m.get("baseScore"), (int, float)):
            out["cvss_v4_score"] = float(m["baseScore"])
        if isinstance(m.get("vectorString"), str):
            out["cvss_v4_vector"] = m["vectorString"]

    cwe_ids: list[str] = []
    weaknesses = cve.get("weaknesses") or []
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in w.get("description") or []:
            if isinstance(d, dict) and isinstance(d.get("value"), str):
                v = d["value"].strip().upper()
                if v.startswith("CWE-"):
                    cwe_ids.append(v)
    if cwe_ids:
        out["cwe_ids"] = sorted(set(cwe_ids))

    references: list[dict[str, str]] = []
    for ref in cve.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            tags = ref.get("tags") or []
            type_label = "web"
            if isinstance(tags, list):
                if any(t == "Patch" for t in tags):
                    type_label = "patch"
                elif any(t == "Exploit" for t in tags):
                    type_label = "exploit"
                elif any(t in {"Vendor Advisory", "Third Party Advisory"} for t in tags):
                    type_label = "advisory"
            references.append({"label": "NVD", "url": ref["url"], "type": type_label})
    out["references"] = references
    return out
