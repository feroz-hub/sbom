"""
OSV (osv.dev) source client.

OSV is the preferred source for ecosystem-aware fix versions. The endpoint
``GET https://api.osv.dev/v1/vulns/{id}`` returns a single OSV vuln record;
``id`` accepts both ``CVE-YYYY-NNNN`` and ``GHSA-...`` aliases. Auth: none.

We extract:
  * ``summary``        — OSV ``summary`` (short)
  * ``details``        — OSV ``details`` (long-form prose, GitHub-flavored markdown)
  * ``aliases``        — list of all known IDs (GHSA, CVE, etc.)
  * ``cwe_ids``        — pulled from ``database_specific.cwe_ids`` when present
  * ``severity``       — OSV ``severity[]`` for CVSS vector / score (heterogenous)
  * ``fix_versions``   — flattened from ``affected[].ranges[]`` (ECOSYSTEM ranges only)
  * ``references``     — OSV ``references[]``
  * ``published``      — ISO datetime
  * ``modified``       — ISO datetime
"""

from __future__ import annotations

import logging
import time
from typing import Any, ClassVar

import httpx

from ...http_client import get_async_http_client
from ...settings import get_settings
from .base import CircuitBreaker, FetchOutcome, FetchResult
from .identifiers import IdKind

log = logging.getLogger("sbom.integrations.cve.osv")

_OSV_URL = "https://api.osv.dev/v1/vulns/{id}"


class OsvClient:
    """Async OSV client. Single instance per process; safe to share."""

    name = "osv"
    accepted_kinds: ClassVar[frozenset[IdKind]] = frozenset(
        {
            IdKind.CVE,
            IdKind.GHSA,
            IdKind.PYSEC,
            IdKind.RUSTSEC,
            IdKind.GO,
            IdKind.OSV_GENERIC,
        }
    )

    def __init__(self) -> None:
        s = get_settings()
        self._connect_timeout = s.cve_http_connect_timeout
        self._read_timeout = s.cve_http_read_timeout
        self._retries = s.cve_http_retries
        self._breaker = CircuitBreaker(
            threshold=s.cve_circuit_breaker_threshold,
            reset_seconds=s.cve_circuit_breaker_reset_seconds,
        )

    async def fetch(self, cve_id: str) -> FetchResult:
        if not self._breaker.allow():
            return FetchResult(source=self.name, outcome=FetchOutcome.CIRCUIT_OPEN)

        url = _OSV_URL.format(id=cve_id)
        timeout = httpx.Timeout(connect=self._connect_timeout, read=self._read_timeout, write=5.0, pool=5.0)
        client = get_async_http_client()

        t0 = time.perf_counter()
        last_exc: BaseException | None = None
        for attempt in range(self._retries + 1):
            try:
                resp = await client.get(url, timeout=timeout)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < self._retries:
                    continue
                break
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 404:
                self._breaker.record_success()
                log.info("osv 404", extra={"cve_id": cve_id, "latency_ms": latency_ms})
                return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND, latency_ms=latency_ms)
            if resp.status_code >= 500:
                last_exc = httpx.HTTPStatusError(
                    f"osv {resp.status_code}", request=resp.request, response=resp
                )
                if attempt < self._retries:
                    continue
                break
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
            self._breaker.record_success()
            data = _parse(payload)
            log.info(
                "osv ok",
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


def _parse(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract aggregator-friendly fields from an OSV vuln record."""
    out: dict[str, Any] = {}
    if isinstance(payload.get("summary"), str):
        out["summary"] = payload["summary"].strip()
    if isinstance(payload.get("details"), str):
        out["details"] = payload["details"].strip()
    aliases = payload.get("aliases") or []
    if isinstance(aliases, list):
        out["aliases"] = [str(a).strip() for a in aliases if isinstance(a, str)]
    out["published"] = payload.get("published") or None
    out["modified"] = payload.get("modified") or None

    db_specific = payload.get("database_specific") or {}
    cwe_ids = db_specific.get("cwe_ids") if isinstance(db_specific, dict) else None
    if isinstance(cwe_ids, list):
        out["cwe_ids"] = [str(c).strip().upper() for c in cwe_ids if isinstance(c, str)]
    elif isinstance(db_specific, dict) and isinstance(db_specific.get("severity"), str):
        # GHSA-style severity hint pulled by OSV (e.g. "MODERATE", "HIGH")
        out["severity_hint"] = db_specific["severity"].strip().lower()

    severity = payload.get("severity") or []
    if isinstance(severity, list):
        for sev in severity:
            if not isinstance(sev, dict):
                continue
            sev_type = (sev.get("type") or "").upper()
            score = sev.get("score")
            if sev_type == "CVSS_V3" and isinstance(score, str):
                out["cvss_v3_vector"] = score
            elif sev_type == "CVSS_V4" and isinstance(score, str):
                out["cvss_v4_vector"] = score

    fix_versions: list[dict[str, Any]] = []
    affected = payload.get("affected") or []
    if isinstance(affected, list):
        for aff in affected:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            ecosystem = pkg.get("ecosystem") if isinstance(pkg, dict) else None
            name = pkg.get("name") if isinstance(pkg, dict) else None
            if not (ecosystem and name):
                continue
            ranges = aff.get("ranges") or []
            if not isinstance(ranges, list):
                continue
            for rng in ranges:
                if not isinstance(rng, dict):
                    continue
                if (rng.get("type") or "").upper() not in {"ECOSYSTEM", "SEMVER"}:
                    continue
                introduced: str | None = None
                fixed: str | None = None
                events = rng.get("events") or []
                if isinstance(events, list):
                    for ev in events:
                        if not isinstance(ev, dict):
                            continue
                        if ev.get("introduced") is not None:
                            introduced = str(ev["introduced"])
                        if ev.get("fixed") is not None:
                            fixed = str(ev["fixed"])
                fix_versions.append(
                    {
                        "ecosystem": str(ecosystem),
                        "package": str(name),
                        "introduced_in": introduced,
                        "fixed_in": fixed,
                        "range": None,
                    }
                )
    out["fix_versions"] = fix_versions

    references: list[dict[str, str]] = []
    refs = payload.get("references") or []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if not isinstance(url, str):
                continue
            ref_type = (ref.get("type") or "WEB").upper()
            type_map = {
                "ADVISORY": "advisory",
                "FIX": "fix",
                "EVIDENCE": "exploit",
                "REPORT": "report",
                "PACKAGE": "web",
                "ARTICLE": "web",
                "WEB": "web",
            }
            references.append({"label": ref_type.title(), "url": url, "type": type_map.get(ref_type, "web")})
    out["references"] = references
    return out
