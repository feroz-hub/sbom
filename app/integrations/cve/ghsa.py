"""
GHSA (GitHub Security Advisories) GraphQL source client.

GHSA holds the best human-readable prose: ``summary``, ``description``,
high-level severity bucket. We also pull CWE titles (GHSA returns named
CWEs whereas OSV returns IDs only) and fix versions per package.

Auth: GitHub Personal Access Token via ``github_token`` setting. No token →
source is treated as ``DISABLED`` (graceful no-op; aggregator records
``is_partial=True`` only when an *enabled* source fails).

Rate limit: 5,000 req/hr. We do not pace internally — the cache TTL plus
the circuit breaker keep us well under that ceiling in practice.
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

log = logging.getLogger("sbom.integrations.cve.ghsa")

_GRAPHQL_URL = "https://api.github.com/graphql"

_QUERY = """
query($id: String!, $type: SecurityAdvisoryIdentifierType!) {
  securityAdvisories(first: 1, identifier: {type: $type, value: $id}) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cwes(first: 10) { nodes { cweId name } }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 25) {
        nodes {
          package { ecosystem name }
          firstPatchedVersion { identifier }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""


class GhsaClient:
    """Async GHSA GraphQL client."""

    name = "ghsa"
    accepted_kinds: ClassVar[frozenset[IdKind]] = frozenset({IdKind.CVE, IdKind.GHSA})

    def __init__(self) -> None:
        s = get_settings()
        self._token = (s.github_token or "").strip()
        self._connect_timeout = s.cve_http_connect_timeout
        self._read_timeout = s.cve_http_read_timeout
        self._retries = s.cve_http_retries
        self._breaker = CircuitBreaker(
            threshold=s.cve_circuit_breaker_threshold,
            reset_seconds=s.cve_circuit_breaker_reset_seconds,
        )

    async def fetch(self, cve_id: str) -> FetchResult:
        if not self._token:
            return FetchResult(source=self.name, outcome=FetchOutcome.DISABLED)
        if not self._breaker.allow():
            return FetchResult(source=self.name, outcome=FetchOutcome.CIRCUIT_OPEN)

        # GHSA's GraphQL accepts the identifier under one of several enum
        # types; route based on input shape so the same client handles
        # CVE-* and GHSA-* call sites uniformly.
        ident_type = "GHSA" if cve_id.upper().startswith("GHSA-") else "CVE"

        timeout = httpx.Timeout(connect=self._connect_timeout, read=self._read_timeout, write=5.0, pool=5.0)
        client = get_async_http_client()
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "sbom-analyzer-cve-modal",
        }
        body = {"query": _QUERY, "variables": {"id": cve_id, "type": ident_type}}

        t0 = time.perf_counter()
        last_exc: BaseException | None = None
        for attempt in range(self._retries + 1):
            try:
                resp = await client.post(_GRAPHQL_URL, json=body, headers=headers, timeout=timeout)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < self._retries:
                    continue
                break
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if resp.status_code >= 500:
                last_exc = httpx.HTTPStatusError(
                    f"ghsa {resp.status_code}", request=resp.request, response=resp
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

            errors = payload.get("errors")
            if errors:
                self._breaker.record_failure()
                return FetchResult(
                    source=self.name,
                    outcome=FetchOutcome.ERROR,
                    error=str(errors)[:200],
                    latency_ms=latency_ms,
                )

            nodes = (
                ((payload.get("data") or {}).get("securityAdvisories") or {}).get("nodes") or []
            )
            self._breaker.record_success()
            if not nodes:
                log.info("ghsa not_found", extra={"cve_id": cve_id, "latency_ms": latency_ms})
                return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND, latency_ms=latency_ms)
            data = _parse(nodes[0])
            log.info(
                "ghsa ok",
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


_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
}


def _parse(node: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(node.get("summary"), str):
        out["title"] = node["summary"].strip() or None
    if isinstance(node.get("description"), str):
        out["summary"] = node["description"].strip()
    sev = (node.get("severity") or "").strip().upper()
    if sev in _SEV_MAP:
        out["severity"] = _SEV_MAP[sev]
    out["published"] = node.get("publishedAt") or None
    out["modified"] = node.get("updatedAt") or None
    out["ghsa_id"] = node.get("ghsaId")

    aliases: list[str] = []
    for ident in node.get("identifiers") or []:
        if isinstance(ident, dict) and isinstance(ident.get("value"), str):
            aliases.append(ident["value"].strip())
    if aliases:
        out["aliases"] = aliases

    cwe_ids: list[str] = []
    cwe_titles: dict[str, str] = {}
    cwe_block = node.get("cwes") or {}
    for c in (cwe_block.get("nodes") if isinstance(cwe_block, dict) else None) or []:
        if isinstance(c, dict) and isinstance(c.get("cweId"), str):
            cid = c["cweId"].strip().upper()
            cwe_ids.append(cid)
            if isinstance(c.get("name"), str):
                cwe_titles[cid] = c["name"].strip()
    if cwe_ids:
        out["cwe_ids"] = cwe_ids
    if cwe_titles:
        out["cwe_titles"] = cwe_titles

    fix_versions: list[dict[str, Any]] = []
    vulns_block = node.get("vulnerabilities") or {}
    for v in (vulns_block.get("nodes") if isinstance(vulns_block, dict) else None) or []:
        if not isinstance(v, dict):
            continue
        pkg = v.get("package") or {}
        eco = pkg.get("ecosystem") if isinstance(pkg, dict) else None
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not (eco and name):
            continue
        first_patched = v.get("firstPatchedVersion") or {}
        fixed_in = (
            first_patched.get("identifier") if isinstance(first_patched, dict) else None
        )
        fix_versions.append(
            {
                "ecosystem": str(eco),
                "package": str(name),
                "fixed_in": fixed_in,
                "introduced_in": None,
                "range": v.get("vulnerableVersionRange"),
            }
        )
    out["fix_versions"] = fix_versions

    references: list[dict[str, str]] = []
    for ref in node.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            references.append({"label": "GHSA", "url": ref["url"], "type": "advisory"})
    out["references"] = references
    return out
