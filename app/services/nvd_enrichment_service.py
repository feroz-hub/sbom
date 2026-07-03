"""Cache-first, budgeted NVD enrichment orchestration."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..settings import Settings, get_settings
from .nvd_cache_service import NvdCacheService
from .nvd_client import (
    NvdClient,
    NvdProviderError,
    build_nvd_params_for_cpe,
    build_nvd_params_for_cve_batch,
)

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TRUSTED_CPE_SOURCES = frozenset({"sbom_provided", "official_nvd_cpe", "manual_verified", "trusted_mapping"})
BLOCKED_CPE_TOKENS = frozenset(
    {"valid-lifecycle", "test", "sample", "example", "generic", "internal", "unknown", "placeholder"}
)


@dataclass(frozen=True)
class NvdIdentifiers:
    cve_ids: list[str]
    trusted_cpes: list[tuple[str, dict[str, Any]]]
    skipped_generated_cpe: int = 0
    skipped_untrusted_cpe: int = 0


class ScanCircuitBreaker:
    def __init__(self, threshold: int) -> None:
        self.threshold = max(1, threshold)
        self.failures = 0
        self.open = False
        self._logged = False

    def record_failure(self, exc: NvdProviderError) -> None:
        self.failures += 1
        if exc.opens_circuit_immediately or self.failures >= self.threshold:
            self.open = True
            if not self._logged:
                log.warning("NVD circuit breaker opened; skipping remaining NVD lookups for this scan")
                self._logged = True


def is_valid_cpe23(value: str | None) -> bool:
    if not value or not value.lower().startswith("cpe:2.3:"):
        return False
    return len(value.split(":")) == 13


def is_trusted_cpe(cpe: str, source: str | None) -> bool:
    if not is_valid_cpe23(cpe) or (source or "").strip().lower() not in TRUSTED_CPE_SOURCES:
        return False
    lowered = cpe.lower()
    return not any(token in lowered for token in BLOCKED_CPE_TOKENS)


def _iter_cve_values(vulnerability: dict[str, Any]) -> Iterable[str]:
    for key in ("vuln_id", "cve_id", "cve", "id"):
        value = vulnerability.get(key)
        if isinstance(value, str):
            yield value
    aliases = vulnerability.get("aliases") or []
    if isinstance(aliases, str):
        aliases = [aliases]
    if isinstance(aliases, list):
        yield from (item for item in aliases if isinstance(item, str))


def collect_nvd_identifiers(
    components: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> NvdIdentifiers:
    cve_ids: list[str] = []
    seen_cves: set[str] = set()
    for vulnerability in vulnerabilities or []:
        for raw in _iter_cve_values(vulnerability):
            normalized = raw.strip().upper()
            if CVE_RE.fullmatch(normalized) and normalized not in seen_cves:
                seen_cves.add(normalized)
                cve_ids.append(normalized)

    cpes: list[tuple[str, dict[str, Any]]] = []
    seen_cpes: set[str] = set()
    skipped_generated = 0
    skipped_untrusted = 0
    for component in components:
        cpe = str(component.get("cpe") or "").strip()
        if not cpe:
            continue
        source = str(component.get("cpe_source") or "unknown").strip().lower()
        if source in {"generated_fallback", "inferred_from_purl", "test_fixture"}:
            skipped_generated += 1
            log.debug("Skipping NVD lookup for generated/untrusted CPE")
            continue
        if not is_trusted_cpe(cpe, source):
            skipped_untrusted += 1
            log.debug("Skipping NVD lookup for generated/untrusted CPE")
            continue
        if cpe not in seen_cpes:
            seen_cpes.add(cpe)
            cpes.append((cpe, component))
    return NvdIdentifiers(cve_ids, cpes, skipped_generated, skipped_untrusted)


def _records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item["cve"]
        for item in payload.get("vulnerabilities", []) or []
        if isinstance(item, dict) and isinstance(item.get("cve"), dict)
    ]


class NvdEnrichmentService:
    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        client: NvdClient | None = None,
        cache: NvdCacheService | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.client = client or NvdClient(self.settings)
        self.cache = cache or NvdCacheService(db, self.settings)

    def enrich(
        self,
        components: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        identifiers = collect_nvd_identifiers(components, vulnerabilities)
        summary: dict[str, Any] = {
            "provider": "NVD",
            "status": "success",
            "total_identifiers": len(identifiers.cve_ids) + len(identifiers.trusted_cpes),
            "cache_hits": 0,
            "cache_misses": 0,
            "queried": 0,
            "skipped_generated_cpe": identifiers.skipped_generated_cpe,
            "skipped_untrusted_cpe": identifiers.skipped_untrusted_cpe,
            "failures": 0,
            "circuit_breaker_open": False,
            "error_message": None,
        }
        if not self.settings.nvd_enabled:
            summary["status"] = "disabled"
            return {"records": [], "provider_status": summary}
        if not summary["total_identifiers"]:
            summary["status"] = "skipped"
            return {"records": [], "provider_status": summary}

        output: list[dict[str, Any]] = []
        breaker = ScanCircuitBreaker(self.settings.nvd_failure_threshold)
        vulnerability_by_cve: dict[str, dict[str, Any]] = {}
        for vulnerability in vulnerabilities or []:
            for value in _iter_cve_values(vulnerability):
                normalized = value.strip().upper()
                if CVE_RE.fullmatch(normalized):
                    vulnerability_by_cve.setdefault(normalized, vulnerability)
        missing_cves: list[str] = []
        for cve_id in identifiers.cve_ids:
            cached = self.cache.get_valid_cache(cve_id, "CVE_ID")
            if cached is None:
                summary["cache_misses"] += 1
                missing_cves.append(cve_id)
            else:
                summary["cache_hits"] += 1
                if cached.status == "success" and isinstance(cached.response_json, dict):
                    output.append(
                        {
                            "raw": cached.response_json,
                            "identifier": cve_id,
                            "component": vulnerability_by_cve.get(cve_id, {}),
                        }
                    )
                elif cached.status not in {"success", "no_result"}:
                    summary["status"] = "degraded"
                    summary["error_message"] = cached.error_message

        batch_size = min(100, max(1, self.settings.nvd_cve_batch_size))
        batches = [missing_cves[i : i + batch_size] for i in range(0, len(missing_cves), batch_size)]
        batches = batches[: self.settings.nvd_max_cve_batches_per_scan]
        for batch in batches:
            if breaker.open:
                break
            try:
                payload = self.client.request_nvd(build_nvd_params_for_cve_batch(batch))
                summary["queried"] += 1
                returned = {str(raw.get("id") or "").upper(): raw for raw in _records(payload)}
                for cve_id in batch:
                    raw = returned.get(cve_id)
                    if raw is None:
                        self.cache.save_no_result(cve_id, "CVE_ID")
                    else:
                        self.cache.save_success(cve_id, "CVE_ID", raw)
                        output.append(
                            {
                                "raw": raw,
                                "identifier": cve_id,
                                "component": vulnerability_by_cve.get(cve_id, {}),
                            }
                        )
            except NvdProviderError as exc:
                summary["failures"] += 1
                summary["error_message"] = str(exc)
                for cve_id in batch:
                    self.cache.save_failure(cve_id, "CVE_ID", exc.cache_status, exc.http_status, str(exc))
                breaker.record_failure(exc)

        cpe_candidates: list[tuple[str, dict[str, Any]]] = []
        for cpe, component in identifiers.trusted_cpes:
            cached = self.cache.get_valid_cache(cpe, "CPE_NAME")
            if cached is None:
                summary["cache_misses"] += 1
                cpe_candidates.append((cpe, component))
            else:
                summary["cache_hits"] += 1
                if cached.status == "success" and isinstance(cached.response_json, list):
                    output.extend(
                        {"raw": raw, "identifier": cpe, "component": component}
                        for raw in cached.response_json
                        if isinstance(raw, dict)
                    )
                elif cached.status not in {"success", "no_result"}:
                    summary["status"] = "degraded"
                    summary["error_message"] = cached.error_message

        for cpe, component in cpe_candidates[: self.settings.nvd_max_cpe_lookups_per_scan]:
            if breaker.open:
                break
            try:
                payload = self.client.request_nvd(build_nvd_params_for_cpe(cpe))
                summary["queried"] += 1
                returned = _records(payload)
                if returned:
                    self.cache.save_success(cpe, "CPE_NAME", returned)
                    output.extend({"raw": raw, "identifier": cpe, "component": component} for raw in returned)
                else:
                    self.cache.save_no_result(cpe, "CPE_NAME")
            except NvdProviderError as exc:
                summary["failures"] += 1
                summary["error_message"] = str(exc)
                self.cache.save_failure(cpe, "CPE_NAME", exc.cache_status, exc.http_status, str(exc))
                breaker.record_failure(exc)

        summary["circuit_breaker_open"] = breaker.open
        if summary["failures"] or breaker.open:
            summary["status"] = "degraded"
        self.db.commit()
        return {"records": output, "provider_status": summary}
