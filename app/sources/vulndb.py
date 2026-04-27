"""VulDB / VulnDB source adapter.

The public API is form-post based (``https://vuldb.com/?api``).  We query it
with either the component CPE, when available, or a conservative
``name version`` search string.  VulDB requires an API key, so the adapter
returns a warning-only empty result when no key is configured.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import SourceResult, empty_result


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_int(value: Any, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _unix_to_iso(value: Any) -> str | None:
    text = _clean(value)
    if not text:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).replace(microsecond=0).isoformat()
        except (OverflowError, OSError, ValueError):
            return text
    return text


def _severity_from_risk(risk: Any, score: float | None) -> str:
    if isinstance(risk, dict):
        name = _clean(risk.get("name"))
    else:
        name = _clean(risk)
    sev = (name or "").upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_nested_score(vulnerability: dict[str, Any]) -> float | None:
    candidates: list[Any] = []
    for cvss_key in ("cvss4", "cvss3", "cvss2"):
        cvss = vulnerability.get(cvss_key) or {}
        if not isinstance(cvss, dict):
            continue
        for provider in ("vuldb", "nvd"):
            provider_obj = cvss.get(provider) or {}
            if isinstance(provider_obj, dict):
                candidates.extend(
                    [
                        provider_obj.get("basescore"),
                        provider_obj.get("baseScore"),
                        provider_obj.get("base_score"),
                        provider_obj.get("score"),
                    ]
                )
        candidates.extend(
            [
                cvss.get("basescore"),
                cvss.get("baseScore"),
                cvss.get("base_score"),
                cvss.get("score"),
            ]
        )
    for candidate in candidates:
        score = _safe_float(candidate)
        if score is not None:
            return score
    return None


def _extract_vector(vulnerability: dict[str, Any]) -> str | None:
    for cvss_key in ("cvss4", "cvss3", "cvss2"):
        cvss = vulnerability.get(cvss_key) or {}
        if not isinstance(cvss, dict):
            continue
        for provider in ("vuldb", "nvd"):
            provider_obj = cvss.get(provider) or {}
            if isinstance(provider_obj, dict):
                vector = _clean(provider_obj.get("vector") or provider_obj.get("vectorString"))
                if vector:
                    return vector
        vector = _clean(cvss.get("vector") or cvss.get("vectorString"))
        if vector:
            return vector
    return None


def _extract_cvss_version(vulnerability: dict[str, Any]) -> str | None:
    for cvss_key, version in (("cvss4", "4.0"), ("cvss3", "3.x"), ("cvss2", "2.0")):
        cvss = vulnerability.get(cvss_key)
        if cvss:
            return version
    return None


def _extract_cwe(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({_clean(v) for v in value if _clean(v)})
    text = _clean(value)
    if not text:
        return []
    return sorted({part.strip() for part in text.replace(";", ",").split(",") if part.strip()})


def _source_cve_id(source: Any) -> str | None:
    if not isinstance(source, dict):
        return None
    cve = source.get("cve")
    if isinstance(cve, dict):
        return _clean(cve.get("id") or cve.get("name"))
    return _clean(cve)


def _vuldb_reference(entry_id: str | None) -> str | None:
    if not entry_id:
        return None
    return f"https://vuldb.com/?id.{entry_id}"


async def _post_vulndb_form(url: str, data: dict[str, str], timeout: int) -> dict[str, Any]:
    """POST form data using the app-wide client when FastAPI lifespan is active."""
    try:
        from app.http_client import get_async_http_client

        client = get_async_http_client()
    except RuntimeError:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, data=data)
    else:
        response = await client.post(url, data=data, timeout=timeout)
    response.raise_for_status()
    return response.json()


class VulnDbSource:
    """``VulnSource`` adapter for VulDB / VulnDB search queries."""

    name: str = "VULNDB"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = (api_key or "").strip() or None

    async def query(self, components: list[dict], settings: Any) -> SourceResult:
        if not components:
            return empty_result()

        api_key = self.api_key
        key_env = getattr(settings, "vulndb_api_key_env", "VULNDB_API_KEY")
        if not api_key:
            return SourceResult(
                findings=[],
                errors=[],
                warnings=[{"source": self.name, "warning": f"Missing API key env: {key_env}"}],
            )

        base_url = getattr(settings, "vulndb_api_base_url", "https://vuldb.com/?api")
        api_version = str(getattr(settings, "vulndb_api_version", 3))
        limit = _safe_int(getattr(settings, "vulndb_limit", 5), 5, minimum=1)
        max_components = _safe_int(getattr(settings, "vulndb_max_components", 100), 100, minimum=1)
        timeout = _safe_int(getattr(settings, "vulndb_request_timeout_seconds", 30), 30, minimum=1)
        delay = float(getattr(settings, "vulndb_request_delay_seconds", 0.0) or 0.0)
        details = _as_bool(getattr(settings, "vulndb_details", False), False)

        findings: list[dict] = []
        errors: list[dict] = []

        targets = self._query_targets(components)[:max_components]
        for idx, target in enumerate(targets):
            try:
                payload = await _post_vulndb_form(
                    base_url,
                    {
                        "apikey": api_key,
                        "version": api_version,
                        "search": target["query"],
                        "limit": str(limit),
                        "details": "1" if details else "0",
                        "fields": (
                            "vulnerability_cwe,"
                            "vulnerability_cvss2_vuldb_basescore,"
                            "vulnerability_cvss2_nvd_basescore,"
                            "software_cpe"
                        ),
                    },
                    timeout,
                )
            except Exception as exc:
                errors.append(
                    {
                        "source": self.name,
                        "component": target["component_name"],
                        "query": target["query"],
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue

            request_meta = payload.get("request") if isinstance(payload, dict) else {}
            if isinstance(request_meta, dict):
                key_state = _clean(request_meta.get("apikey"))
                if key_state and key_state != "valid":
                    errors.append(
                        {
                            "source": self.name,
                            "component": target["component_name"],
                            "query": target["query"],
                            "error": f"VulDB API key is {key_state}",
                        }
                    )
                    continue

            status = str(payload.get("status", "200")) if isinstance(payload, dict) else "0"
            if status.startswith(("4", "5")):
                errors.append(
                    {
                        "source": self.name,
                        "component": target["component_name"],
                        "query": target["query"],
                        "error": f"VulDB API status {status}",
                    }
                )
                continue

            result_items = payload.get("result", []) if isinstance(payload, dict) else []
            if not isinstance(result_items, list):
                result_items = []

            for item in result_items:
                if isinstance(item, dict):
                    findings.append(self._finding_from_item(item, target))

            if delay > 0 and idx < len(targets) - 1:
                await asyncio.sleep(delay)

        return SourceResult(findings=findings, errors=errors, warnings=[])

    @staticmethod
    def _query_targets(components: list[dict]) -> list[dict[str, str | None]]:
        targets: list[dict[str, str | None]] = []
        seen: set[str] = set()
        for comp in components:
            name = _clean(comp.get("name"))
            version = _clean(comp.get("version"))
            cpe = _clean(comp.get("cpe"))
            if cpe:
                query = cpe
            elif name and version:
                query = f"{name} {version}"
            elif name:
                query = name
            else:
                continue
            dedupe_key = query.lower()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            targets.append(
                {
                    "query": query,
                    "component_name": name,
                    "component_version": version,
                    "cpe": cpe,
                }
            )
        return targets

    @staticmethod
    def _finding_from_item(item: dict[str, Any], target: dict[str, str | None]) -> dict[str, Any]:
        entry = item.get("entry") if isinstance(item.get("entry"), dict) else {}
        vulnerability = item.get("vulnerability") if isinstance(item.get("vulnerability"), dict) else {}
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        advisory = item.get("advisory") if isinstance(item.get("advisory"), dict) else {}

        entry_id = _clean(entry.get("id"))
        cve_id = _source_cve_id(source)
        vuln_id = cve_id or (f"VULDB-{entry_id}" if entry_id else "VULDB-UNKNOWN")
        aliases = [a for a in [cve_id, f"VULDB-{entry_id}" if entry_id else None] if a]

        score = _extract_nested_score(vulnerability)
        severity = _severity_from_risk(vulnerability.get("risk"), score)
        reference = _vuldb_reference(entry_id)
        references = [r for r in [reference, f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None] if r]

        return {
            "vuln_id": vuln_id,
            "aliases": aliases,
            "sources": ["VULNDB"],
            "description": _clean(entry.get("title")) or vuln_id,
            "severity": severity,
            "score": score,
            "vector": _extract_vector(vulnerability),
            "attack_vector": None,
            "cvss_version": _extract_cvss_version(vulnerability),
            "published": _unix_to_iso(advisory.get("date")),
            "references": references,
            "url": reference,
            "cwe": _extract_cwe(vulnerability.get("cwe")),
            "fixed_versions": [],
            "component_name": target.get("component_name"),
            "component_version": target.get("component_version"),
            "cpe": target.get("cpe"),
        }
