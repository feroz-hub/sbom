"""OSV provider for vulnerability-aware lifecycle recommendations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_OSV
from .types import LOW, UNKNOWN, LifecycleResult, NormalizedComponent, unknown_result

OSV_URL = "https://api.osv.dev/v1/query"

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "go": "Go",
    "cargo": "crates.io",
}


class OSVProvider(LifecycleProvider):
    name = "OSV"
    priority = PRIORITY_OSV

    def supports(self, component: NormalizedComponent) -> bool:
        return (
            component.ecosystem in OSV_ECOSYSTEMS
            and bool(component.normalized_name)
            and bool(component.normalized_version)
        )

    def __init__(
        self,
        *,
        http_post: Callable[[str, dict[str, Any]], Any] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._http_post = http_post
        self._timeout_seconds = timeout_seconds

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        ecosystem = OSV_ECOSYSTEMS.get(component.ecosystem)
        if not ecosystem or not component.normalized_name or not component.normalized_version:
            return unknown_result(component, self.name)

        payload = self._post_json(
            OSV_URL,
            {
                "version": component.normalized_version,
                "package": {"name": component.normalized_name, "ecosystem": ecosystem},
            },
        )
        if not isinstance(payload, dict):
            return unknown_result(component, self.name)

        vulns = payload.get("vulns") or []
        if not isinstance(vulns, list) or not vulns:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=UNKNOWN,
                source_name=self.name,
                source_url="https://osv.dev/",
                evidence={"vulnerability_count": 0},
                confidence=LOW,
                vulnerability_count=0,
            ).canonicalized()

        fixed_versions = _extract_fixed_versions(vulns)
        recommended = fixed_versions[0] if fixed_versions else None
        recommendation = None
        if recommended:
            recommendation = f"Upgrade to fixed version {recommended}; OSV reports {len(vulns)} vulnerabilities."
        else:
            recommendation = f"Review vulnerabilities in OSV; {len(vulns)} records matched this component."

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=UNKNOWN,
            recommended_version=recommended,
            recommendation=recommendation,
            source_name=self.name,
            source_url="https://osv.dev/",
            evidence={
                "vulnerability_count": len(vulns),
                "fixed_versions": fixed_versions,
                "vuln_ids": [vuln.get("id") for vuln in vulns if isinstance(vuln, dict)][:25],
            },
            confidence=LOW,
            vulnerability_count=len(vulns),
        ).canonicalized()

    def _post_json(self, url: str, payload: dict[str, Any]) -> Any | None:
        try:
            if self._http_post is not None:
                return self._http_post(url, payload)
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=True) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            return None


def _extract_fixed_versions(vulns: list[Any]) -> list[str]:
    fixed: list[str] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        for affected in vuln.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            for range_info in affected.get("ranges") or []:
                if not isinstance(range_info, dict):
                    continue
                for event in range_info.get("events") or []:
                    if isinstance(event, dict) and event.get("fixed") and event["fixed"] not in fixed:
                        fixed.append(str(event["fixed"]))
    return fixed


__all__ = ["OSVProvider"]
