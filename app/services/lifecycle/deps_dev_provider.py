"""deps.dev lifecycle metadata provider."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version

from .provider_base import LifecycleProvider
from .types import DEPRECATED, LOW, MEDIUM, UNKNOWN, LifecycleResult, NormalizedComponent, unknown_result

DEPS_DEV_SYSTEMS = {
    "npm": "NPM",
    "pypi": "PYPI",
    "maven": "MAVEN",
    "go": "GO",
    "nuget": "NUGET",
    "cargo": "CARGO",
}


class DepsDevProvider(LifecycleProvider):
    """Query deps.dev for package/version metadata and advisory hints."""

    name = "deps.dev"

    def __init__(
        self,
        *,
        http_get: Callable[[str], Any] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._http_get = http_get
        self._timeout_seconds = timeout_seconds

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        system = DEPS_DEV_SYSTEMS.get(component.ecosystem)
        if not system or not component.normalized_name:
            return unknown_result(component, self.name)

        package_url = (
            f"https://api.deps.dev/v3/systems/{system}/packages/{quote(component.normalized_name, safe='')}"
        )
        package_payload = self._get_json(package_url)
        if not isinstance(package_payload, dict):
            return unknown_result(component, self.name)

        latest = _latest_version(package_payload)
        version_payload: dict[str, Any] = {}
        if component.normalized_version:
            version_url = (
                f"{package_url}/versions/{quote(component.normalized_version, safe='')}"
            )
            fetched_version = self._get_json(version_url)
            if isinstance(fetched_version, dict):
                version_payload = fetched_version

        deprecation = _deprecation_signal(package_payload, version_payload)
        advisories = _advisories(package_payload, version_payload)
        recommended = latest if _is_newer(latest, component.normalized_version) else None

        if deprecation:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=DEPRECATED,
                deprecated=True,
                maintenance_status="Deprecated by deps.dev metadata",
                latest_version=latest,
                latest_supported_version=latest,
                recommended_version=recommended,
                recommendation=(
                    f"{deprecation} Upgrade to {latest} after compatibility testing."
                    if recommended
                    else deprecation
                ),
                source_name=self.name,
                source_url=f"https://deps.dev/{system}/{'p/' if system != 'GO' else ''}{component.normalized_name}",
                evidence={
                    "package": _compact(package_payload),
                    "version": _compact(version_payload),
                    "deprecation": deprecation,
                    "advisory_count": len(advisories),
                },
                confidence=MEDIUM,
                vulnerability_count=len(advisories) if advisories else None,
            ).canonicalized()

        recommendation = None
        if advisories and recommended:
            recommendation = f"deps.dev reports {len(advisories)} advisories; review upgrade to {latest}."
        elif recommended:
            recommendation = f"Review upgrade to latest deps.dev version {latest}."

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=UNKNOWN,
            latest_version=latest,
            latest_supported_version=latest,
            recommended_version=recommended,
            recommendation=recommendation,
            source_name=self.name,
            source_url=f"https://deps.dev/{system}/{component.normalized_name}",
            evidence={
                "package": _compact(package_payload),
                "version": _compact(version_payload),
                "advisory_count": len(advisories),
                "advisories": advisories[:25],
            },
            confidence=LOW,
            vulnerability_count=len(advisories) if advisories else None,
        ).canonicalized()

    def _get_json(self, url: str) -> Any | None:
        try:
            if self._http_get is not None:
                return self._http_get(url)
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=True) as client:
                response = client.get(url)
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            return None


def _latest_version(payload: dict[str, Any]) -> str | None:
    versions = payload.get("versions")
    if not isinstance(versions, list):
        return None
    values = [str(row.get("versionKey", {}).get("version") or row.get("version") or "") for row in versions if isinstance(row, dict)]
    values = [value for value in values if value]
    if not values:
        return None
    try:
        return str(max((Version(value), value) for value in values)[1])
    except InvalidVersion:
        return values[-1]


def _deprecation_signal(*payloads: dict[str, Any]) -> str | None:
    for payload in payloads:
        for key in ("deprecated", "isDeprecated", "deprecation", "yanked"):
            value = payload.get(key)
            if value:
                return str(value if not isinstance(value, bool) else f"{key}=true")
    return None


def _advisories(*payloads: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for payload in payloads:
        value = payload.get("advisoryKeys") or payload.get("advisories") or []
        if isinstance(value, list):
            records.extend([row for row in value if isinstance(row, dict)])
    return records


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload.get(key) for key in ("versionKey", "isDefault", "licenses", "links", "publishedAt") if key in payload}


def _is_newer(candidate: str | None, current: str | None) -> bool:
    if not candidate or not current:
        return False
    try:
        return Version(str(candidate)) > Version(str(current))
    except InvalidVersion:
        return str(candidate) != str(current)


__all__ = ["DepsDevProvider"]
