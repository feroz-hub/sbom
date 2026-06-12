"""Lifecycle signals from package registries.

Registry providers are intentionally conservative: deprecation metadata is
treated as lifecycle evidence, but package age alone is not promoted to EOL.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version

from .provider_base import LifecycleProvider
from .types import (
    DEPRECATED,
    LOW,
    MEDIUM,
    UNKNOWN,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)


class PackageRegistryProvider(LifecycleProvider):
    name = "Package Registry"

    def __init__(
        self,
        *,
        http_get: Callable[[str], Any] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._http_get = http_get
        self._timeout_seconds = timeout_seconds

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        if not component.normalized_name:
            return unknown_result(component, self.name)
        try:
            if component.ecosystem == "npm":
                return self._lookup_npm(component)
            if component.ecosystem == "pypi":
                return self._lookup_pypi(component)
            if component.ecosystem == "nuget":
                return self._lookup_nuget(component)
            if component.ecosystem == "maven":
                return self._lookup_maven(component)
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return unknown_result(component, self.name)
        return unknown_result(component, self.name)

    def _lookup_npm(self, component: NormalizedComponent) -> LifecycleResult:
        encoded = quote(component.normalized_name, safe="")
        url = f"https://registry.npmjs.org/{encoded}"
        payload = self._get_json(url)
        if not isinstance(payload, dict):
            return unknown_result(component, "npm registry")

        latest = (payload.get("dist-tags") or {}).get("latest")
        repository_url = _repository_url(payload.get("repository"))
        versions = payload.get("versions") or {}
        version_payload = versions.get(component.normalized_version or "") if isinstance(versions, dict) else None
        deprecated_message = None
        if isinstance(version_payload, dict):
            deprecated_message = version_payload.get("deprecated")
        if not deprecated_message:
            deprecated_message = payload.get("deprecated")

        if deprecated_message:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=DEPRECATED,
                deprecated=True,
                maintenance_status="Deprecated by npm registry",
                latest_version=latest,
                latest_supported_version=latest,
                recommended_version=latest if _is_newer(latest, component.normalized_version) else None,
                recommendation=_registry_recommendation(latest, component.normalized_version, deprecated_message),
                source_name="npm registry",
                source_url=f"https://www.npmjs.com/package/{component.normalized_name}",
                evidence={
                    "deprecated": deprecated_message,
                    "dist_tags": payload.get("dist-tags"),
                    "repository_url": repository_url,
                },
                confidence=MEDIUM,
            ).canonicalized()

        return _unknown_with_latest(
            component,
            "npm registry",
            f"https://www.npmjs.com/package/{component.normalized_name}",
            latest,
            {"dist_tags": payload.get("dist-tags"), "repository_url": repository_url},
        )

    def _lookup_pypi(self, component: NormalizedComponent) -> LifecycleResult:
        encoded = quote(component.normalized_name, safe="")
        url = f"https://pypi.org/pypi/{encoded}/json"
        payload = self._get_json(url)
        if not isinstance(payload, dict):
            return unknown_result(component, "PyPI")

        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        latest = info.get("version")
        repository_url = _first_project_url(info, "Source", "Source Code", "Code", "Repository", "Homepage", "Home-page")
        releases = payload.get("releases") if isinstance(payload.get("releases"), dict) else {}
        current_files = releases.get(component.normalized_version or "") or []
        yanked = bool(current_files) and all(bool(file.get("yanked")) for file in current_files if isinstance(file, dict))
        if yanked:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=DEPRECATED,
                deprecated=True,
                maintenance_status="Release yanked on PyPI",
                latest_version=latest,
                latest_supported_version=latest,
                recommended_version=latest if _is_newer(latest, component.normalized_version) else None,
                recommendation=_registry_recommendation(latest, component.normalized_version, "Release is yanked on PyPI."),
                source_name="PyPI",
                source_url=f"https://pypi.org/project/{component.normalized_name}/",
                evidence={"release_files": current_files[:5], "latest": latest, "repository_url": repository_url},
                confidence=MEDIUM,
            ).canonicalized()

        return _unknown_with_latest(
            component,
            "PyPI",
            f"https://pypi.org/project/{component.normalized_name}/",
            latest,
            {"latest": latest, "repository_url": repository_url},
        )

    def _lookup_nuget(self, component: NormalizedComponent) -> LifecycleResult:
        package_name = component.normalized_name.split("/")[-1].lower()
        url = f"https://api.nuget.org/v3/registration5-semver1/{quote(package_name, safe='')}/index.json"
        payload = self._get_json(url)
        if not isinstance(payload, dict):
            return unknown_result(component, "NuGet")

        entries = _nuget_entries(payload)
        latest = _latest_from_versions([entry.get("version") for entry in entries])
        current = _match_version_entry(entries, component.normalized_version)
        repository_url = None
        if isinstance(current, dict):
            repository_url = current.get("repositoryUrl") or current.get("projectUrl")
        deprecation = current.get("deprecation") if isinstance(current, dict) else None
        if deprecation:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=DEPRECATED,
                deprecated=True,
                maintenance_status="Deprecated by NuGet",
                latest_version=latest,
                latest_supported_version=latest,
                recommended_version=latest if _is_newer(latest, component.normalized_version) else None,
                recommendation=_registry_recommendation(latest, component.normalized_version, "Package version is deprecated."),
                source_name="NuGet",
                source_url=f"https://www.nuget.org/packages/{package_name}",
                evidence={"deprecation": deprecation, "version": component.normalized_version, "repository_url": repository_url},
                confidence=MEDIUM,
            ).canonicalized()

        return _unknown_with_latest(
            component,
            "NuGet",
            f"https://www.nuget.org/packages/{package_name}",
            latest,
            {"latest": latest, "repository_url": repository_url},
        )

    def _lookup_maven(self, component: NormalizedComponent) -> LifecycleResult:
        parts = component.normalized_name.split("/")
        if len(parts) >= 2:
            group_id, artifact_id = parts[-2], parts[-1]
            query = quote(f'g:"{group_id}" AND a:"{artifact_id}"')
        else:
            artifact_id = component.normalized_name
            query = quote(f'a:"{artifact_id}"')
        url = f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"
        payload = self._get_json(url)
        docs = (((payload or {}).get("response") or {}).get("docs") or []) if isinstance(payload, dict) else []
        latest = docs[0].get("latestVersion") if docs and isinstance(docs[0], dict) else None
        return _unknown_with_latest(
            component,
            "Maven Central",
            "https://search.maven.org/",
            latest,
            {"latest": latest},
        )

    def _get_json(self, url: str) -> Any | None:
        if self._http_get is not None:
            return self._http_get(url)
        with httpx.Client(timeout=self._timeout_seconds, follow_redirects=True) as client:
            response = client.get(url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()


def _unknown_with_latest(
    component: NormalizedComponent,
    source_name: str,
    source_url: str,
    latest: str | None,
    evidence: dict[str, Any],
) -> LifecycleResult:
    current = component.normalized_version
    recommended = latest if _is_newer(latest, current) else None
    return LifecycleResult(
        component_name=component.normalized_name,
        component_version=current,
        ecosystem=component.ecosystem,
        purl=component.purl,
        cpe=component.cpe,
        lifecycle_status=UNKNOWN,
        latest_version=latest,
        latest_supported_version=latest,
        recommended_version=recommended,
        recommendation=f"Review upgrade to latest registry version {latest}." if recommended else None,
        source_name=source_name,
        source_url=source_url,
        evidence=evidence,
        confidence=LOW,
    ).canonicalized()


def _registry_recommendation(latest: str | None, current: str | None, message: str) -> str:
    if _is_newer(latest, current):
        return f"{message} Upgrade to registry latest version {latest} after compatibility testing."
    return str(message)


def _is_newer(candidate: str | None, current: str | None) -> bool:
    if not candidate or not current:
        return False
    try:
        return Version(str(candidate)) > Version(str(current))
    except InvalidVersion:
        return str(candidate) != str(current)


def _latest_from_versions(values: list[Any]) -> str | None:
    versions = [str(value) for value in values if value]
    if not versions:
        return None
    try:
        return str(max((Version(version), version) for version in versions)[1])
    except InvalidVersion:
        return versions[-1]


def _nuget_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for page in payload.get("items", []) or []:
        page_items = page.get("items") if isinstance(page, dict) else None
        if page_items:
            for item in page_items:
                catalog = item.get("catalogEntry", item) if isinstance(item, dict) else {}
                if isinstance(catalog, dict):
                    entries.append(catalog)
        elif isinstance(page, dict) and "catalogEntry" in page:
            catalog = page.get("catalogEntry")
            if isinstance(catalog, dict):
                entries.append(catalog)
    return entries


def _match_version_entry(entries: list[dict[str, Any]], version: str | None) -> dict[str, Any]:
    if not version:
        return {}
    for entry in entries:
        if str(entry.get("version") or "").lower() == version.lower():
            return entry
    return {}


def _repository_url(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        url = value.get("url") or value.get("web")
        if isinstance(url, str):
            return url.removeprefix("git+").removesuffix(".git").strip() or None
    return None


def _first_project_url(info: dict[str, Any], *names: str) -> str | None:
    urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    for name in names:
        value = urls.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    home = info.get("home_page")
    return home.strip() if isinstance(home, str) and home.strip() else None


__all__ = ["PackageRegistryProvider"]
