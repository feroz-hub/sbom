"""Lifecycle provider backed by the public endoflife.date API."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from .provider_base import LifecycleProvider
from .types import (
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    HIGH,
    SUPPORTED,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)

END_OF_LIFE_API_V1 = "https://endoflife.date/api/v1/products"
END_OF_LIFE_LEGACY_API = "https://endoflife.date/api"
EOL_SOON_DAYS = 180


PRODUCT_SLUGS: dict[str, str] = {
    "node": "nodejs",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "python": "python",
    "java": "java",
    "openjdk": "java",
    "jdk": "java",
    "dotnet": "dotnet",
    ".net": "dotnet",
    "angular": "angular",
    "@angular/core": "angular",
    "django": "django",
    "spring": "spring-framework",
    "spring-framework": "spring-framework",
    "spring framework": "spring-framework",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "golang": "go",
    "go": "go",
    "ruby": "ruby",
    "php": "php",
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "redis": "redis",
    "openssl": "openssl",
    "docker": "docker-engine",
    "alpine": "alpine",
    "elasticsearch": "elasticsearch",
    "kafka": "kafka",
}


class EndOfLifeDateProvider(LifecycleProvider):
    name = "endoflife.date"

    def __init__(
        self,
        *,
        http_get: Callable[[str], Any] | None = None,
        timeout_seconds: float = 5.0,
        retries: int = 1,
        today: date | None = None,
    ) -> None:
        self._http_get = http_get
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._today = today

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        slug = slug_for_component(component)
        if not slug or not component.normalized_version:
            return unknown_result(component, self.name)

        payload = self._fetch_product(slug)
        cycles = _extract_cycles(payload)
        if not cycles:
            return unknown_result(component, self.name)

        matched = _match_cycle(cycles, component.normalized_version)
        if not matched:
            return unknown_result(component, self.name)

        eol_date = _extract_date(matched, "eol", "eolFrom", "endOfLife")
        eos_date = _extract_date(matched, "support", "eos", "endOfSupport")
        eof_date = _extract_date(matched, "eof", "endOfFix", "endOfFullSupport")
        latest = _string_value(matched, "latest", "latestVersion", "latestRelease")
        status = self._status_from_dates(eol_date, eos_date, eof_date, matched)
        recommendation = _recommendation(status, latest, component.normalized_version, slug)

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=status,
            eos_date=eos_date,
            eol_date=eol_date,
            eof_date=eof_date,
            unsupported=status in {EOL, EOS, EOF, UNSUPPORTED},
            maintenance_status=_maintenance_status(status),
            latest_version=latest,
            latest_supported_version=latest,
            recommended_version=latest if _is_newer(latest, component.normalized_version) else None,
            recommendation=recommendation,
            source_name=self.name,
            source_url=f"https://endoflife.date/{slug}",
            evidence={"product": slug, "cycle": matched},
            confidence=HIGH,
        ).canonicalized()

    def _fetch_product(self, slug: str) -> Any | None:
        urls = (f"{END_OF_LIFE_API_V1}/{slug}/", f"{END_OF_LIFE_LEGACY_API}/{slug}.json")
        for url in urls:
            payload = self._fetch_json_with_retries(url)
            if payload:
                return payload
        return None

    def _fetch_json_with_retries(self, url: str) -> Any | None:
        attempts = max(1, self._retries + 1)
        for _ in range(attempts):
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
                continue
        return None

    def _status_from_dates(
        self,
        eol_date: str | None,
        eos_date: str | None,
        eof_date: str | None,
        cycle: dict[str, Any],
    ) -> str:
        today = self._today or datetime.now(UTC).date()
        eol = _parse_date(eol_date)
        eos = _parse_date(eos_date)
        eof = _parse_date(eof_date)
        if eol and eol < today:
            return EOL
        if eos and eos < today:
            return EOS
        if eof and eof < today:
            return EOF
        if eol and today <= eol <= today + timedelta(days=EOL_SOON_DAYS):
            return EOL_SOON
        if _truthy_any(cycle, "discontinued", "unsupported", "obsolete"):
            return UNSUPPORTED
        if eol or eos or eof:
            return SUPPORTED
        return UNKNOWN


def slug_for_component(component: NormalizedComponent) -> str | None:
    candidates = [
        component.normalized_name,
        component.name,
        component.component_group or "",
        component.supplier or "",
        component.ecosystem if component.ecosystem in {"ubuntu", "debian"} else "",
    ]
    for candidate in candidates:
        cleaned = _slug_key(candidate)
        if cleaned in PRODUCT_SLUGS:
            return PRODUCT_SLUGS[cleaned]
        leaf = cleaned.split("/")[-1]
        if leaf in PRODUCT_SLUGS:
            return PRODUCT_SLUGS[leaf]
    return None


def _slug_key(value: str | None) -> str:
    if not value:
        return ""
    cleaned = value.strip().lower()
    if cleaned.startswith("@") and "/" in cleaned:
        return cleaned
    return cleaned.replace("_", "-").replace(" ", "-")


def _extract_cycles(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("releases", "cycles", "result"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _extract_cycles(value)
            if nested:
                return nested
    if "cycle" in payload:
        return [payload]
    return []


def _match_cycle(cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
    version_clean = version.strip().lower().lstrip("v")
    sorted_cycles = sorted(cycles, key=lambda row: len(str(row.get("cycle") or "")), reverse=True)
    for cycle in sorted_cycles:
        cycle_value = str(cycle.get("cycle") or cycle.get("name") or "").strip().lower().lstrip("v")
        if not cycle_value:
            continue
        if version_clean == cycle_value or version_clean.startswith(f"{cycle_value}."):
            return cycle
    major = version_clean.split(".", 1)[0]
    for cycle in sorted_cycles:
        cycle_value = str(cycle.get("cycle") or cycle.get("name") or "").strip().lower().lstrip("v")
        if cycle_value == major:
            return cycle
    return None


def _extract_date(row: dict[str, Any], *keys: str) -> str | None:
    value = _first_value(row, *keys)
    if value in (None, False, "false", "False", ""):
        return None
    if value is True:
        return None
    parsed = _parse_date(str(value))
    return parsed.isoformat() if parsed else None


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    text = value.strip()
    if not text or text.lower() in {"false", "true", "none", "null"}:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _string_value(row: dict[str, Any], *keys: str) -> str | None:
    value = _first_value(row, *keys)
    if value in (None, False, "false", "False", ""):
        return None
    return str(value)


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row:
            return row[key]
    return None


def _truthy_any(row: dict[str, Any], *keys: str) -> bool:
    return any(bool(row.get(key)) for key in keys)


def _is_newer(candidate: str | None, current: str | None) -> bool:
    if not candidate or not current:
        return False
    try:
        return Version(candidate) > Version(current)
    except InvalidVersion:
        return candidate != current


def _maintenance_status(status: str) -> str:
    if status == EOL:
        return "End of life"
    if status == EOS:
        return "End of support"
    if status == EOF:
        return "End of fixes"
    if status == EOL_SOON:
        return "EOL within 180 days"
    if status == UNSUPPORTED:
        return "Unsupported"
    if status == SUPPORTED:
        return "Supported"
    return "Unknown"


def _recommendation(status: str, latest: str | None, current: str | None, slug: str) -> str | None:
    if status in {EOL, EOS, EOF, EOL_SOON, UNSUPPORTED}:
        if _is_newer(latest, current):
            return f"Upgrade {slug} to supported version {latest}."
        return f"Review {slug} lifecycle support and upgrade to a supported cycle."
    return None


__all__ = ["EndOfLifeDateProvider", "slug_for_component"]
