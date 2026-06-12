"""Repository health lifecycle signals.

Repository signals are deliberately conservative. Archived repositories are
strong evidence that a component is unsupported. Lack of recent activity is
stored as maintenance evidence only; it never becomes EOL by itself.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx

from .provider_base import LifecycleProvider
from .types import LOW, MEDIUM, UNKNOWN, UNSUPPORTED, LifecycleResult, NormalizedComponent, unknown_result

STALE_ACTIVITY_DAYS = 730


class RepositoryHealthProvider(LifecycleProvider):
    name = "Repository Health"

    def __init__(
        self,
        *,
        http_get: Callable[[str], Any] | None = None,
        timeout_seconds: float = 5.0,
        today: datetime | None = None,
    ) -> None:
        self._http_get = http_get
        self._timeout_seconds = timeout_seconds
        self._today = today

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        repo_url = component.repository_url or _repository_url_from_evidence(component.external_references)
        if not repo_url:
            return unknown_result(component, self.name)

        github_repo = _github_owner_repo(repo_url)
        if github_repo:
            return self._lookup_github(component, repo_url, github_repo)

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=UNKNOWN,
            maintenance_status="Repository URL available; health not supported for this host",
            source_name=self.name,
            source_url=repo_url,
            evidence={"repository_url": repo_url},
            confidence=LOW,
        ).canonicalized()

    def _lookup_github(
        self,
        component: NormalizedComponent,
        repo_url: str,
        owner_repo: tuple[str, str],
    ) -> LifecycleResult:
        owner, repo = owner_repo
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        payload = self._get_json(api_url)
        if not isinstance(payload, dict):
            return unknown_result(component, self.name)

        archived = bool(payload.get("archived"))
        disabled = bool(payload.get("disabled"))
        pushed_at = _parse_datetime(payload.get("pushed_at"))
        updated_at = _parse_datetime(payload.get("updated_at"))
        stale_threshold = (self._today or datetime.now(UTC)) - timedelta(days=STALE_ACTIVITY_DAYS)
        last_activity = pushed_at or updated_at
        evidence = {
            "repository_url": repo_url,
            "api_url": api_url,
            "archived": archived,
            "disabled": disabled,
            "pushed_at": payload.get("pushed_at"),
            "updated_at": payload.get("updated_at"),
            "default_branch": payload.get("default_branch"),
            "security_and_analysis": payload.get("security_and_analysis"),
        }

        if archived or disabled:
            return LifecycleResult(
                component_name=component.normalized_name,
                component_version=component.normalized_version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                cpe=component.cpe,
                lifecycle_status=UNSUPPORTED,
                unsupported=True,
                maintenance_status="Repository archived or disabled",
                source_name="GitHub Repository",
                source_url=repo_url,
                evidence=evidence,
                confidence=MEDIUM,
            ).canonicalized()

        maintenance_status = None
        if last_activity and last_activity < stale_threshold:
            maintenance_status = "Possibly Unmaintained"
            evidence["stale_activity_days"] = STALE_ACTIVITY_DAYS

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=UNKNOWN,
            maintenance_status=maintenance_status,
            source_name="GitHub Repository",
            source_url=repo_url,
            evidence=evidence,
            confidence=LOW,
        ).canonicalized()

    def _get_json(self, url: str) -> Any | None:
        try:
            if self._http_get is not None:
                return self._http_get(url)
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=True) as client:
                response = client.get(url, headers={"Accept": "application/vnd.github+json"})
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            return None


def _github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    parsed = urlparse(repo_url)
    host = parsed.netloc.lower()
    if host not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    repo = parts[1].removesuffix(".git")
    return parts[0], repo


def _repository_url_from_evidence(references: list[dict[str, Any]]) -> str | None:
    for ref in references:
        if not isinstance(ref, dict):
            continue
        value = ref.get("url") or ref.get("reference")
        kind = str(ref.get("type") or ref.get("comment") or "").lower()
        if isinstance(value, str) and value.strip() and ("repo" in kind or "vcs" in kind or "github.com" in value):
            return value.strip()
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


__all__ = ["RepositoryHealthProvider"]
