"""Lifecycle provider backed by Xeol's component EOL check API."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_XEOL
from .types import (
    DEPRECATED,
    EOL,
    EOL_SOON,
    HIGH,
    MEDIUM,
    SUPPORTED,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)

XEOL_CHECK_URL = "https://edb-prod.xeol.io/eol/check"
EOL_SOON_DAYS = 180


class XeolProvider(LifecycleProvider):
    """Query Xeol using the documented name/version/ecosystem request."""

    name = "Xeol"
    priority = PRIORITY_XEOL

    def supports(self, component: NormalizedComponent) -> bool:
        return self.enabled and bool(component.normalized_name and component.normalized_version)

    def __init__(
        self,
        *,
        api_url: str = XEOL_CHECK_URL,
        api_key: str | None = None,
        http_post: Callable[..., Any] | None = None,
        timeout_seconds: float = 5.0,
        enabled: bool = True,
        today: date | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._http_post = http_post
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.today = today

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        if not self.enabled or not component.normalized_name or not component.normalized_version:
            return unknown_result(component, self.name)

        request = {
            "component": {
                "name": component.normalized_name,
                "version": component.normalized_version,
                "ecosystem": component.ecosystem or "generic",
            }
        }
        payload = self._post(request)
        if not isinstance(payload, dict) or payload.get("error"):
            return unknown_result(component, self.name)
        result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
        if not isinstance(result, dict):
            return unknown_result(component, self.name)

        parsed = _parse_xeol_result(result, today=self.today)
        if not parsed["matched"]:
            return unknown_result(component, self.name)

        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            supplier=component.supplier,
            lifecycle_status=parsed["status"],
            eol_date=parsed["eol_date"],
            deprecated=parsed["status"] == DEPRECATED,
            unsupported=parsed["status"] in {EOL, UNSUPPORTED},
            maintenance_status=parsed["maintenance_status"],
            recommendation=parsed["recommendation"],
            source_name=self.name,
            source_url=parsed["source_url"] or "https://www.xeol.io/",
            confidence=parsed["confidence"],
            evidence={
                "provider": "xeol",
                "reason": parsed["reason"],
                "authority": "vendor-derived" if parsed["reason"] == "vendor_announced" else "aggregator",
                "raw": result,
            },
        ).canonicalized()

    def _post(self, request: dict[str, Any]) -> Any | None:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            if self._http_post is not None:
                try:
                    return self._http_post(self.api_url, request, headers)
                except TypeError:
                    return self._http_post(self.api_url, request)
            with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                response = client.post(self.api_url, json=request, headers=headers)
                if response.status_code in {400, 401, 404, 429}:
                    return None
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, TypeError, ValueError):
            return None


def _parse_xeol_result(result: dict[str, Any], *, today: date | None = None) -> dict[str, Any]:
    current_date = today or datetime.now(UTC).date()
    reason = str(result.get("eol_reason") or "").strip().lower()
    eol_date = _date(result.get("eol_date"))
    eol_flag = result.get("eol") is True
    matched = bool(result.get("match", {}).get("found")) if isinstance(result.get("match"), dict) else False
    source_url = _reference_url(result)

    eol_block = result.get("eol")
    if isinstance(eol_block, dict):
        now_block = eol_block.get("now") if isinstance(eol_block.get("now"), dict) else {}
        primary = now_block.get("primary") if isinstance(now_block.get("primary"), dict) else None
        if primary:
            matched = True
            eol_flag = True
            reason = str(primary.get("reason") or reason).strip().lower()
            eol_date = _date(primary.get("date")) or eol_date
        future = eol_block.get("future") if isinstance(eol_block.get("future"), dict) else {}
        future_primary = future.get("primary") if isinstance(future.get("primary"), dict) else None
        if not primary and future_primary:
            matched = True
            reason = str(future_primary.get("reason") or reason).strip().lower()
            eol_date = _date(future_primary.get("date")) or eol_date

    if result.get("version") or result.get("entity") or result.get("componentName"):
        matched = True

    if reason == "registry_deprecated":
        status = DEPRECATED
    elif reason == "source_archived":
        status = UNSUPPORTED
    elif eol_flag or (eol_date and eol_date < current_date):
        status = EOL
    elif eol_date and eol_date <= current_date + timedelta(days=EOL_SOON_DAYS):
        status = EOL_SOON
    elif matched:
        status = SUPPORTED
    else:
        status = UNKNOWN

    eol_iso = eol_date.isoformat() if eol_date else None
    recommendation = None
    if status in {EOL, EOL_SOON, DEPRECATED, UNSUPPORTED}:
        recommendation = "Upgrade or replace this component with a vendor-supported release."
    confidence = HIGH if reason == "vendor_announced" else MEDIUM
    maintenance_status = {
        EOL: "End of life",
        EOL_SOON: "EOL within 180 days",
        DEPRECATED: "Deprecated",
        UNSUPPORTED: "Unsupported",
        SUPPORTED: "Supported",
    }.get(status, "Unknown")
    return {
        "matched": matched,
        "status": status,
        "reason": reason or None,
        "eol_date": eol_iso,
        "source_url": source_url,
        "confidence": confidence,
        "maintenance_status": maintenance_status,
        "recommendation": recommendation,
    }


def _date(value: Any) -> date | None:
    if not value or isinstance(value, bool):
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _reference_url(result: dict[str, Any]) -> str | None:
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    entity = evidence.get("entity") if isinstance(evidence.get("entity"), dict) else {}
    references = entity.get("references") if isinstance(entity.get("references"), list) else []
    for reference in references:
        if isinstance(reference, dict) and reference.get("url"):
            return str(reference["url"])
    lifecycles = result.get("lifecycles") if isinstance(result.get("lifecycles"), list) else []
    for lifecycle in lifecycles:
        if isinstance(lifecycle, dict) and lifecycle.get("uri"):
            return str(lifecycle["uri"])
    return None


__all__ = ["XEOL_CHECK_URL", "XeolProvider"]
