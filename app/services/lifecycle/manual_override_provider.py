"""Manual lifecycle override provider.

Overrides intentionally outrank external sources and are never refreshed away.
"""

from __future__ import annotations

from typing import Any

from .provider_base import LifecycleProvider
from .types import HIGH, MEDIUM, UNKNOWN, LifecycleResult, NormalizedComponent, now_iso, unknown_result


class ManualOverrideProvider(LifecycleProvider):
    name = "Manual Override"

    def __init__(self, component: Any | None = None) -> None:
        self._component = component

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        orm_component = self._component
        if orm_component is None or not bool(getattr(orm_component, "lifecycle_manual_override", False)):
            return unknown_result(component, self.name)

        evidence = getattr(orm_component, "lifecycle_evidence_json", None) or {}
        source_url = getattr(orm_component, "lifecycle_source_url", None)
        confidence = HIGH if source_url else MEDIUM
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            lifecycle_status=getattr(orm_component, "lifecycle_status", None) or UNKNOWN,
            eos_date=getattr(orm_component, "eos_date", None),
            eol_date=getattr(orm_component, "eol_date", None),
            eof_date=getattr(orm_component, "eof_date", None),
            deprecated=bool(
                getattr(orm_component, "deprecated", False) or getattr(orm_component, "is_deprecated", False)
            ),
            maintenance_status=getattr(orm_component, "maintenance_status", None),
            latest_supported_version=getattr(orm_component, "latest_supported_version", None),
            recommended_version=getattr(orm_component, "recommended_version", None),
            recommendation=getattr(orm_component, "lifecycle_recommendation", None),
            source_name=self.name,
            source_url=source_url,
            evidence=evidence if isinstance(evidence, dict) else {"raw": evidence},
            confidence=confidence,
            checked_at=getattr(orm_component, "lifecycle_checked_at", None) or now_iso(),
            stale=False,
            manual_override=True,
        ).canonicalized()


__all__ = ["ManualOverrideProvider"]
