"""Provider contracts for component lifecycle enrichment."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .types import LifecycleResult, NormalizedComponent, unknown_result


class LifecycleProvider(ABC):
    name: str

    @abstractmethod
    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        """Return lifecycle data for a normalized component.

        Providers must catch network/provider failures and return Unknown
        instead of raising; SBOM ingestion should never fail because lifecycle
        enrichment is temporarily unavailable.
        """


class NullLifecycleProvider(LifecycleProvider):
    name = "Unknown"

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        return unknown_result(component, self.name)


__all__ = ["LifecycleProvider", "NullLifecycleProvider"]
