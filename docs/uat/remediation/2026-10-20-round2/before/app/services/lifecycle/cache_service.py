"""Lifecycle cache service facade."""

from __future__ import annotations

from ...models import ComponentLifecycleCache
from .cache import cache_is_expired, lookup_key_for
from .types import NormalizedComponent


class LifecycleCacheService:
    """Small facade used by enrichment jobs and tests."""

    def lookup_key_for(self, component: NormalizedComponent) -> str:
        return lookup_key_for(component)

    def is_expired(self, cache_entry: ComponentLifecycleCache) -> bool:
        return cache_is_expired(cache_entry)


__all__ = ["LifecycleCacheService"]
