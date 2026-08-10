"""Lifecycle cache helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from ...models import ComponentLifecycleCache
from .normalizer import build_lifecycle_lookup_key
from .types import NormalizedComponent


def lookup_key_for(component: NormalizedComponent) -> str:
    return build_lifecycle_lookup_key(component)


def cache_is_expired(cache_entry: ComponentLifecycleCache) -> bool:
    try:
        return datetime.fromisoformat(str(cache_entry.expires_at).replace("Z", "+00:00")) <= datetime.now(UTC)
    except (AttributeError, ValueError):
        return True


__all__ = ["cache_is_expired", "lookup_key_for"]
