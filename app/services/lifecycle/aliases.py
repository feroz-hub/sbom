"""Component lifecycle alias resolution from static configuration."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ruamel.yaml import YAML

_ALIASES_PATH = Path(__file__).with_name("aliases.yml")
_yaml = YAML(typ="safe")


@dataclass(frozen=True, slots=True)
class LifecycleAlias:
    alias: str
    canonical_name: str
    provider_product_name: str
    ecosystem: str
    source: str


def _normalize_alias_key(value: str | None) -> str:
    return " ".join((value or "").strip().lower().replace("_", " ").replace("-", " ").split())


@lru_cache(maxsize=1)
def load_lifecycle_aliases() -> dict[str, LifecycleAlias]:
    """Load alias table keyed by normalized alias string."""
    if not _ALIASES_PATH.is_file():
        return {}
    with _ALIASES_PATH.open(encoding="utf-8") as handle:
        payload = _yaml.load(handle) or {}
    rows = payload.get("aliases") if isinstance(payload, dict) else []
    aliases: dict[str, LifecycleAlias] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        alias_key = _normalize_alias_key(str(row.get("alias") or ""))
        canonical = str(row.get("canonical_name") or "").strip().lower()
        if not alias_key or not canonical:
            continue
        entry = LifecycleAlias(
            alias=alias_key,
            canonical_name=canonical,
            provider_product_name=str(row.get("provider_product_name") or canonical).strip().lower(),
            ecosystem=str(row.get("ecosystem") or "generic").strip().lower(),
            source=str(row.get("source") or "endoflife.date").strip().lower(),
        )
        aliases[alias_key] = entry
        aliases[_normalize_alias_key(canonical)] = entry
    return aliases


def resolve_lifecycle_alias(name: str | None, ecosystem: str | None = None) -> LifecycleAlias | None:
    """Resolve a component name to a lifecycle alias entry."""
    key = _normalize_alias_key(name)
    if not key:
        return None
    aliases = load_lifecycle_aliases()
    entry = aliases.get(key)
    if entry is None:
        leaf = key.split("/")[-1]
        entry = aliases.get(leaf)
    if entry is None:
        return None
    if ecosystem and ecosystem not in {"generic", entry.ecosystem}:
        return entry
    return entry


def apply_alias_to_component_fields(
    normalized_name: str,
    ecosystem: str,
) -> tuple[str, str, str | None]:
    """Return canonical name, ecosystem, and provider product slug after alias resolution."""
    entry = resolve_lifecycle_alias(normalized_name, ecosystem)
    if entry is None:
        return normalized_name, ecosystem, None
    eco = entry.ecosystem if entry.ecosystem != "generic" else ecosystem
    return entry.canonical_name, eco, entry.provider_product_name


def clear_alias_cache() -> None:
    """Clear cached alias table (for tests)."""
    load_lifecycle_aliases.cache_clear()


__all__ = [
    "LifecycleAlias",
    "apply_alias_to_component_fields",
    "clear_alias_cache",
    "load_lifecycle_aliases",
    "resolve_lifecycle_alias",
]
