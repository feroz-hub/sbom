"""Helpers for constructing vulnerability source adapters."""

from __future__ import annotations

from collections.abc import Iterable

from .base import VulnSource
from .ghsa import GhsaSource
from .nvd import NvdSource
from .osv import OsvSource
from .vulndb import VulnDbSource

DEFAULT_ANALYSIS_SOURCES = ["NVD", "OSV", "GITHUB"]
SUPPORTED_ANALYSIS_SOURCES = ["NVD", "OSV", "GITHUB", "VULNDB"]


def normalize_source_names(
    sources: Iterable[str] | None,
    *,
    default: list[str] | None = None,
) -> list[str]:
    """Return canonical, de-duplicated source names in request order."""
    use_default = sources is None
    raw = list(default or DEFAULT_ANALYSIS_SOURCES) if use_default else list(sources)
    out: list[str] = []
    seen: set[str] = set()
    supported = set(SUPPORTED_ANALYSIS_SOURCES)
    for source in raw:
        name = (source or "").strip().upper()
        if not name or name in seen or name not in supported:
            continue
        seen.add(name)
        out.append(name)
    if out:
        return out
    return list(default or DEFAULT_ANALYSIS_SOURCES) if use_default else []


def configured_default_sources() -> list[str]:
    """Read the application's default analysis sources from settings."""
    from ..settings import get_settings

    return normalize_source_names(get_settings().analysis_sources_list) or list(DEFAULT_ANALYSIS_SOURCES)


def build_source_adapters(sources: Iterable[str]) -> list[VulnSource]:
    """Instantiate source adapters with process-configured credentials."""
    from ..credentials import github_token_for_adapters, nvd_api_key_for_adapters, vulndb_api_key_for_adapters

    factories = {
        "NVD": lambda: NvdSource(api_key=nvd_api_key_for_adapters()),
        "OSV": OsvSource,
        "GITHUB": lambda: GhsaSource(token=github_token_for_adapters()),
        "VULNDB": lambda: VulnDbSource(api_key=vulndb_api_key_for_adapters()),
    }
    return [factories[name]() for name in normalize_source_names(sources) if name in factories]
