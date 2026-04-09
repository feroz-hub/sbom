"""
Source-name → adapter-class registry.

Lets call sites do:

    cls = SOURCE_REGISTRY["NVD"]
    result = await cls(api_key=...).query(components, settings)

Adding a fourth source (e.g. Snyk, OSS Index) is then a one-line change in
this file plus a new module under ``app/sources/``. The Phase 3 cut-over of
``sboms_crud.py`` and the Phase 4 cut-over of ``analyze_endpoints.py`` will
both consume the registry to fan out concurrent ``query()`` calls via
``asyncio.gather``.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import VulnSource
from .ghsa import GhsaSource
from .nvd import NvdSource
from .osv import OsvSource


SOURCE_REGISTRY: Dict[str, Type[VulnSource]] = {
    NvdSource.name: NvdSource,
    OsvSource.name: OsvSource,
    GhsaSource.name: GhsaSource,
}


def get_source(name: str) -> Type[VulnSource]:
    """Look up an adapter class by canonical source name (case-insensitive)."""
    key = (name or "").strip().upper()
    if key not in SOURCE_REGISTRY:
        raise KeyError(
            f"Unknown vulnerability source '{name}'. "
            f"Registered sources: {sorted(SOURCE_REGISTRY)}"
        )
    return SOURCE_REGISTRY[key]
