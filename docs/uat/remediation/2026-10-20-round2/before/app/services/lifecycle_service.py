"""Backward-compatible lifecycle service facade.

The previous implementation used an in-process static catalog as the source of
truth.  The production path now delegates to provider-based enrichment under
``app.services.lifecycle`` while keeping this module's public functions stable
for upload/versioning code.
"""

from __future__ import annotations

from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy.orm import Session

from .lifecycle import LifecycleEnrichmentService
from .lifecycle import sync_lifecycle_for_sbom as _sync_lifecycle_for_sbom
from .lifecycle.types import UNKNOWN


def parse_clean_version(version_str: str | None) -> Version | None:
    """Clean and parse non-standard version strings into Version objects."""
    if not version_str or version_str.upper() == "UNKNOWN":
        return None
    cleaned = version_str.replace(",", ".").replace(" ", "").strip()
    try:
        return Version(cleaned)
    except InvalidVersion:
        numeric_parts = [char for char in cleaned if char.isdigit() or char == "."]
        numeric_str = "".join(numeric_parts).strip(".")
        try:
            return Version(numeric_str) if numeric_str else None
        except InvalidVersion:
            return None


def analyze_component_lifecycle(name: str, version_str: str | None) -> dict[str, Any]:
    """Compatibility helper for old callers.

    Provider-backed enrichment requires a persisted component and database
    cache.  Callers that need real enrichment should use ``sync_lifecycle_for_sbom``
    or ``LifecycleEnrichmentService.enrich_component``.  This function avoids
    making hidden network calls and returns an explicit Unknown lifecycle state.
    """

    return {
        "component_name": name,
        "component_version": version_str,
        "lifecycle_status": UNKNOWN,
        "eos_date": None,
        "eol_date": None,
        "eof_date": None,
        "is_deprecated": False,
        "deprecated": False,
        "maintenance_status": "Unknown",
        "source_name": None,
        "confidence": "Unknown",
    }


def sync_lifecycle_for_sbom(db: Session, sbom_id: int, *, force_refresh: bool = False) -> dict[str, Any]:
    """Enrich all components in an SBOM with provider-sourced lifecycle data."""

    return _sync_lifecycle_for_sbom(db, sbom_id, force_refresh=force_refresh)


__all__ = [
    "LifecycleEnrichmentService",
    "analyze_component_lifecycle",
    "parse_clean_version",
    "sync_lifecycle_for_sbom",
]
