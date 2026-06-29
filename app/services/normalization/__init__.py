"""Service-facing imports for Stage 9 normalization."""

from app.normalization import (
    ComponentDeduplicator,
    normalize_component,
    normalize_cpes,
    normalize_purl,
    normalize_version,
)

__all__ = ["ComponentDeduplicator", "normalize_component", "normalize_cpes", "normalize_purl", "normalize_version"]
