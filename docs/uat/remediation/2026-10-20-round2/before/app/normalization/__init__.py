"""Pure SBOM component normalization and deduplication helpers."""

from .component_deduplicator import ComponentDeduplicator
from .component_normalizer import normalize_component
from .cpe_normalizer import normalize_cpes
from .purl_normalizer import normalize_purl
from .version_normalizer import normalize_version

__all__ = [
    "ComponentDeduplicator",
    "normalize_component",
    "normalize_cpes",
    "normalize_purl",
    "normalize_version",
]
