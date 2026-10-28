"""SBOM format detection and component extraction (CycloneDX / SPDX)."""

from .extract import extract_components
from .format import detect_sbom_format

__all__ = ["extract_components", "detect_sbom_format"]
