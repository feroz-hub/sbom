"""
Detect SBOM format (CycloneDX vs SPDX) from a parsed JSON document.

Single source of truth for format detection used by upload validation and services.
"""

from __future__ import annotations

from typing import Any


def detect_sbom_format(sbom: dict[str, Any]) -> tuple[str, str]:
    """
    Detect SBOM format and return (format, spec_version).

    format is 'cyclonedx' or 'spdx'.

    Raises:
        ValueError: If format cannot be detected.
    """
    # CycloneDX indicators
    if (isinstance(sbom.get("bomFormat"), str) and sbom.get("bomFormat", "").lower() == "cyclonedx") or (
        "components" in sbom and isinstance(sbom["components"], list)
    ):
        version_str = sbom.get("specVersion") or sbom.get("version") or "unknown"
        return "cyclonedx", str(version_str)

    # SPDX indicators
    if "spdxVersion" in sbom or "packages" in sbom:
        version_str = sbom.get("spdxVersion", "unknown")
        return "spdx", str(version_str)

    raise ValueError(
        "Unable to detect SBOM format. Expected CycloneDX (bomFormat/components) or SPDX (spdxVersion/packages)."
    )
