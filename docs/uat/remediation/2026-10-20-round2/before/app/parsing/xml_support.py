"""Optional xmltodict for CycloneDX/SPDX XML SBOM parsing."""

try:
    import xmltodict  # type: ignore[import-untyped]

    XMLTODICT_AVAILABLE = True
except ImportError:
    XMLTODICT_AVAILABLE = False
