"""Extract normalized components from CycloneDX or SPDX SBOM input."""

from __future__ import annotations

import json
from typing import Any

from .cyclonedx import parse_cyclonedx_dict, parse_cyclonedx_xml
from .spdx import parse_spdx_dict, parse_spdx_xml


def extract_components(sbom_json: Any) -> list[dict]:
    """Accept SBOM as JSON string, XML string, or already-parsed dict."""
    if isinstance(sbom_json, dict):
        doc = sbom_json
        if doc.get("bomFormat") == "CycloneDX":
            return parse_cyclonedx_dict(doc)
        if doc.get("spdxVersion") or doc.get("SPDXID"):
            return parse_spdx_dict(doc)
        if "components" in doc:  # best-effort CycloneDX-like
            return parse_cyclonedx_dict(doc)
        raise ValueError("Unsupported SBOM format (expect CycloneDX or SPDX)")

    # Strip BOM, zero-width chars, and whitespace
    _INVISIBLE = "\ufeff\ufffe\u200b\u200c\u200d\u2060\ufffe\u00a0"
    text = sbom_json.strip().lstrip(_INVISIBLE).strip() if isinstance(sbom_json, str) else ""

    # Try JSON first
    if text.startswith("{") or text.startswith("["):
        try:
            doc = json.loads(text)
            if doc.get("bomFormat") == "CycloneDX":
                return parse_cyclonedx_dict(doc)
            if doc.get("spdxVersion") or doc.get("SPDXID"):
                return parse_spdx_dict(doc)
            if "components" in doc:
                return parse_cyclonedx_dict(doc)
            raise ValueError("Unsupported SBOM format (expect CycloneDX or SPDX)")
        except json.JSONDecodeError:
            pass

    # Try XML
    if text.startswith("<"):
        text_lower = text.lower()
        if "cyclonedx" in text_lower or 'bomformat="cyclonedx"' in text_lower or "<bom" in text_lower:
            return parse_cyclonedx_xml(text)
        if "spdx" in text_lower:
            return parse_spdx_xml(text)
        return parse_cyclonedx_xml(text)

    # Last resort: try JSON parse
    doc = json.loads(text)
    if doc.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx_dict(doc)
    if doc.get("spdxVersion") or doc.get("SPDXID"):
        return parse_spdx_dict(doc)
    raise ValueError("Unsupported SBOM format (expect CycloneDX or SPDX)")
