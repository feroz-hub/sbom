"""
Factory-style registry: map detected format label to dict parsers.

Used for tests and future extension; ``extract_components`` remains the main entrypoint.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .cyclonedx import parse_cyclonedx_dict
from .spdx import parse_spdx_dict

DictParser = Callable[[dict[str, Any]], list[dict]]

JSON_SBOM_PARSERS: dict[str, DictParser] = {
    "cyclonedx": parse_cyclonedx_dict,
    "spdx": parse_spdx_dict,
}


def get_json_parser_for_doc(doc: dict[str, Any]) -> DictParser:
    """
    Return a parser for a JSON SBOM dict based on the same heuristics as extract_components.

    Raises:
        ValueError: if the document cannot be classified.
    """
    if doc.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx_dict
    if doc.get("spdxVersion") or doc.get("SPDXID"):
        return parse_spdx_dict
    if "components" in doc:
        return parse_cyclonedx_dict
    raise ValueError("Unsupported SBOM format (expect CycloneDX or SPDX)")
