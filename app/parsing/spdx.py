"""SPDX SBOM parsing (JSON and XML)."""

from __future__ import annotations

from typing import Any

from .common import norm
from .xml_support import XMLTODICT_AVAILABLE

if XMLTODICT_AVAILABLE:
    import xmltodict  # type: ignore[import-untyped]


def parse_spdx_dict(doc: dict[str, Any]) -> list[dict[str, Any]]:
    comps = []
    # SPDX 2.x "packages"
    for pkg in doc.get("packages", []) or []:
        purl = None
        cpe = None
        for ref in pkg.get("externalRefs") or []:
            rtype = (ref.get("referenceType") or "").lower()
            if rtype == "purl":
                purl = norm(ref.get("referenceLocator"))
            if "cpe" in rtype:
                cpe = norm(ref.get("referenceLocator"))
        supplier = None
        supplier_info = pkg.get("supplier")
        if isinstance(supplier_info, str):
            supplier = norm(supplier_info)
        comps.append(
            {
                "name": norm(pkg.get("name")),
                "version": norm(pkg.get("versionInfo")),
                "type": "library",
                "group": None,
                "supplier": supplier,
                "scope": None,
                "purl": purl,
                "cpe": cpe,
                "bom_ref": norm(pkg.get("SPDXID")),
            }
        )
    # SPDX-Lite or other representations
    for obj in doc.get("elements", []) or []:
        if obj.get("type") == "software:package":
            purl = norm(obj.get("packageUrl") or obj.get("packageURL"))
            cpe = None
            for ref in obj.get("externalRefs") or obj.get("externalIdentifiers") or []:
                rtype = (ref.get("referenceType") or ref.get("type") or "").lower()
                if "cpe" in rtype:
                    cpe = norm(ref.get("referenceLocator") or ref.get("locator"))
                if rtype == "purl" and not purl:
                    purl = norm(ref.get("referenceLocator") or ref.get("locator"))
            comps.append(
                {
                    "name": norm(obj.get("name")),
                    "version": norm(obj.get("version")),
                    "type": "library",
                    "group": None,
                    "supplier": None,
                    "scope": None,
                    "purl": purl,
                    "cpe": cpe,
                    "bom_ref": norm(obj.get("id") or obj.get("spdx-id")),
                }
            )
    return comps


def parse_spdx_xml(xml_string: str) -> list[dict[str, Any]]:
    """Parse SPDX XML (RDF/XML or tag-value as XML) — best-effort."""
    if XMLTODICT_AVAILABLE:
        doc = xmltodict.parse(xml_string)
        return parse_spdx_dict(doc)
    return []
