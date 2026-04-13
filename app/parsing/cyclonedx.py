"""CycloneDX SBOM parsing (JSON and XML)."""

from __future__ import annotations

from typing import Any

from .common import norm
from .xml_support import XMLTODICT_AVAILABLE

if XMLTODICT_AVAILABLE:
    import xmltodict  # type: ignore[import-untyped]


def parse_cyclonedx_dict(doc: dict[str, Any]) -> list[dict[str, Any]]:
    comps = []
    for c in doc.get("components", []) or []:
        comps.append(
            {
                "name": norm(c.get("name")),
                "version": norm(c.get("version")),
                "type": norm(c.get("type")),
                "group": norm(c.get("group")),
                "supplier": norm((c.get("supplier") or {}).get("name"))
                if isinstance(c.get("supplier"), dict)
                else norm(c.get("supplier")),
                "scope": norm(c.get("scope")),
                "purl": norm(c.get("purl")),
                "cpe": norm(c.get("cpe")),
                "bom_ref": norm(c.get("bom-ref") or c.get("bomRef")),
            }
        )
    return comps


def parse_cyclonedx_xml(xml_string: str) -> list[dict[str, Any]]:
    """Parse CycloneDX XML SBOM using xmltodict or xml.etree fallback."""
    if XMLTODICT_AVAILABLE:
        doc = xmltodict.parse(xml_string)
        bom = doc.get("bom") or doc
        components_raw = bom.get("components") or {}
        component_list = components_raw.get("component", [])
        if isinstance(component_list, dict):
            component_list = [component_list]
        out = []
        for c in component_list:
            purl = None
            cpe = None
            ext_refs = c.get("externalReferences", {})
            ref_list = ext_refs.get("reference", []) if isinstance(ext_refs, dict) else []
            if isinstance(ref_list, dict):
                ref_list = [ref_list]
            for ref in ref_list:
                rtype = (ref.get("@type") or "").lower()
                url = ref.get("url")
                if rtype == "purl" and url:
                    purl = url
                if "cpe" in rtype and url:
                    cpe = url
            if not purl:
                purl = norm(c.get("purl"))
            if not cpe:
                cpe = norm(c.get("cpe"))
            supplier_raw = c.get("supplier") or {}
            supplier = norm(supplier_raw.get("name") if isinstance(supplier_raw, dict) else supplier_raw)
            out.append(
                {
                    "name": norm(c.get("name")),
                    "version": norm(c.get("version")),
                    "type": norm(c.get("@type")),
                    "group": norm(c.get("group")),
                    "supplier": supplier,
                    "scope": norm(c.get("@scope")),
                    "purl": purl,
                    "cpe": cpe,
                    "bom_ref": norm(c.get("@bom-ref")),
                }
            )
        return out
    import xml.etree.ElementTree as ET

    ns = {"cdx": "http://cyclonedx.org/schema/bom/1"}
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML SBOM: {e}") from e
    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0][1:]
        ns = {"cdx": ns_uri}
    out = []
    comps_el = root.find("cdx:components", ns)
    if comps_el is None:
        return out
    for comp in comps_el.findall("cdx:component", ns):
        purl_el = comp.find("cdx:purl", ns)
        cpe_el = comp.find("cdx:cpe", ns)
        name_el = comp.find("cdx:name", ns)
        ver_el = comp.find("cdx:version", ns)
        grp_el = comp.find("cdx:group", ns)
        out.append(
            {
                "name": norm(name_el.text if name_el is not None else None),
                "version": norm(ver_el.text if ver_el is not None else None),
                "type": norm(comp.get("type")),
                "group": norm(grp_el.text if grp_el is not None else None),
                "supplier": None,
                "scope": norm(comp.get("scope")),
                "purl": norm(purl_el.text if purl_el is not None else None),
                "cpe": norm(cpe_el.text if cpe_el is not None else None),
                "bom_ref": norm(comp.get("bom-ref")),
            }
        )
    return out
