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
        external_refs = c.get("externalReferences") or c.get("externalRefs") or []
        cpes = []
        if norm(c.get("cpe")):
            cpes.append(norm(c.get("cpe")))
        for ref in external_refs if isinstance(external_refs, list) else []:
            if not isinstance(ref, dict):
                continue
            rtype = (ref.get("type") or ref.get("referenceType") or "").lower()
            locator = norm(ref.get("url") or ref.get("referenceLocator"))
            if "cpe" in rtype and locator:
                cpes.append(locator)
        # Extract license
        licenses = c.get("licenses")
        license_str = None
        if isinstance(licenses, list):
            lic_names = []
            for lic_item in licenses:
                if isinstance(lic_item, dict):
                    lic_obj = lic_item.get("license")
                    if isinstance(lic_obj, dict):
                        lic_name = lic_obj.get("id") or lic_obj.get("name")
                        if lic_name:
                            lic_names.append(str(lic_name))
                    elif isinstance(lic_obj, str):
                        lic_names.append(lic_obj)
                    elif lic_item.get("expression"):
                        lic_names.append(str(lic_item.get("expression")))
                elif isinstance(lic_item, str):
                    lic_names.append(lic_item)
            if lic_names:
                license_str = ", ".join(lic_names)
        elif isinstance(licenses, dict):
            lic_obj = licenses.get("license")
            if isinstance(lic_obj, dict):
                license_str = lic_obj.get("id") or lic_obj.get("name")
            elif isinstance(lic_obj, str):
                license_str = lic_obj
            elif licenses.get("expression"):
                license_str = licenses.get("expression")
        elif isinstance(licenses, str):
            license_str = licenses

        if not license_str and c.get("license"):
            license_str = str(c.get("license"))

        # Extract hashes
        hashes = c.get("hashes")
        hashes_str = None
        if isinstance(hashes, list):
            hash_parts = []
            for h in hashes:
                if isinstance(h, dict):
                    alg = h.get("alg")
                    content = h.get("content")
                    if alg and content:
                        hash_parts.append(f"{alg}:{content}")
                    elif content:
                        hash_parts.append(str(content))
                elif isinstance(h, str):
                    hash_parts.append(h)
            if hash_parts:
                hashes_str = ", ".join(hash_parts)
        elif isinstance(hashes, str):
            hashes_str = hashes

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
                "cpes": cpes,
                "external_references": external_refs if isinstance(external_refs, list) else [],
                "cpe_source": "sbom_provided" if norm(c.get("cpe")) else None,
                "bom_ref": norm(c.get("bom-ref") or c.get("bomRef")),
                "license": norm(license_str),
                "hashes": norm(hashes_str),
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

            # Licenses in xmltodict
            licenses_raw = c.get("licenses") or {}
            license_list = licenses_raw.get("license", []) if isinstance(licenses_raw, dict) else []
            if isinstance(license_list, dict):
                license_list = [license_list]
            elif isinstance(license_list, str):
                license_list = [{"name": license_list}]
            lic_names = []
            for lic_item in license_list:
                if isinstance(lic_item, dict):
                    lic_name = lic_item.get("id") or lic_item.get("name")
                    if lic_name:
                        lic_names.append(str(lic_name))
                elif isinstance(lic_item, str):
                    lic_names.append(lic_item)
            if isinstance(licenses_raw, dict) and licenses_raw.get("expression"):
                lic_names.append(str(licenses_raw.get("expression")))
            license_str = ", ".join(lic_names) if lic_names else None

            # Hashes in xmltodict
            hashes_raw = c.get("hashes") or {}
            hash_list = hashes_raw.get("hash", []) if isinstance(hashes_raw, dict) else []
            if isinstance(hash_list, dict):
                hash_list = [hash_list]
            elif isinstance(hash_list, str):
                hash_list = [hash_list]
            hash_parts = []
            for h in hash_list:
                if isinstance(h, dict):
                    alg = h.get("@alg")
                    content = h.get("#text") or h.get("text")
                    if alg and content:
                        hash_parts.append(f"{alg}:{content}")
                    elif content:
                        hash_parts.append(str(content))
                elif isinstance(h, str):
                    hash_parts.append(h)
            hashes_str = ", ".join(hash_parts) if hash_parts else None

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
                    "cpes": [cpe] if cpe else [],
                    "external_references": ref_list if isinstance(ref_list, list) else [],
                    "cpe_source": "sbom_provided" if cpe else None,
                    "bom_ref": norm(c.get("@bom-ref")),
                    "license": norm(license_str),
                    "hashes": norm(hashes_str),
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

        # Extract licenses using ElementTree
        lic_names = []
        licenses_el = comp.find("cdx:licenses", ns)
        if licenses_el is not None:
            expr_el = licenses_el.find("cdx:expression", ns)
            if expr_el is not None and expr_el.text:
                lic_names.append(expr_el.text)
            for lic_el in licenses_el.findall("cdx:license", ns):
                id_el = lic_el.find("cdx:id", ns)
                name_el_lic = lic_el.find("cdx:name", ns)
                if id_el is not None and id_el.text:
                    lic_names.append(id_el.text)
                elif name_el_lic is not None and name_el_lic.text:
                    lic_names.append(name_el_lic.text)
        license_str = ", ".join(lic_names) if lic_names else None

        # Extract hashes using ElementTree
        hash_parts = []
        hashes_el = comp.find("cdx:hashes", ns)
        if hashes_el is not None:
            for hash_el in hashes_el.findall("cdx:hash", ns):
                alg = hash_el.get("alg")
                content = hash_el.text
                if alg and content:
                    hash_parts.append(f"{alg}:{content}")
                elif content:
                    hash_parts.append(content)
        hashes_str = ", ".join(hash_parts) if hash_parts else None

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
                "cpes": [norm(cpe_el.text)] if cpe_el is not None and norm(cpe_el.text) else [],
                "external_references": [],
                "cpe_source": "sbom_provided" if cpe_el is not None and norm(cpe_el.text) else None,
                "bom_ref": norm(comp.get("bom-ref")),
                "license": norm(license_str),
                "hashes": norm(hashes_str),
            }
        )
    return out
