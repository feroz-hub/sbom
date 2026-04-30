"""Spec-specific dict → :class:`InternalSbom` projection.

The semantic stages call :func:`normalize_spdx` or :func:`normalize_cyclonedx`
once after stage 3 succeeds. Both produce the same internal shape so stages
5-8 are spec-agnostic.

Normalization is **lossy on purpose**: only fields that downstream stages
need are extracted. The original dict survives on ``InternalSbom.raw_dict``
and on each component's ``raw`` field for any semantic check that needs to
re-read the source.
"""

from __future__ import annotations

from typing import Any

from .models import Component, DependencyEdge, DocumentMetadata, InternalSbom


def normalize_cyclonedx(doc: dict[str, Any], spec_version: str) -> InternalSbom:
    """Project a parsed CycloneDX dict into the internal model."""
    components: list[Component] = []
    declared_refs: set[str] = set()
    metadata_block = doc.get("metadata") or {}
    creators: list[str] = []
    for tool in metadata_block.get("tools") or []:
        # CycloneDX 1.5+ tools may be {"components": [...], "services": [...]}
        if isinstance(tool, dict):
            name = tool.get("name") or tool.get("vendor")
            if isinstance(name, str):
                creators.append(name)
    if isinstance(metadata_block.get("tools"), dict):
        tools_obj = metadata_block["tools"]
        for sub in tools_obj.get("components") or []:
            if isinstance(sub, dict) and isinstance(sub.get("name"), str):
                creators.append(sub["name"])

    bom_version = doc.get("version")
    if isinstance(bom_version, str) and bom_version.lstrip("-").isdigit():
        bom_version_int = int(bom_version)
    elif isinstance(bom_version, int):
        bom_version_int = bom_version
    else:
        bom_version_int = None

    md = DocumentMetadata(
        document_namespace=None,
        serial_number=doc.get("serialNumber"),
        bom_version=bom_version_int,
        spec_version=spec_version,
        data_license=None,
        name=(metadata_block.get("component") or {}).get("name") if isinstance(metadata_block.get("component"), dict) else None,
        creators=creators,
        created=metadata_block.get("timestamp"),
    )

    raw_components = doc.get("components") or []
    if not isinstance(raw_components, list):
        raw_components = []

    for index, comp in enumerate(raw_components):
        if not isinstance(comp, dict):
            continue
        ref = comp.get("bom-ref") or comp.get("bomRef") or f"__index_{index}__"
        if isinstance(ref, str):
            declared_refs.add(ref)
        licenses: list[str] = []
        for lic in comp.get("licenses") or []:
            if isinstance(lic, dict):
                expr = lic.get("expression")
                lic_obj = lic.get("license") or {}
                lic_id = lic_obj.get("id") if isinstance(lic_obj, dict) else None
                lic_name = lic_obj.get("name") if isinstance(lic_obj, dict) else None
                token = expr or lic_id or lic_name
                if isinstance(token, str):
                    licenses.append(token)
        supplier_block = comp.get("supplier")
        if isinstance(supplier_block, dict):
            supplier = supplier_block.get("name")
        else:
            supplier = supplier_block if isinstance(supplier_block, str) else None
        components.append(
            Component(
                ref=str(ref),
                name=comp.get("name") if isinstance(comp.get("name"), str) else None,
                version=comp.get("version") if isinstance(comp.get("version"), str) else None,
                purl=comp.get("purl") if isinstance(comp.get("purl"), str) else None,
                cpe=comp.get("cpe") if isinstance(comp.get("cpe"), str) else None,
                hashes=[h for h in (comp.get("hashes") or []) if isinstance(h, dict)],
                supplier=supplier if isinstance(supplier, str) else None,
                type=comp.get("type") if isinstance(comp.get("type"), str) else None,
                licenses=licenses,
                raw_path=f"components[{index}]",
                raw=comp,
            )
        )

    dependencies: list[DependencyEdge] = []
    for dep in doc.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        source = dep.get("ref")
        if not isinstance(source, str):
            continue
        for target in dep.get("dependsOn") or []:
            if isinstance(target, str):
                dependencies.append(DependencyEdge(source=source, target=target))

    return InternalSbom(
        spec="cyclonedx",
        spec_version=spec_version,
        metadata=md,
        components=components,
        dependencies=dependencies,
        declared_refs=declared_refs,
        signature_block=doc.get("signature") if isinstance(doc.get("signature"), dict) else None,
        raw_dict=doc,
    )


def normalize_spdx(doc: dict[str, Any], spec_version: str) -> InternalSbom:
    """Project a parsed SPDX 2.x dict into the internal model."""
    declared_refs: set[str] = set()
    components: list[Component] = []
    document_refs: set[str] = set()

    spdx_id = doc.get("SPDXID")
    if isinstance(spdx_id, str):
        declared_refs.add(spdx_id)

    creation_info = doc.get("creationInfo") or {}
    creators_field = creation_info.get("creators") or []
    creators = [c for c in creators_field if isinstance(c, str)]

    md = DocumentMetadata(
        document_namespace=doc.get("documentNamespace") if isinstance(doc.get("documentNamespace"), str) else None,
        serial_number=None,
        bom_version=None,
        spec_version=spec_version,
        data_license=doc.get("dataLicense") if isinstance(doc.get("dataLicense"), str) else None,
        name=doc.get("name") if isinstance(doc.get("name"), str) else None,
        creators=creators,
        created=creation_info.get("created") if isinstance(creation_info.get("created"), str) else None,
    )

    for ref_block in doc.get("externalDocumentRefs") or []:
        if isinstance(ref_block, dict):
            ext_id = ref_block.get("externalDocumentId")
            if isinstance(ext_id, str):
                document_refs.add(ext_id)

    for index, pkg in enumerate(doc.get("packages") or []):
        if not isinstance(pkg, dict):
            continue
        spdxid = pkg.get("SPDXID")
        if isinstance(spdxid, str):
            declared_refs.add(spdxid)
        purl = None
        cpe = None
        for ref in pkg.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            rtype = (ref.get("referenceType") or "").lower()
            locator = ref.get("referenceLocator")
            if rtype == "purl" and isinstance(locator, str):
                purl = locator
            elif "cpe" in rtype and isinstance(locator, str):
                cpe = locator

        hashes: list[dict[str, str]] = []
        for chk in pkg.get("checksums") or []:
            if isinstance(chk, dict):
                alg = chk.get("algorithm")
                value = chk.get("checksumValue")
                if isinstance(alg, str) and isinstance(value, str):
                    hashes.append({"alg": alg, "content": value})

        licenses: list[str] = []
        for key in ("licenseConcluded", "licenseDeclared"):
            value = pkg.get(key)
            if isinstance(value, str) and value not in ("NOASSERTION", "NONE"):
                licenses.append(value)

        components.append(
            Component(
                ref=str(spdxid) if isinstance(spdxid, str) else f"__pkg_{index}__",
                name=pkg.get("name") if isinstance(pkg.get("name"), str) else None,
                version=pkg.get("versionInfo") if isinstance(pkg.get("versionInfo"), str) else None,
                purl=purl,
                cpe=cpe,
                hashes=hashes,
                supplier=pkg.get("supplier") if isinstance(pkg.get("supplier"), str) else None,
                type="library",
                licenses=licenses,
                raw_path=f"packages[{index}]",
                raw=pkg,
            )
        )

    for file_block in doc.get("files") or []:
        if isinstance(file_block, dict) and isinstance(file_block.get("SPDXID"), str):
            declared_refs.add(file_block["SPDXID"])

    dependencies: list[DependencyEdge] = []
    for rel in doc.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        source = rel.get("spdxElementId")
        target = rel.get("relatedSpdxElement")
        kind = rel.get("relationshipType") or "RELATES_TO"
        if isinstance(source, str) and isinstance(target, str):
            dependencies.append(DependencyEdge(source=source, target=target, kind=kind))

    return InternalSbom(
        spec="spdx",
        spec_version=spec_version,
        metadata=md,
        components=components,
        dependencies=dependencies,
        declared_refs=declared_refs,
        document_refs=document_refs,
        signature_block=None,
        raw_dict=doc,
    )
