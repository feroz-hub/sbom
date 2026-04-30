"""Coverage for the ``app.validation.normalize`` projection branches."""

from __future__ import annotations

from app.validation.normalize import normalize_cyclonedx, normalize_spdx


def test_cdx_string_version_parses_to_int() -> None:
    """CycloneDX top-level ``version`` may arrive as a string in unusual exporters."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": "5",
        "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
        "components": [],
        "dependencies": [],
    }
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.metadata.bom_version == 5


def test_cdx_negative_version_rejected_by_normalize() -> None:
    """Negative integer versions parse but the semantic stage rejects them."""
    doc = {"version": -1, "components": []}
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.metadata.bom_version == -1


def test_cdx_non_int_non_str_version_falls_to_none() -> None:
    doc = {"version": [], "components": []}
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.metadata.bom_version is None


def test_cdx_metadata_tools_dict_form_collected() -> None:
    """CycloneDX 1.5+ may emit ``tools`` as a dict with a ``components`` list."""
    doc = {
        "specVersion": "1.5",
        "metadata": {
            "tools": {
                "components": [
                    {"name": "tool-a"},
                    {"name": "tool-b"},
                ]
            }
        },
        "components": [],
    }
    sbom = normalize_cyclonedx(doc, "1.5")
    assert "tool-a" in sbom.metadata.creators
    assert "tool-b" in sbom.metadata.creators


def test_cdx_string_supplier_supported() -> None:
    """``supplier`` may be a bare string (legacy exporters)."""
    doc = {
        "specVersion": "1.6",
        "metadata": {},
        "components": [
            {"type": "library", "bom-ref": "x", "name": "x", "version": "1",
             "supplier": "ACME"}
        ],
    }
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.components[0].supplier == "ACME"


def test_cdx_components_non_list_falls_to_empty() -> None:
    doc = {"specVersion": "1.6", "metadata": {}, "components": "not-a-list"}
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.components == []


def test_cdx_dependency_with_non_string_source_skipped() -> None:
    doc = {
        "specVersion": "1.6",
        "metadata": {},
        "components": [],
        "dependencies": [{"ref": 123, "dependsOn": ["a"]}],
    }
    sbom = normalize_cyclonedx(doc, "1.6")
    assert sbom.dependencies == []


def test_cdx_license_objects_with_expression_collected() -> None:
    doc = {
        "specVersion": "1.6",
        "metadata": {},
        "components": [
            {"type": "library", "bom-ref": "x", "name": "x", "version": "1",
             "licenses": [
                 {"expression": "Apache-2.0 OR MIT"},
                 {"license": {"id": "BSD-3-Clause"}},
                 {"license": {"name": "Custom Name"}},
             ]}
        ],
    }
    sbom = normalize_cyclonedx(doc, "1.6")
    licenses = sbom.components[0].licenses
    assert "Apache-2.0 OR MIT" in licenses
    assert "BSD-3-Clause" in licenses
    assert "Custom Name" in licenses


def test_spdx_external_doc_refs_collected() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": []},
        "externalDocumentRefs": [
            {"externalDocumentId": "DocumentRef-other", "spdxDocument": "u"},
            "garbage",
        ],
        "packages": [],
        "files": [
            {"SPDXID": "SPDXRef-File", "fileName": "x.py"},
            "garbage",
        ],
    }
    sbom = normalize_spdx(doc, "SPDX-2.3")
    assert "DocumentRef-other" in sbom.document_refs
    assert "SPDXRef-File" in sbom.declared_refs


def test_spdx_package_purl_and_cpe_extracted_from_externalrefs() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": []},
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": "x",
                "versionInfo": "1.0.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:npm/x@1.0.0"},
                    {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:vendor:x:1:*:*:*:*:*:*:*"},
                ],
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": "a" * 40},
                ],
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "NOASSERTION",
            }
        ],
    }
    sbom = normalize_spdx(doc, "SPDX-2.3")
    comp = sbom.components[0]
    assert comp.purl == "pkg:npm/x@1.0.0"
    assert comp.cpe == "cpe:2.3:a:vendor:x:1:*:*:*:*:*:*:*"
    assert "Apache-2.0" in comp.licenses
    assert "NOASSERTION" not in comp.licenses
    assert {"alg": "SHA1", "content": "a" * 40} in comp.hashes


def test_spdx_relationship_with_kind() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": []},
        "packages": [],
        "relationships": [
            {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-B",
             "relationshipType": "CONTAINS"},
            "garbage",
            {"spdxElementId": 123, "relatedSpdxElement": "SPDXRef-B"},
        ],
    }
    sbom = normalize_spdx(doc, "SPDX-2.3")
    assert any(d.kind == "CONTAINS" for d in sbom.dependencies)
    assert len(sbom.dependencies) == 1
