"""Unit tests for stage 4 — semantic SPDX 2.x and CycloneDX."""

from __future__ import annotations

import json
from copy import deepcopy

from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.stages import semantic_cyclonedx, semantic_spdx, semantic_spdx3

# ---------------------------------------------------------------------------
# SPDX
# ---------------------------------------------------------------------------

_SPDX_VALID = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test",
    "documentNamespace": "https://example.com/sboms/abc",
    "creationInfo": {
        "created": "2026-04-30T12:00:00Z",
        "creators": ["Tool: tests"],
    },
    "packages": [
        {"SPDXID": "SPDXRef-Package", "name": "x", "versionInfo": "1.0.0",
         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
         "supplier": "Organization: ACME",
         "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0",
         "copyrightText": "NOASSERTION",
         "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}]}
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": "SPDXRef-Package"}
    ],
}


def _spdx(doc: dict) -> ValidationContext:
    ctx = ValidationContext(
        raw_bytes=json.dumps(doc).encode(),
        text=json.dumps(doc),
        spec="spdx",
        spec_version="SPDX-2.3",
        encoding="json",
        parsed_dict=doc,
    )
    return semantic_spdx.run(ctx)


def test_spdx_valid_minimal() -> None:
    ctx = _spdx(deepcopy(_SPDX_VALID))
    codes = [e.code for e in ctx.report.errors]
    assert codes == []


def test_spdx_bad_spdxid_rejected() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["packages"][0]["SPDXID"] = "BAD-Package"
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E040_SPDXID_MALFORMED in codes


def test_spdx_data_license_rejected() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["dataLicense"] = "Apache-2.0"
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E042_DATA_LICENSE_INVALID in codes


def test_spdx_namespace_with_fragment_rejected() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["documentNamespace"] = "https://example.com/sboms/abc#frag"
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E041_DOCUMENT_NAMESPACE_INVALID in codes


def test_spdx_created_without_z_rejected() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["creationInfo"]["created"] = "2026-04-30 12:00:00"
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E045_CREATED_TIMESTAMP_INVALID in codes


def test_spdx_checksum_length_mismatch() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["packages"][0]["checksums"] = [{"algorithm": "SHA256", "checksumValue": "abc"}]
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E044_CHECKSUM_LENGTH_MISMATCH in codes


def test_spdx_missing_describes_relationship() -> None:
    doc = deepcopy(_SPDX_VALID)
    doc["relationships"] = []
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E046_DESCRIBES_RELATIONSHIP_MISSING in codes


def test_spdx_documentDescribes_satisfies_describes() -> None:
    """SPDX 2.2 short-form ``documentDescribes`` is treated as DESCRIBES."""
    doc = deepcopy(_SPDX_VALID)
    doc["relationships"] = []
    doc["documentDescribes"] = ["SPDXRef-Package"]
    ctx = _spdx(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E046_DESCRIBES_RELATIONSHIP_MISSING not in codes


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

_CDX_VALID = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {"timestamp": "2026-04-30T12:00:00Z", "tools": [{"name": "test"}]},
    "components": [
        {"type": "library", "bom-ref": "pkg:npm/foo@1.0.0", "name": "foo",
         "version": "1.0.0", "purl": "pkg:npm/foo@1.0.0",
         "supplier": {"name": "ACME"}}
    ],
    "dependencies": [{"ref": "pkg:npm/foo@1.0.0", "dependsOn": []}],
}


def _cdx(doc: dict) -> ValidationContext:
    ctx = ValidationContext(
        raw_bytes=json.dumps(doc).encode(),
        text=json.dumps(doc),
        spec="cyclonedx",
        spec_version="1.6",
        encoding="json",
        parsed_dict=doc,
    )
    return semantic_cyclonedx.run(ctx)


def test_cdx_valid_minimal() -> None:
    ctx = _cdx(deepcopy(_CDX_VALID))
    assert [e.code for e in ctx.report.errors] == []


def test_cdx_serial_number_invalid_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["serialNumber"] = "not-a-urn"
    ctx = _cdx(doc)
    assert E.E050_SERIAL_NUMBER_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_duplicate_bom_ref_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["components"].append(deepcopy(doc["components"][0]))
    ctx = _cdx(doc)
    assert E.E051_BOM_REF_DUPLICATE in [e.code for e in ctx.report.errors]


def test_cdx_bad_purl_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["components"][0]["purl"] = "garbage"
    ctx = _cdx(doc)
    assert E.E052_PURL_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_bad_cpe_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["components"][0]["cpe"] = "cpe:1.0:bad"
    ctx = _cdx(doc)
    assert E.E053_CPE_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_negative_bom_version_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["version"] = -1
    ctx = _cdx(doc)
    assert E.E055_BOM_VERSION_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_bad_metadata_timestamp_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["metadata"]["timestamp"] = "not-a-timestamp"
    ctx = _cdx(doc)
    assert E.E056_METADATA_TIMESTAMP_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_bad_component_type_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["components"][0]["type"] = "not-a-type"
    ctx = _cdx(doc)
    assert E.E057_COMPONENT_TYPE_INVALID in [e.code for e in ctx.report.errors]


def test_cdx_hash_length_mismatch_rejected() -> None:
    doc = deepcopy(_CDX_VALID)
    doc["components"][0]["hashes"] = [{"alg": "SHA-256", "content": "deadbeef"}]
    ctx = _cdx(doc)
    assert E.E054_HASH_LENGTH_MISMATCH in [e.code for e in ctx.report.errors]


# ---------------------------------------------------------------------------
# SPDX 3.0 (deferred — should always reject with E013)
# ---------------------------------------------------------------------------


def test_spdx3_always_rejects() -> None:
    ctx = ValidationContext(raw_bytes=b"{}", text="{}", spec="spdx", spec_version="3.0", encoding="json")
    out = semantic_spdx3.run(ctx)
    assert E.E013_SPEC_VERSION_UNSUPPORTED in [e.code for e in out.report.errors]
