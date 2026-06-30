from __future__ import annotations

import json

from app.services.sbom.format_detector import detect_sbom_format


def test_detects_spdx_json_with_spdx_version() -> None:
    result = detect_sbom_format(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [],
            }
        )
    )

    assert result.format == "spdx_json"
    assert result.spec_version == "SPDX-2.3"
    assert result.confidence == 0.99


def test_detects_cyclonedx_json_with_bom_format() -> None:
    result = detect_sbom_format(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [],
            }
        )
    )

    assert result.format == "cyclonedx_json"
    assert result.spec_version == "1.4"


def test_detects_spdx_tag_value() -> None:
    result = detect_sbom_format("SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\n")

    assert result.format == "spdx_tag_value"
    assert result.spec_version == "SPDX-2.3"


def test_detects_cyclonedx_xml() -> None:
    result = detect_sbom_format('<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"></bom>')

    assert result.format == "cyclonedx_xml"


def test_unknown_json_does_not_default_to_cyclonedx() -> None:
    result = detect_sbom_format('{"ok": false, "dependencyCount": 10052}')

    assert result.format == "unknown"
    assert result.confidence == 0.0
