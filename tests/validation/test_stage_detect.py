"""Unit tests for stage 2 — format & version detection."""

from __future__ import annotations

import json

from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.stages import detect


def _run(text: str) -> ValidationContext:
    ctx = ValidationContext(raw_bytes=text.encode(), text=text)
    return detect.run(ctx)


def test_cyclonedx_json_detected() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    ctx = _run(json.dumps(doc))
    assert ctx.spec == "cyclonedx"
    assert ctx.spec_version == "1.6"
    assert ctx.encoding == "json"
    assert not ctx.report.has_errors()


def test_spdx_json_detected() -> None:
    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
    ctx = _run(json.dumps(doc))
    assert ctx.spec == "spdx"
    assert ctx.spec_version == "SPDX-2.3"
    assert ctx.encoding == "json"


def test_ambiguous_rejected() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "spdxVersion": "SPDX-2.3"}
    ctx = _run(json.dumps(doc))
    assert ctx.report.entries[0].code == E.E011_FORMAT_AMBIGUOUS


def test_format_indeterminate_text() -> None:
    ctx = _run("hello world")
    assert ctx.report.entries[0].code == E.E010_FORMAT_INDETERMINATE


def test_unsupported_cyclonedx_version() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.99"}
    ctx = _run(json.dumps(doc))
    assert ctx.report.entries[0].code == E.E013_SPEC_VERSION_UNSUPPORTED


def test_missing_cyclonedx_spec_version() -> None:
    doc = {"bomFormat": "CycloneDX"}
    ctx = _run(json.dumps(doc))
    assert ctx.report.entries[0].code == E.E014_SPEC_VERSION_MISSING


def test_spdx_3_0_rejected() -> None:
    doc = {"@graph": [], "@context": "https://spdx.org/3.0"}
    ctx = _run(json.dumps(doc))
    assert ctx.report.entries[0].code == E.E013_SPEC_VERSION_UNSUPPORTED


def test_cyclonedx_xml_namespace_detected() -> None:
    xml = (
        '<?xml version="1.0"?>\n'
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1"></bom>'
    )
    ctx = _run(xml)
    assert ctx.spec == "cyclonedx"
    assert ctx.spec_version == "1.5"
    assert ctx.encoding == "xml"


def test_xml_unknown_namespace_rejected() -> None:
    xml = '<?xml version="1.0"?>\n<bom xmlns="http://example.com/foo"></bom>'
    ctx = _run(xml)
    assert ctx.report.entries[0].code == E.E010_FORMAT_INDETERMINATE


def test_spdx_tagvalue_detected() -> None:
    text = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n"
    ctx = _run(text)
    assert ctx.spec == "spdx"
    assert ctx.spec_version == "SPDX-2.3"
    assert ctx.encoding == "tag-value"


def test_top_level_json_array_rejected() -> None:
    ctx = _run("[1,2,3]")
    assert ctx.report.entries[0].code == E.E010_FORMAT_INDETERMINATE


def test_malformed_json_reports_parse_error() -> None:
    ctx = _run("{not json")
    assert ctx.report.entries[0].code == E.E020_JSON_PARSE_FAILED


def test_empty_after_strip() -> None:
    ctx = _run("    \n\n  ")
    assert ctx.report.entries[0].code == E.E005_EMPTY_BODY
