"""Property-based tests — Hypothesis strategies for SPDX / CycloneDX identifiers.

Every generated *invalid* form must be rejected; every generated *valid*
form must be accepted. The strategies are deliberately narrow — we are
exercising the validators, not the generators.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy

import pytest
from app.validation import errors as E
from app.validation import run as run_validation
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.property

_HYPOTHESIS = settings(
    max_examples=80,
    deadline=200,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)

_VALID_SPDXID_BODY = st.from_regex(r"^[a-zA-Z0-9.\-]{1,32}$", fullmatch=True)
_INVALID_SPDXID_BODY = st.text(min_size=1, max_size=32).filter(
    lambda s: not re.fullmatch(r"[a-zA-Z0-9.\-]+", s)
)


_BASE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test",
    "documentNamespace": "https://example.com/sboms/abc",
    "creationInfo": {"created": "2026-04-30T12:00:00Z", "creators": ["Tool: t"]},
    "packages": [
        {"SPDXID": "SPDXRef-Package", "name": "p", "versionInfo": "1.0.0",
         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
         "supplier": "Organization: ACME",
         "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0",
         "copyrightText": "NOASSERTION"}
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": "SPDXRef-Package"}
    ],
}


@_HYPOTHESIS
@given(body=_VALID_SPDXID_BODY)
def test_valid_spdxid_accepted(body: str) -> None:
    doc = deepcopy(_BASE_SPDX)
    doc["packages"][0]["SPDXID"] = f"SPDXRef-{body}"
    doc["relationships"][0]["relatedSpdxElement"] = f"SPDXRef-{body}"
    report = run_validation(json.dumps(doc).encode())
    codes = [e.code for e in report.errors]
    assert E.E040_SPDXID_MALFORMED not in codes


@_HYPOTHESIS
@given(body=_INVALID_SPDXID_BODY)
def test_invalid_spdxid_rejected(body: str) -> None:
    bad = f"SPDXRef-{body}"
    if re.fullmatch(r"SPDXRef-[a-zA-Z0-9.\-]+", bad):
        # Not a real bad case after sanitisation; skip.
        return
    doc = deepcopy(_BASE_SPDX)
    doc["packages"][0]["SPDXID"] = bad
    doc["relationships"][0]["relatedSpdxElement"] = bad
    report = run_validation(json.dumps(doc).encode())
    # Either the semantic check (E040) or the schema (E025/E026) rejects.
    codes = [e.code for e in report.errors]
    assert codes, f"{bad!r} produced no errors"


_BASE_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "version": 1,
    "metadata": {"timestamp": "2026-04-30T12:00:00Z", "tools": [{"name": "t"}]},
    "components": [
        {"type": "library", "bom-ref": "ref-a", "name": "a", "version": "1.0.0",
         "purl": "pkg:npm/a@1.0.0", "supplier": {"name": "ACME"}}
    ],
    "dependencies": [{"ref": "ref-a", "dependsOn": []}],
}


@_HYPOTHESIS
@given(
    purl_type=st.sampled_from(["npm", "pypi", "gem", "maven", "cargo", "nuget"]),
    name=st.from_regex(r"^[a-z][a-z0-9_\-]{0,15}$", fullmatch=True),
    version=st.from_regex(r"^\d+\.\d+\.\d+$", fullmatch=True),
)
def test_valid_purl_accepted(purl_type: str, name: str, version: str) -> None:
    doc = deepcopy(_BASE_CDX)
    purl = f"pkg:{purl_type}/{name}@{version}"
    doc["components"][0]["purl"] = purl
    report = run_validation(json.dumps(doc).encode())
    codes = [e.code for e in report.errors]
    assert E.E052_PURL_INVALID not in codes, (purl, codes)


@_HYPOTHESIS
@given(garbage=st.text(min_size=1, max_size=32).filter(lambda s: not s.startswith("pkg:")))
def test_invalid_purl_rejected(garbage: str) -> None:
    doc = deepcopy(_BASE_CDX)
    doc["components"][0]["purl"] = garbage
    report = run_validation(json.dumps(doc).encode())
    codes = [e.code for e in report.errors]
    # Either schema (E025) or semantic (E052) rejects malformed PURLs.
    assert codes, f"{garbage!r} produced no errors"


@_HYPOTHESIS
@given(uuid=st.from_regex(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", fullmatch=True))
def test_valid_serial_number_accepted(uuid: str) -> None:
    doc = deepcopy(_BASE_CDX)
    doc["serialNumber"] = f"urn:uuid:{uuid}"
    report = run_validation(json.dumps(doc).encode())
    codes = [e.code for e in report.errors]
    assert E.E050_SERIAL_NUMBER_INVALID not in codes


@_HYPOTHESIS
@given(garbage=st.text(min_size=1, max_size=64).filter(lambda s: not s.startswith("urn:uuid:")))
def test_invalid_serial_number_rejected(garbage: str) -> None:
    doc = deepcopy(_BASE_CDX)
    doc["serialNumber"] = garbage
    report = run_validation(json.dumps(doc).encode())
    codes = [e.code for e in report.errors]
    # Either schema (E025) or semantic (E050) rejects malformed serials.
    assert codes, f"{garbage!r} produced no errors"
