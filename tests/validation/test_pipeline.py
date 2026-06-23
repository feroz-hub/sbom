"""Pipeline-level unit tests — orchestration / short-circuit / dispatch."""

from __future__ import annotations

import json

from app.validation import errors as E
from app.validation import run as run_validation
from app.validation.context import ValidationContext
from app.validation.errors import ErrorReport
from app.validation.pipeline import _CallableStage, default_stages


def test_default_stages_have_canonical_names() -> None:
    names = [s.name for s in default_stages()]
    assert names == [
        "ingress",
        "detect",
        "schema",
        "semantic",
        "integrity",
        "security",
        "ntia",
        "signature",
    ]


def test_short_circuit_after_error() -> None:
    """Stages with skip_on_errors=True must not run after a prior error."""

    visited: list[str] = []

    def make(name: str, *, skip: bool = True):
        def _run(ctx: ValidationContext) -> ValidationContext:
            visited.append(name)
            return ctx

        return _CallableStage(name, _run, skip_on_errors=skip)

    pipeline = [
        _CallableStage("seed", lambda c: _emit_error(c), skip_on_errors=False),
        make("a"),
        make("ntia", skip=False),
        make("b"),
    ]
    report = run_validation(b"x", stages=pipeline)
    assert report.has_errors()
    # a, b must NOT have run; ntia must have run.
    assert visited == ["ntia"]


def _emit_error(ctx: ValidationContext) -> ValidationContext:
    ctx.report.add(
        E.E025_SCHEMA_VIOLATION,
        stage="seed",
        path="",
        message="seed",
        remediation="r",
    )
    return ctx


def test_uncaught_stage_exception_mapped_to_e025() -> None:
    """A stage that raises must produce a stable E025 entry, not a 500."""

    def boom(ctx: ValidationContext) -> ValidationContext:
        raise RuntimeError("unexpected")

    report = run_validation(
        b"{}",
        stages=[_CallableStage("ingress", lambda c: c, skip_on_errors=False), _CallableStage("explode", boom)],
    )
    assert isinstance(report, ErrorReport)
    assert E.E025_SCHEMA_VIOLATION in [e.code for e in report.errors]


def test_cyclonedx_1_6_clean_file_validates(read_fixture) -> None:
    # Regression: Stage 3 hardcoded Draft202012Validator, which crashed on
    # CycloneDX's draft-07 tuple-form `items` ('list' object has no attribute
    # 'get' inside referencing), and the orchestrator wrapped the crash as a
    # generic E025 "Internal validator error". A clean 1.6 file must validate.
    raw = read_fixture("valid/cyclonedx_1_6_clean.json")
    report = run_validation(raw)
    error_codes = [e.code for e in report.errors]
    assert not report.has_errors(), error_codes
    assert E.E025_SCHEMA_VIOLATION not in error_codes


def test_cyclonedx_license_id_ref_resolves_offline() -> None:
    """Regression: CycloneDX BOM schemas $ref spdx.schema.json for license ids.

    Without the vendored SPDX enum registered in the validator registry,
    documents that use ``license.id`` (e.g. normalized export) crash schema
    validation with an internal E025 instead of a real violation report.
    """
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "version": 1,
        "metadata": {"timestamp": "2026-04-30T12:00:00Z"},
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:npm/lodash@4.17.21",
                "name": "lodash",
                "version": "4.17.21",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
    }
    report = run_validation(json.dumps(doc).encode())
    error_codes = [e.code for e in report.errors]
    assert E.E025_SCHEMA_VIOLATION not in error_codes or "Internal validator error" not in (
        e.message for e in report.errors
    )
    assert not any("Internal validator error" in e.message for e in report.errors)


def test_dispatcher_routes_spdx_2_x_to_semantic_spdx() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "x",
        "documentNamespace": "https://example.com/sboms/x",
        "creationInfo": {"created": "2026-04-30T12:00:00Z", "creators": ["Tool: t"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": "p",
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "Organization: ACME",
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            }
        ],
    }
    report = run_validation(json.dumps(doc).encode())
    assert not report.has_errors(), [e.code for e in report.entries[:5]]
