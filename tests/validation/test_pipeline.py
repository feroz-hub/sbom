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


def test_dispatcher_routes_spdx_2_x_to_semantic_spdx() -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "x",
        "documentNamespace": "https://example.com/sboms/x",
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
    report = run_validation(json.dumps(doc).encode())
    assert not report.has_errors(), [e.code for e in report.entries[:5]]
