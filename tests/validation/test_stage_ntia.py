"""Unit tests for stage 7 — NTIA minimum elements."""

from __future__ import annotations

from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.errors import Severity
from app.validation.models import (
    Component,
    DependencyEdge,
    DocumentMetadata,
    InternalSbom,
)
from app.validation.stages import ntia


def _model(*, with_supplier: bool = True, with_creator: bool = True, with_deps: bool = True) -> InternalSbom:
    md = DocumentMetadata(
        spec_version="1.6",
        creators=["Tool: tests"] if with_creator else [],
        created="2026-04-30T12:00:00Z",
    )
    comp = Component(
        ref="a",
        name="a",
        version="1.0.0",
        purl="pkg:npm/a@1.0.0",
        supplier="ACME" if with_supplier else None,
        raw_path="components[0]",
    )
    deps = [DependencyEdge(source="a", target="a")] if with_deps else []
    return InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=md,
        components=[comp],
        dependencies=deps,
        declared_refs={"a"},
    )


def test_complete_sbom_emits_no_warnings() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=_model())
    out = ntia.run(ctx)
    assert not out.report.warnings


def test_missing_supplier_emits_warning() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=_model(with_supplier=False))
    out = ntia.run(ctx)
    codes = [e.code for e in out.report.warnings]
    assert E.W100_NTIA_SUPPLIER_MISSING in codes


def test_missing_dependency_relationship_emits_warning() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=_model(with_deps=False))
    out = ntia.run(ctx)
    codes = [e.code for e in out.report.warnings]
    assert E.W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING in codes


def test_strict_mode_promotes_to_errors() -> None:
    ctx = ValidationContext(
        raw_bytes=b"",
        strict_ntia=True,
        internal_model=_model(with_supplier=False),
    )
    out = ntia.run(ctx)
    assert out.report.has_errors()
    err_codes = [e.code for e in out.report.errors]
    assert E.W100_NTIA_SUPPLIER_MISSING in err_codes
    # Severity reflects the promotion.
    err = next(e for e in out.report.errors if e.code == E.W100_NTIA_SUPPLIER_MISSING)
    assert err.severity is Severity.ERROR


def test_skips_when_no_internal_model() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=None)
    out = ntia.run(ctx)
    assert not out.report.entries
