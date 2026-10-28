"""Unit tests for stage 8 — signature (feature-flagged stub)."""

from __future__ import annotations

from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.models import DocumentMetadata, InternalSbom
from app.validation.stages import signature


def _model(*, with_signature: bool = False) -> InternalSbom:
    return InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        signature_block={"alg": "RS256", "value": "..."} if with_signature else None,
    )


def test_flag_off_runs_no_op() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=_model(with_signature=True), verify_signature=False)
    out = signature.run(ctx)
    assert not out.report.entries


def test_flag_on_no_signature_emits_w113() -> None:
    ctx = ValidationContext(raw_bytes=b"", internal_model=_model(), verify_signature=True)
    out = signature.run(ctx)
    codes = [e.code for e in out.report.entries]
    assert E.W113_SIGNATURE_NOT_PRESENT in codes


def test_flag_on_with_signature_emits_e110_until_implemented() -> None:
    ctx = ValidationContext(
        raw_bytes=b"",
        internal_model=_model(with_signature=True),
        verify_signature=True,
    )
    out = signature.run(ctx)
    codes = [e.code for e in out.report.errors]
    assert E.E110_SIGNATURE_INVALID in codes
