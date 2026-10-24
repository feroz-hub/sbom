"""Unit tests for stage 6 — depth-capped JSON decoder + walk.

The capped decoder itself is exercised from :mod:`stage 2 (detect)` — see
``test_stage_detect.py`` and the integration tests. The tests below cover
the post-parse walk that stage 6 owns directly: prototype-pollution keys
and oversized embedded blobs.
"""

from __future__ import annotations

import json

import pytest
from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.stages import security


def _run(doc: object, *, encoding: str = "json") -> ValidationContext:
    text = json.dumps(doc)
    ctx = ValidationContext(
        raw_bytes=text.encode(),
        text=text,
        encoding=encoding,
        parsed_dict=doc if isinstance(doc, dict) else None,
    )
    return security.run(ctx)


def test_capped_decoder_rejects_depth_bomb() -> None:
    """The decoder lives in stage 6's module but runs from stage 2."""
    nested: object = "leaf"
    for _ in range(80):
        nested = {"x": nested}
    text = json.dumps(nested)
    decoder = security._CappedJSONDecoder()
    with pytest.raises(security._CappedDecodeError) as exc_info:
        decoder.decode(text)
    assert exc_info.value.code == E.E080_JSON_DEPTH_EXCEEDED


def test_capped_decoder_rejects_array_length(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "MAX_ARRAY_LENGTH", 100)
    text = json.dumps({"x": list(range(200))})
    decoder = security._CappedJSONDecoder()
    with pytest.raises(security._CappedDecodeError) as exc_info:
        decoder.decode(text)
    assert exc_info.value.code == E.E081_JSON_ARRAY_LENGTH_EXCEEDED


def test_capped_decoder_rejects_string_length(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "MAX_STRING_LENGTH", 32)
    text = json.dumps({"x": "A" * 64})
    decoder = security._CappedJSONDecoder()
    with pytest.raises(security._CappedDecodeError) as exc_info:
        decoder.decode(text)
    assert exc_info.value.code == E.E082_JSON_STRING_LENGTH_EXCEEDED


def test_prototype_pollution_key_rejected() -> None:
    doc = {"a": {"__proto__": {"polluted": True}}}
    ctx = _run(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E087_PROTOTYPE_POLLUTION_KEY in codes


def test_constructor_key_rejected() -> None:
    doc = {"a": {"constructor": "x"}}
    ctx = _run(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E087_PROTOTYPE_POLLUTION_KEY in codes


def test_oversized_blob_rejected(monkeypatch) -> None:
    monkeypatch.setattr(security, "MAX_EMBEDDED_BLOB_BYTES", 16)
    doc = {"unknownField": "A" * 1024}
    ctx = _run(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E088_EMBEDDED_BLOB_TOO_LARGE in codes


def test_known_blob_field_allowed(monkeypatch) -> None:
    monkeypatch.setattr(security, "MAX_EMBEDDED_BLOB_BYTES", 16)
    doc = {"hashes": [{"alg": "SHA-256", "content": "A" * 64}]}
    ctx = _run(doc)
    codes = [e.code for e in ctx.report.errors]
    assert E.E088_EMBEDDED_BLOB_TOO_LARGE not in codes


def test_non_json_encoding_skips_decoder() -> None:
    """XML / tag-value paths skip the JSON-specific gating but still walk."""
    doc = {"a": 1}
    ctx = ValidationContext(
        raw_bytes=b"<bom/>",
        text="<bom/>",
        encoding="xml",
        parsed_dict=doc,
    )
    ctx2 = security.run(ctx)
    assert not ctx2.report.errors  # walk found nothing actionable
