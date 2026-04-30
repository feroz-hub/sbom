"""Unit tests for stage 1 — ingress guard."""

from __future__ import annotations

import gzip

import pytest
from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.stages import ingress


def _run(body: bytes, *, content_encoding: str | None = None) -> ValidationContext:
    ctx = ValidationContext(raw_bytes=body, content_encoding=content_encoding)
    return ingress.run(ctx)


def test_empty_body_rejected() -> None:
    ctx = _run(b"")
    assert ctx.report.entries[0].code == E.E005_EMPTY_BODY


def test_size_exceeded_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ingress,
        "_load_limits",
        lambda: {"max_upload": 16, "max_decompressed": 1024, "max_ratio": 100},
    )
    ctx = _run(b"a" * 32)
    assert ctx.report.entries[0].code == E.E001_SIZE_EXCEEDED


def test_utf16_bom_rejected() -> None:
    ctx = _run(b"\xff\xfe<bom xmlns=\"...\"/>")
    assert ctx.report.entries[0].code == E.E004_ENCODING_NOT_UTF8


def test_utf8_bom_stripped() -> None:
    ctx = _run(b"\xef\xbb\xbf{\"a\": 1}")
    assert not ctx.report.has_errors()
    assert ctx.text == '{"a": 1}'


def test_invalid_utf8_rejected() -> None:
    ctx = _run(b"\xc3\x28")  # invalid UTF-8 sequence
    assert ctx.report.entries[0].code == E.E004_ENCODING_NOT_UTF8


def test_unsupported_encoding_rejected() -> None:
    ctx = _run(b"x", content_encoding="brotli")
    assert ctx.report.entries[0].code == E.E006_UNSUPPORTED_COMPRESSION


def test_gzip_decompression_succeeds() -> None:
    raw = b"{\"bomFormat\": \"CycloneDX\"}"
    ctx = _run(gzip.compress(raw), content_encoding="gzip")
    assert not ctx.report.has_errors()
    assert ctx.text == raw.decode()


def test_gzip_decompression_ratio_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ingress,
        "_load_limits",
        lambda: {"max_upload": 100 * 1024, "max_decompressed": 200 * 1024 * 1024, "max_ratio": 5},
    )
    huge = b"A" * (1024 * 1024)
    small = gzip.compress(huge)
    ctx = _run(small, content_encoding="gzip")
    codes = [e.code for e in ctx.report.entries]
    assert E.E003_DECOMPRESSION_RATIO_EXCEEDED in codes


def test_decompressed_size_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ingress,
        "_load_limits",
        lambda: {"max_upload": 100 * 1024 * 1024, "max_decompressed": 4 * 1024, "max_ratio": 100_000},
    )
    huge = b"A" * (1024 * 1024)
    small = gzip.compress(huge)
    ctx = _run(small, content_encoding="gzip")
    codes = [e.code for e in ctx.report.entries]
    assert E.E002_DECOMPRESSED_SIZE_EXCEEDED in codes
