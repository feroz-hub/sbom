"""
Identifier classifier — focused unit tests.

This module is small and load-bearing (every modal request flows through
``classify``); we exercise every accepted format, every canonicalisation
quirk, and every UNKNOWN edge case.
"""

from __future__ import annotations

import pytest

from app.integrations.cve.identifiers import IdKind, SUPPORTED_FORMATS, classify


@pytest.mark.parametrize(
    "raw,expected_kind,expected_norm",
    [
        # CVE — uppercased.
        ("CVE-2021-44228", IdKind.CVE, "CVE-2021-44228"),
        ("cve-2021-44228", IdKind.CVE, "CVE-2021-44228"),
        ("Cve-2024-1", IdKind.UNKNOWN, "Cve-2024-1"),  # too short — must NOT match CVE
        ("CVE-2024-12345", IdKind.CVE, "CVE-2024-12345"),
        # GHSA — head upper, body lower.
        ("GHSA-jfh8-c2jp-5v3q", IdKind.GHSA, "GHSA-jfh8-c2jp-5v3q"),
        ("ghsa-JFH8-C2JP-5V3Q", IdKind.GHSA, "GHSA-jfh8-c2jp-5v3q"),
        ("GHSA-JFH8-C2JP-5V3Q", IdKind.GHSA, "GHSA-jfh8-c2jp-5v3q"),
        # PYSEC.
        ("PYSEC-2024-1", IdKind.PYSEC, "PYSEC-2024-1"),
        ("pysec-2024-99999", IdKind.PYSEC, "PYSEC-2024-99999"),
        # RUSTSEC.
        ("RUSTSEC-2023-0044", IdKind.RUSTSEC, "RUSTSEC-2023-0044"),
        ("rustsec-2023-0044", IdKind.RUSTSEC, "RUSTSEC-2023-0044"),
        # GO advisories.
        ("GO-2023-1234", IdKind.GO, "GO-2023-1234"),
        ("GO-2024-12345678", IdKind.GO, "GO-2024-12345678"),
        # Whitespace at the edges is tolerated.
        ("  CVE-2024-12345  ", IdKind.CVE, "CVE-2024-12345"),
        ("\tGHSA-jfh8-c2jp-5v3q\n", IdKind.GHSA, "GHSA-jfh8-c2jp-5v3q"),
        # Garbage.
        ("FOOBAR-123", IdKind.UNKNOWN, "FOOBAR-123"),
        ("GHSA-too-short", IdKind.UNKNOWN, "GHSA-too-short"),
        ("GHSA-1234-5678", IdKind.UNKNOWN, "GHSA-1234-5678"),  # missing third group
        ("CVE-2024", IdKind.UNKNOWN, "CVE-2024"),
        ("", IdKind.UNKNOWN, ""),
        ("   ", IdKind.UNKNOWN, ""),
    ],
)
def test_classify(raw: str, expected_kind: IdKind, expected_norm: str):
    vid = classify(raw)
    assert vid.kind == expected_kind, f"{raw!r} → {vid.kind}, expected {expected_kind}"
    assert vid.normalized == expected_norm
    # raw is preserved verbatim (modulo nothing — even whitespace stays).
    assert vid.raw == raw


def test_classify_rejects_unicode_lookalikes():
    """Cyrillic Е (U+0415) instead of Latin E — must NOT match CVE."""
    vid = classify("CVЕ-2024-12345")
    assert vid.kind == IdKind.UNKNOWN


def test_classify_handles_non_string_input():
    """Defensive: non-str inputs (e.g. accidental ints) become UNKNOWN."""
    vid = classify(12345)  # type: ignore[arg-type]
    assert vid.kind == IdKind.UNKNOWN


def test_supported_formats_advertises_all_kinds():
    """Error envelopes ship the SUPPORTED_FORMATS tuple to the client; if
    we add a new IdKind we want this list to grow with it (modulo the
    UNKNOWN sentinel + OSV_GENERIC which is opportunistic, not user-facing)."""
    user_facing = {k for k in IdKind} - {IdKind.UNKNOWN, IdKind.OSV_GENERIC}
    assert len(SUPPORTED_FORMATS) == len(user_facing)
