"""
Identifier classifier — focused unit tests.

This module is small and load-bearing (every modal request flows through
``classify``); we exercise every accepted format, every canonicalisation
quirk, and every UNKNOWN edge case.
"""

from __future__ import annotations

import pytest
from app.integrations.cve.identifiers import SUPPORTED_FORMATS, IdKind, classify, resolve


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


# --------------------------------------------------------------------------- #
# resolve() — canonical-id resolution (source-prefixed aliases, alias reuse). #
# Kept in lockstep with the frontend ``resolveVulnId`` parity block in         #
# ``frontend/src/lib/vulnIds.test.ts``.                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw,expected_kind,expected_norm",
    [
        # Debian source-prefixed alias → embedded canonical CVE (the bug).
        ("DEBIAN-CVE-2011-3374", IdKind.CVE, "CVE-2011-3374"),
        ("debian-cve-2011-3374", IdKind.CVE, "CVE-2011-3374"),  # lowercase
        ("  DEBIAN-CVE-2011-3374  ", IdKind.CVE, "CVE-2011-3374"),  # whitespace
        ("UBUNTU-CVE-2020-1234", IdKind.CVE, "CVE-2020-1234"),
        # Canonical ids are preserved unchanged.
        ("CVE-2011-3374", IdKind.CVE, "CVE-2011-3374"),
        ("GHSA-jfh8-c2jp-5v3q", IdKind.GHSA, "GHSA-jfh8-c2jp-5v3q"),
        ("PYSEC-2024-1", IdKind.PYSEC, "PYSEC-2024-1"),
        ("RUSTSEC-2023-0044", IdKind.RUSTSEC, "RUSTSEC-2023-0044"),
        ("GO-2023-1234", IdKind.GO, "GO-2023-1234"),
        # Genuinely unsupported → controlled UNKNOWN, never raises.
        ("FOOBAR-123", IdKind.UNKNOWN, "FOOBAR-123"),
        ("", IdKind.UNKNOWN, ""),
    ],
)
def test_resolve_without_aliases(raw: str, expected_kind: IdKind, expected_norm: str):
    vid = resolve(raw)
    assert vid.kind == expected_kind, f"{raw!r} → {vid.kind}, expected {expected_kind}"
    assert vid.normalized == expected_norm
    # Original id is always preserved for display / provenance.
    assert vid.raw == raw


def test_resolve_reuses_cve_from_aliases():
    """A CVE already merged into aliases is reused even when the raw id itself
    carries no embedded CVE (not just prefix stripping)."""
    vid = resolve("DLA-1234-1", aliases=["GHSA-xxxx-yyyy-zzzz", "CVE-2011-3374"])
    assert vid.kind == IdKind.CVE
    assert vid.normalized == "CVE-2011-3374"
    assert vid.raw == "DLA-1234-1"


def test_resolve_prefers_cve_alias_over_prefix_strip():
    """When both an alias CVE and a strippable prefix are available, the merged
    alias is used (reuse-first, per the dedup pipeline)."""
    vid = resolve("DEBIAN-CVE-2011-3374", aliases=["CVE-2011-3374"])
    assert vid.kind == IdKind.CVE
    assert vid.normalized == "CVE-2011-3374"


def test_resolve_prefers_explicit_canonical_id():
    vid = resolve("DEBIAN-CVE-2011-3374", canonical_id="CVE-2011-3374")
    assert vid.kind == IdKind.CVE
    assert vid.normalized == "CVE-2011-3374"


def test_resolve_handles_non_string_input():
    vid = resolve(12345)  # type: ignore[arg-type]
    assert vid.kind == IdKind.UNKNOWN
