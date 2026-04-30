"""
Vulnerability identifier classifier.

Single source of truth for which formats we accept and how each is
canonicalised. Each ``CveSource`` declares an ``accepted_kinds`` set; the
orchestrator filters sources by that set before fan-out, so NVD never sees
a GHSA-* id, OSV gets every supported kind, and so on.

Adding support for a new format is one regex addition here plus a list
update on the relevant source clients — no orchestrator changes needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class IdKind(str, Enum):
    """Canonical advisory identifier families."""

    CVE = "cve"
    GHSA = "ghsa"
    PYSEC = "pysec"
    RUSTSEC = "rustsec"
    GO = "go"
    OSV_GENERIC = "osv_generic"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VulnId:
    """Classifier output. ``raw`` preserves user input (logs / error responses); ``normalized`` is what every downstream consumer keys on."""

    raw: str
    normalized: str
    kind: IdKind


# Anchored, case-insensitive matchers. Order is significant only insofar as
# every prefix is unambiguous — there's no overlap, so first match wins.
_PATTERNS: list[tuple[IdKind, re.Pattern[str]]] = [
    (IdKind.CVE, re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)),
    (IdKind.GHSA, re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)),
    (IdKind.PYSEC, re.compile(r"^PYSEC-\d{4}-\d+$", re.IGNORECASE)),
    (IdKind.RUSTSEC, re.compile(r"^RUSTSEC-\d{4}-\d{4}$", re.IGNORECASE)),
    (IdKind.GO, re.compile(r"^GO-\d{4}-\d{4,}$", re.IGNORECASE)),
]

#: Stable list for error responses ("supported_formats" payload).
SUPPORTED_FORMATS: tuple[str, ...] = (
    "CVE-YYYY-NNNN",
    "GHSA-xxxx-xxxx-xxxx",
    "PYSEC-YYYY-N",
    "RUSTSEC-YYYY-NNNN",
    "GO-YYYY-NNNN",
)


def classify(raw: str) -> VulnId:
    """Classify ``raw`` into a :class:`VulnId`.

    Whitespace is stripped at the boundary; non-string input yields UNKNOWN
    so callers can branch off ``vid.kind`` without isinstance() guards. The
    returned ``raw`` field preserves whatever the caller passed (minus
    leading/trailing whitespace) — it's what we echo back in error
    envelopes and structured logs.
    """
    if not isinstance(raw, str):
        return VulnId(raw=str(raw), normalized=str(raw), kind=IdKind.UNKNOWN)
    s = raw.strip()
    if not s:
        return VulnId(raw=raw, normalized="", kind=IdKind.UNKNOWN)
    for kind, pat in _PATTERNS:
        if pat.match(s):
            return VulnId(raw=raw, normalized=_canonicalize(s, kind), kind=kind)
    return VulnId(raw=raw, normalized=s, kind=IdKind.UNKNOWN)


def _canonicalize(s: str, kind: IdKind) -> str:
    """Return the form every downstream component keys on."""
    if kind == IdKind.CVE:
        return s.upper()
    if kind == IdKind.GHSA:
        head, *rest = s.split("-")
        return "-".join([head.upper(), *(seg.lower() for seg in rest)])
    # PYSEC / RUSTSEC / GO / OSV_GENERIC: uppercase prefix + payload.
    return s.upper()
