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
from collections.abc import Iterable
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

#: A source-specific advisory alias that wraps a canonical CVE, e.g. the
#: Debian Security Tracker's ``DEBIAN-CVE-2011-3374`` (also ``UBUNTU-CVE-…``,
#: ``SUSE-CVE-…``). :func:`resolve` strips the prefix to the embedded CVE so
#: the modal, cache and upstream lookups key on one id — the original alias is
#: preserved on ``VulnId.raw`` for display and provenance.
_SOURCE_PREFIXED_CVE: re.Pattern[str] = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*-(CVE-\d{4}-\d{4,7})$", re.IGNORECASE
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


def _first_supported_alias(aliases: Iterable[str]) -> VulnId | None:
    """First alias that classifies as a supported kind, preferring CVE."""
    fallback: VulnId | None = None
    for alias in aliases:
        vid = classify(alias)
        if vid.kind == IdKind.CVE:
            return vid
        if vid.kind != IdKind.UNKNOWN and fallback is None:
            fallback = vid
    return fallback


def resolve(raw: str, *, aliases: Iterable[str] = (), canonical_id: str | None = None) -> VulnId:
    """Resolve ``raw`` to a canonical, supported :class:`VulnId`.

    Where :func:`classify` is pure format detection, ``resolve`` additionally
    maps a *source-specific* advisory alias to the canonical identifier every
    consumer keys on — so the modal fetch, the ``cve_cache`` key and the
    NVD/OSV/EPSS/KEV fan-out all agree. Precedence:

      1. an explicit ``canonical_id`` when it is itself supported;
      2. ``raw`` when already a supported canonical id (CVE / GHSA / PYSEC /
         RUSTSEC / GO — preserved unchanged);
      3. a supported id already present in ``aliases`` (preferring CVE) —
         reuses the CVE the dedup/merge step stored rather than relying on
         string surgery alone;
      4. a CVE embedded in a source prefix (``DEBIAN-CVE-… → CVE-…``) as
         defense in depth when no alias is available;
      5. otherwise :attr:`IdKind.UNKNOWN` — a controlled result, never raised.

    ``raw`` is always preserved verbatim on the returned ``VulnId`` for display
    and provenance; ``normalized`` carries the canonical id ("" on UNKNOWN).
    """
    if not isinstance(raw, str):
        return VulnId(raw=str(raw), normalized=str(raw), kind=IdKind.UNKNOWN)
    s = raw.strip()

    # 1. Explicit canonical id wins when provided and valid.
    if canonical_id:
        cv = classify(canonical_id)
        if cv.kind != IdKind.UNKNOWN:
            return VulnId(raw=raw, normalized=cv.normalized, kind=cv.kind)

    # 2. ``raw`` is already a supported canonical id — keep it as-is.
    direct = classify(s)
    if direct.kind != IdKind.UNKNOWN:
        return VulnId(raw=raw, normalized=direct.normalized, kind=direct.kind)

    # 3. Reuse a CVE (or other supported id) already merged into aliases.
    alias_hit = _first_supported_alias(aliases)
    if alias_hit is not None:
        return VulnId(raw=raw, normalized=alias_hit.normalized, kind=alias_hit.kind)

    # 4. Strip a source prefix wrapping a canonical CVE.
    m = _SOURCE_PREFIXED_CVE.match(s)
    if m:
        return VulnId(raw=raw, normalized=m.group(1).upper(), kind=IdKind.CVE)

    # 5. Controlled unsupported result.
    return VulnId(raw=raw, normalized=s, kind=IdKind.UNKNOWN)
