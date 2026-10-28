"""Canonical vulnerability identity for VEX contexts (VEX-CTX-002).

A GHSA advisory reported by the analyser and a CVE asserted by a VEX document
describe one vulnerability and must share one investigation context. This
module produces the canonical id every context keys on, plus the alias set kept
alongside it for search and display.

The identifier logic itself is **not** reimplemented here:
:func:`app.integrations.cve.identifiers.resolve` handles format classification,
source-prefix stripping (``DEBIAN-CVE-…`` → ``CVE-…``) and alias fallback, and
never raises. This module adapts it to VEX's inputs — notably the
JSON-array-in-text ``AnalysisFinding.aliases`` column.

One deliberate difference. ``resolve`` preserves an already-canonical id
unchanged, so ``GHSA-…`` with a ``CVE-…`` alias resolves to the GHSA. That is
right for the cache and provider fan-out it was built for, but wrong here:
VEX-CTX-002 says "where a CVE is available, CVE should normally become the
canonical identifier", and the section 47 matrix requires a GHSA finding and a
CVE VEX assertion to share one context. So a CVE among the inputs wins first,
and ``resolve`` is consulted for everything else.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ...integrations.cve.identifiers import IdKind, classify, resolve


@dataclass(frozen=True)
class CanonicalVulnerability:
    """Resolved identity for one vulnerability across sources."""

    canonical_id: str
    #: Every other identifier seen for this vulnerability, upper-cased and
    #: sorted, excluding ``canonical_id`` itself.
    aliases: tuple[str, ...] = field(default=())
    #: ``True`` when the canonical id is a recognised advisory format. A
    #: ``False`` here means we fell back to the raw identifier — still a usable
    #: context key, but it will not merge with an alias-linked context.
    is_supported: bool = False

    @property
    def aliases_json(self) -> str:
        """Serialised form for the ``VexInvestigation.aliases_json`` column."""
        return json.dumps(list(self.aliases))


def parse_alias_column(raw: Any) -> list[str]:
    """Read the JSON-array-in-text ``AnalysisFinding.aliases`` column.

    Permissive by design, mirroring ``app/ai/grounding.py:129`` — malformed
    alias data must never break reconciliation.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(x).strip() for x in value if str(x).strip()]


def _first_cve(candidates: Iterable[str | None]) -> str | None:
    """First value that classifies as a CVE, normalised."""
    for candidate in candidates:
        if not candidate:
            continue
        identified = classify(str(candidate))
        if identified.kind is IdKind.CVE:
            return identified.normalized
    return None


def canonical_vulnerability(
    vulnerability_id: Any,
    *,
    aliases: Iterable[str] | None = None,
    canonical_id: str | None = None,
) -> CanonicalVulnerability:
    """Resolve one vulnerability id plus its aliases to a canonical identity.

    ``aliases`` accepts whatever a caller has: a list, or the raw text of
    ``AnalysisFinding.aliases``. Every identifier that is not the canonical one
    is returned in :attr:`CanonicalVulnerability.aliases`, so a context found
    via GHSA is still searchable by its GHSA id.
    """
    alias_list = parse_alias_column(aliases) if isinstance(aliases, str) else [
        str(a).strip() for a in (aliases or []) if str(a).strip()
    ]

    # VEX-CTX-002: a CVE anywhere in the inputs is the canonical id, even when
    # the raw identifier is itself a valid GHSA/PYSEC/… that ``resolve`` would
    # otherwise preserve. Order is explicit-hint, raw, then aliases.
    cve = _first_cve([canonical_id, str(vulnerability_id or ""), *alias_list])

    resolved = resolve(vulnerability_id, aliases=alias_list, canonical_id=canonical_id)
    canonical = (cve or resolved.normalized or str(vulnerability_id or "")).strip().upper()

    seen = {canonical}
    others: list[str] = []
    for candidate in [str(vulnerability_id or ""), *alias_list]:
        value = candidate.strip().upper()
        if value and value not in seen:
            seen.add(value)
            others.append(value)

    return CanonicalVulnerability(
        canonical_id=canonical,
        aliases=tuple(sorted(others)),
        is_supported=bool(cve) or resolved.kind is not IdKind.UNKNOWN,
    )


def canonical_for_finding(finding: Any) -> CanonicalVulnerability:
    """Convenience wrapper for an ``AnalysisFinding`` row."""
    return canonical_vulnerability(
        getattr(finding, "vuln_id", None), aliases=getattr(finding, "aliases", None)
    )


def canonical_for_statement(statement: Any) -> CanonicalVulnerability:
    """Convenience wrapper for a ``VexStatement`` row.

    ``cve_id`` is passed as an explicit canonical hint: importers already
    extract it, and it takes precedence in :func:`resolve` when valid.
    """
    return canonical_vulnerability(
        getattr(statement, "vulnerability_id", None),
        canonical_id=getattr(statement, "cve_id", None),
    )


__all__ = [
    "CanonicalVulnerability",
    "canonical_for_finding",
    "canonical_for_statement",
    "canonical_vulnerability",
    "parse_alias_column",
]
