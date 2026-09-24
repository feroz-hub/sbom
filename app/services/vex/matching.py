"""Component mapping and version applicability for VEX assertions.

Spec sections 15-16 (VEX-MAP-001, VEX-MAP-002).

The existing matcher in ``app/services/lifecycle/vex_provider.py`` answers
"which component is this?" and returns the first hit. That is the behaviour
GAP-007 identifies: when several components satisfy a weak, non-identifying
match the honest answer is "I don't know", not an arbitrary pick. This module
answers a different question — *which candidates, by what strategy, with what
confidence* — and leaves the binding decision to the caller.

Nothing here deletes or rewrites evidence. A statement that matches nothing is
still retained, exactly as today (spec section 15, last paragraph).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .enums import WEAK_MATCH_STRATEGIES, MappingConfidence, VexMatchStrategy

#: Strategy -> confidence. Identifier-based strategies are exact; a supplier
#: qualified name+version is strong; bare name matching is weak.
_CONFIDENCE_BY_STRATEGY: dict[VexMatchStrategy, MappingConfidence] = {
    VexMatchStrategy.BOM_REF: MappingConfidence.EXACT,
    VexMatchStrategy.PURL: MappingConfidence.EXACT,
    VexMatchStrategy.CPE: MappingConfidence.EXACT,
    VexMatchStrategy.PACKAGE_IDENTITY_VERSION: MappingConfidence.STRONG,
    VexMatchStrategy.SUPPLIER_NAME_VERSION: MappingConfidence.STRONG,
    VexMatchStrategy.NAME_VERSION: MappingConfidence.WEAK,
    VexMatchStrategy.NAME_ONLY: MappingConfidence.WEAK,
    VexMatchStrategy.NONE: MappingConfidence.UNRESOLVED,
}

#: Priority order from spec section 15. First strategy with any candidate wins.
_STRATEGY_ORDER: tuple[VexMatchStrategy, ...] = (
    VexMatchStrategy.BOM_REF,
    VexMatchStrategy.PURL,
    VexMatchStrategy.CPE,
    VexMatchStrategy.PACKAGE_IDENTITY_VERSION,
    VexMatchStrategy.SUPPLIER_NAME_VERSION,
    VexMatchStrategy.NAME_VERSION,
    VexMatchStrategy.NAME_ONLY,
)


def _norm(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _normalize_purl(value: Any) -> str:
    """Compare PURLs without qualifiers or subpath, which are not identity."""
    text = _norm(value)
    if not text.startswith("pkg:"):
        return text
    return text.split("#", 1)[0].split("?", 1)[0]


@dataclass(frozen=True)
class ComponentMatch:
    """Outcome of mapping one VEX assertion onto SBOM components."""

    strategy: VexMatchStrategy
    confidence: MappingConfidence
    candidates: tuple[int, ...] = field(default=())

    @property
    def component_id(self) -> int | None:
        """The bound component, or ``None`` when the mapping is unresolved.

        A weak strategy with more than one candidate never binds — that is
        precisely the GAP-007 case. A weak strategy with exactly one candidate
        does bind, but keeps ``WEAK`` confidence so the UI can flag it.
        """
        if len(self.candidates) != 1:
            return None
        if self.strategy in WEAK_MATCH_STRATEGIES and len(self.candidates) > 1:
            return None
        return self.candidates[0]

    @property
    def is_ambiguous(self) -> bool:
        """Several candidates satisfied a weak match: UNRESOLVED_MAPPING."""
        return len(self.candidates) > 1

    @property
    def is_unmatched(self) -> bool:
        return not self.candidates


UNRESOLVED = ComponentMatch(VexMatchStrategy.NONE, MappingConfidence.UNRESOLVED, ())


def _reference_values(reference: Any) -> dict[str, list[str]]:
    """Pull comparable identity values out of whatever a format gave us."""
    if reference is None:
        return {}
    if not isinstance(reference, dict):
        text = _norm(reference)
        return {"ref": [text]} if text else {}

    helper = reference.get("product_identification_helper")
    helper = helper if isinstance(helper, dict) else {}

    def collect(*values: Any) -> list[str]:
        out: list[str] = []
        for value in values:
            if isinstance(value, list):
                out.extend(_norm(v) for v in value if v)
            elif value:
                out.append(_norm(value))
        return [v for v in out if v]

    return {
        "ref": collect(
            reference.get("ref"),
            reference.get("bom_ref"),
            reference.get("bom-ref"),
            reference.get("product_id"),
            reference.get("productId"),
            reference.get("id"),
        ),
        "purl": collect(reference.get("purl"), helper.get("purl")),
        "cpe": collect(reference.get("cpe"), helper.get("cpe"), helper.get("cpe23Uri")),
        "name": collect(reference.get("name"), reference.get("product_name")),
        "version": collect(reference.get("version"), helper.get("version")),
        "supplier": collect(
            reference.get("supplier"), reference.get("vendor"), helper.get("supplier")
        ),
    }


def _candidates_for_strategy(
    strategy: VexMatchStrategy, components: list[Any], values: dict[str, list[str]]
) -> list[int]:
    refs = values.get("ref") or []
    purls = values.get("purl") or []
    cpes = values.get("cpe") or []
    names = values.get("name") or []
    versions = values.get("version") or []
    suppliers = values.get("supplier") or []

    # A bare string reference can legitimately be any of bom-ref/purl/cpe/name.
    if refs and not (purls or cpes or names):
        purls = purls or [r for r in refs if r.startswith("pkg:")]
        cpes = cpes or [r for r in refs if r.startswith("cpe:")]
        names = names or refs

    matched: list[int] = []
    for component in components:
        if strategy is VexMatchStrategy.BOM_REF:
            hit = bool(component.bom_ref) and _norm(component.bom_ref) in refs
        elif strategy is VexMatchStrategy.PURL:
            hit = bool(component.purl) and _normalize_purl(component.purl) in {
                _normalize_purl(p) for p in purls
            }
        elif strategy is VexMatchStrategy.CPE:
            hit = bool(component.cpe) and _norm(component.cpe) in cpes
        elif strategy is VexMatchStrategy.PACKAGE_IDENTITY_VERSION:
            package = _package_name_from_purl(component.purl)
            hit = bool(package) and package in {_package_name_from_purl(p) or p for p in purls} and (
                not versions or _norm(component.version) in versions
            )
        elif strategy is VexMatchStrategy.SUPPLIER_NAME_VERSION:
            hit = (
                bool(component.supplier)
                and _norm(component.supplier) in suppliers
                and _norm(component.name) in names
                and _norm(component.version) in versions
            )
        elif strategy is VexMatchStrategy.NAME_VERSION:
            hit = bool(versions) and _norm(component.name) in names and _norm(component.version) in versions
        elif strategy is VexMatchStrategy.NAME_ONLY:
            hit = _norm(component.name) in names
        else:
            hit = False
        if hit:
            matched.append(component.id)
    return matched


def _package_name_from_purl(value: Any) -> str:
    """``pkg:pypi/django@4.2`` -> ``pkg:pypi/django`` (identity without version)."""
    text = _normalize_purl(value)
    if not text.startswith("pkg:"):
        return ""
    return text.split("@", 1)[0]


def match_component(reference: Any, components: list[Any]) -> ComponentMatch:
    """Map a VEX assertion's product reference onto SBOM components.

    Walks the spec section 15 priority order and stops at the first strategy
    with any candidate. Returns every candidate that strategy found, so the
    caller can tell a confident binding from an ambiguous one.
    """
    values = _reference_values(reference)
    if not values:
        return UNRESOLVED

    for strategy in _STRATEGY_ORDER:
        candidates = _candidates_for_strategy(strategy, components, values)
        if candidates:
            return ComponentMatch(
                strategy=strategy,
                confidence=_CONFIDENCE_BY_STRATEGY[strategy]
                if len(candidates) == 1
                else MappingConfidence.UNRESOLVED,
                candidates=tuple(sorted(candidates)),
            )
    return UNRESOLVED


# --------------------------------------------------------------------------
# Version applicability (VEX-MAP-002)
# --------------------------------------------------------------------------

_RANGE_TOKEN = re.compile(r"(>=|<=|>|<|==|=)\s*([^,\s|]+)")


def _version_tuple(value: str) -> tuple:
    """Compare versions segment-wise, numerics numerically."""
    parts = re.split(r"[.\-+_]", value.strip().lower())
    out: list[tuple[int, Any]] = []
    for part in parts:
        if part.isdigit():
            out.append((0, int(part)))
        elif part:
            out.append((1, part))
    return tuple(out)


def _compare(left: str, right: str) -> int:
    a, b = _version_tuple(left), _version_tuple(right)
    return (a > b) - (a < b)


def version_applies(component_version: Any, specification: Any) -> bool | None:
    """Is ``component_version`` covered by a VEX version specification?

    Supports the three forms spec section 16 requires: an exact version, a list
    of versions, and a range (``>= 1.0, < 1.4`` or ``vers``-style with ``|``).

    Returns ``None`` when there is nothing to evaluate — no specification, or a
    version we cannot parse. ``None`` means "not assessed", which is different
    from ``False`` ("assessed and does not apply"): only ``False`` makes a
    statement ineligible to become the effective determination.
    """
    version = _norm(component_version)
    if not version or specification is None:
        return None

    if isinstance(specification, (list, tuple, set)):
        values = [_norm(v) for v in specification if _norm(v)]
        return version in values if values else None

    spec = _norm(specification)
    if not spec:
        return None

    tokens = _RANGE_TOKEN.findall(spec)
    if not tokens:
        return version == spec

    # All constraints must hold; a ``|``-separated vers range is any-of.
    for clause in re.split(r"\|\|?", spec):
        clause_tokens = _RANGE_TOKEN.findall(clause)
        if not clause_tokens:
            continue
        if all(_satisfies(version, operator, bound) for operator, bound in clause_tokens):
            return True
    return False


def _satisfies(version: str, operator: str, bound: str) -> bool:
    try:
        result = _compare(version, _norm(bound))
    except (TypeError, ValueError):
        return False
    return {
        ">=": result >= 0,
        ">": result > 0,
        "<=": result <= 0,
        "<": result < 0,
        "==": result == 0,
        "=": result == 0,
    }.get(operator, False)


__all__ = [
    "UNRESOLVED",
    "ComponentMatch",
    "match_component",
    "version_applies",
]
