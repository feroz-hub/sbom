"""Unique component version and component family keys (spec §2 glossary).

A *unique component version* is a distinct canonical identity including
version, by priority normalized PURL → CPE + version → supplier + name +
version + ecosystem. That is exactly ``build_identity_key`` in
``app/normalization/component_normalizer.py``, whose SHA-256 is persisted as
``SBOMComponent.dedupe_canonical_id``. This module reuses it rather than
inventing a second identity scheme:

1. ``dedupe_canonical_id`` when persisted.
2. Otherwise the same key rebuilt from the stored normalized fields (older
   rows normalized before the column was populated).
3. Otherwise the occurrence itself (``occ-<component id>``) with LOW identity
   confidence. Such a row is never merged with another one on a guess; it is
   flagged for review instead (spec §2 "incomplete evidence").

The *component family* (same package, any version) is
``normalized_package_key`` — used for same-family version discovery.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ...normalization.component_normalizer import build_identity_key

OCCURRENCE_KEY_PREFIX = "occ-"

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


@dataclass(frozen=True)
class VersionIdentity:
    key: str
    basis: str  # "purl" | "cpe" | "name" | "occurrence"
    confidence: str  # HIGH | MEDIUM | LOW


def _basis_for(identity_key: str) -> str:
    return identity_key.split(":", 1)[0]


def _confidence(value: str | None, basis: str) -> str:
    cleaned = str(value or "").strip().upper()
    if cleaned in (HIGH, MEDIUM, LOW):
        return cleaned
    return HIGH if basis in ("purl", "cpe") else MEDIUM


def version_identity(component: Any) -> VersionIdentity:
    """Identity of one ``SBOMComponent`` occurrence (row or row-like object)."""
    canonical = getattr(component, "dedupe_canonical_id", None)
    identity_key, rebuilt_confidence, _reason = build_identity_key(
        normalized_purl=getattr(component, "normalized_purl", None),
        primary_cpe=getattr(component, "primary_cpe", None),
        ecosystem=getattr(component, "normalized_ecosystem", None) or "",
        normalized_name=getattr(component, "normalized_name", None),
        normalized_version=getattr(component, "normalized_version", None),
        supplier=getattr(component, "normalized_supplier", None),
    )
    if canonical:
        basis = _basis_for(identity_key) if identity_key else "name"
        return VersionIdentity(
            canonical, basis, _confidence(getattr(component, "canonical_identity_confidence", None), basis)
        )
    if identity_key:
        basis = _basis_for(identity_key)
        return VersionIdentity(
            hashlib.sha256(identity_key.encode("utf-8")).hexdigest(), basis, _confidence(rebuilt_confidence, basis)
        )
    return VersionIdentity(f"{OCCURRENCE_KEY_PREFIX}{component.id}", "occurrence", LOW)


def family_key(component: Any) -> str | None:
    """Version-less package key (ecosystem:name[:supplier]) or ``None``."""
    return getattr(component, "normalized_package_key", None) or None


def split_licenses(*values: str | None) -> list[str]:
    """Distinct licenses from the comma-separated ``SBOMComponent.license``.

    SPDX expressions are kept verbatim; they are not parsed (phase0 §10).
    """
    seen: dict[str, str] = {}
    for value in values:
        for part in str(value or "").split(","):
            cleaned = part.strip()
            if cleaned and cleaned.lower() not in seen:
                seen[cleaned.lower()] = cleaned
    return sorted(seen.values(), key=str.lower)


__all__ = [
    "OCCURRENCE_KEY_PREFIX",
    "VersionIdentity",
    "family_key",
    "split_licenses",
    "version_identity",
]
