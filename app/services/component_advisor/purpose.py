"""Component purpose metadata with provenance (FR-SCA-009, US-SCA-07).

Pure resolution logic. Each field is taken from the highest-priority source
that supplies it, in the spec's order:

1. ``SBOM`` — the component ``description`` declared in an active SBOM.
2. ``PACKAGE`` — trusted package / maintainer metadata.
3. ``CURATED`` — internal curated metadata (tenant row overrides platform row).
4. ``AI`` — AI-assisted classification, only if such a row exists.

Fields: ``functional_description``, ``primary_use_case`` (also the spec's
"typical development purpose") and ``technology_category``. Every field keeps
its own source, confidence and provenance, and AI-sourced fields are flagged
``ai_assisted`` so they are visually and structurally distinguishable and
never silently become authoritative.

Purpose search (T15) only matches *sufficiently evidenced* fields: any
non-AI source, or AI with MEDIUM/HIGH confidence. A LOW-confidence AI guess
never makes a component match a purpose query, and nothing is ever inferred
from the component name.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PurposeSource(str, Enum):
    SBOM = "SBOM"
    PACKAGE = "PACKAGE"
    CURATED = "CURATED"
    AI = "AI"


SOURCE_PRIORITY = (PurposeSource.SBOM, PurposeSource.PACKAGE, PurposeSource.CURATED, PurposeSource.AI)
#: Sources that may be written as rows; SBOM evidence comes from components.
STORED_SOURCES = frozenset({PurposeSource.PACKAGE, PurposeSource.CURATED, PurposeSource.AI})
CONFIDENCE_VALUES = ("HIGH", "MEDIUM", "LOW")
SEARCHABLE_AI_CONFIDENCE = frozenset({"HIGH", "MEDIUM"})
FIELDS = ("functional_description", "primary_use_case", "technology_category")


@dataclass(frozen=True)
class PurposeRecord:
    """One stored purpose row (``component_purpose_metadata``), already scoped."""

    source: PurposeSource
    tenant_id: int | None
    purpose: str | None
    primary_use_case: str | None
    category: str | None
    confidence: str
    provenance: dict[str, Any] | None = None
    record_id: int | None = None

    def value(self, field_name: str) -> str | None:
        return {
            "functional_description": self.purpose,
            "primary_use_case": self.primary_use_case,
            "technology_category": self.category,
        }[field_name]


@dataclass(frozen=True)
class PurposeField:
    value: str
    source: PurposeSource
    confidence: str
    provenance: dict[str, Any]

    @property
    def ai_assisted(self) -> bool:
        return self.source is PurposeSource.AI

    @property
    def searchable(self) -> bool:
        return not self.ai_assisted or self.confidence in SEARCHABLE_AI_CONFIDENCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source.value,
            "confidence": self.confidence,
            "ai_assisted": self.ai_assisted,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class ResolvedPurpose:
    fields: dict[str, PurposeField]

    @property
    def available(self) -> bool:
        return bool(self.fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "AVAILABLE" if self.available else "NOT_AVAILABLE",
            "ai_assisted": any(f.ai_assisted for f in self.fields.values()),
            **{name: (self.fields[name].to_dict() if name in self.fields else None) for name in FIELDS},
        }

    def matches(self, needle: str, facet: str) -> bool:
        """Evidence-backed substring match for ``facet`` purpose / category / all."""
        names = {
            "purpose": ("functional_description", "primary_use_case"),
            "category": ("technology_category",),
            "all": FIELDS,
        }[facet]
        lowered = needle.lower()
        return any(
            name in self.fields and self.fields[name].searchable and lowered in self.fields[name].value.lower()
            for name in names
        )


NOT_AVAILABLE = ResolvedPurpose({})


def _sbom_description(descriptions: Sequence[tuple[int, str | None]]) -> PurposeField | None:
    """Most common SBOM-declared description across occurrences, with provenance."""
    present = [(sbom_id, text.strip()) for sbom_id, text in descriptions if text and text.strip()]
    if not present:
        return None
    counts = Counter(text for _, text in present)
    value, count = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0]
    sboms = sorted({sbom_id for sbom_id, text in present if text == value})
    return PurposeField(
        value=value,
        source=PurposeSource.SBOM,
        confidence="HIGH" if len(counts) == 1 else "MEDIUM",
        provenance={"sbom_ids": sboms, "occurrences_declaring": count, "distinct_descriptions": len(counts)},
    )


def resolve_purpose(
    *,
    sbom_descriptions: Sequence[tuple[int, str | None]] = (),
    records: Iterable[PurposeRecord] = (),
) -> ResolvedPurpose:
    """Resolve purpose fields by source priority; tenant rows beat platform rows."""
    fields: dict[str, PurposeField] = {}
    sbom = _sbom_description(sbom_descriptions)
    if sbom is not None:
        fields["functional_description"] = sbom

    ordered = sorted(
        records,
        key=lambda r: (SOURCE_PRIORITY.index(r.source), 0 if r.tenant_id is not None else 1),
    )
    for name in FIELDS:
        if name in fields:
            continue
        for record in ordered:
            value = record.value(name)
            if value and value.strip():
                provenance = dict(record.provenance or {})
                provenance.setdefault("record_id", record.record_id)
                provenance.setdefault("scope", "TENANT" if record.tenant_id is not None else "PLATFORM")
                fields[name] = PurposeField(value.strip(), record.source, record.confidence, provenance)
                break
    return ResolvedPurpose(fields)


def validate_purpose_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a curated / AI purpose write; AI rows must carry provenance."""
    source = PurposeSource(str(payload.get("source") or "CURATED").upper())
    if source not in STORED_SOURCES:
        raise ValueError("source must be PACKAGE, CURATED or AI (SBOM evidence comes from SBOMs)")
    confidence = str(payload.get("confidence") or ("HIGH" if source is PurposeSource.CURATED else "")).upper()
    if confidence not in CONFIDENCE_VALUES:
        raise ValueError("confidence must be HIGH, MEDIUM or LOW")
    values = {
        "purpose": (payload.get("functional_description") or "").strip() or None,
        "primary_use_case": (payload.get("primary_use_case") or "").strip() or None,
        "category": (payload.get("technology_category") or "").strip() or None,
    }
    if not any(values.values()):
        raise ValueError("At least one of functional_description, primary_use_case, technology_category is required")
    provenance = payload.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise ValueError("provenance must be an object")
    if source is PurposeSource.AI and not (provenance and provenance.get("model") and provenance.get("generated_at")):
        raise ValueError("AI-assisted purpose requires provenance.model and provenance.generated_at")
    return {"source": source, "confidence": confidence, "provenance": provenance, **values}


__all__ = [
    "FIELDS",
    "NOT_AVAILABLE",
    "PurposeField",
    "PurposeRecord",
    "PurposeSource",
    "ResolvedPurpose",
    "SOURCE_PRIORITY",
    "resolve_purpose",
    "validate_purpose_payload",
]
