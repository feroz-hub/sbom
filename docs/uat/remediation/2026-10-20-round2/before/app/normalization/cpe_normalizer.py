"""CPE normalization for component identity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .version_normalizer import normalize_version


@dataclass(slots=True)
class CpeNormalizationResult:
    original_cpes: list[str] = field(default_factory=list)
    normalized_cpes: list[str] = field(default_factory=list)
    primary_cpe: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def normalize_cpes(*values: Any) -> CpeNormalizationResult:
    originals: list[str] = []
    normalized: list[str] = []
    evidence_items: list[dict[str, str]] = []
    notes: list[str] = []

    for value in values:
        for raw in _iter_cpe_values(value):
            originals.append(raw)
            cpe = _normalize_single(raw)
            if cpe is None:
                notes.append("invalid_or_unsupported_cpe")
                evidence_items.append({"original": raw, "normalized": "", "status": "kept_as_evidence_only"})
                continue
            if cpe not in normalized:
                normalized.append(cpe)
            evidence_items.append({"original": raw, "normalized": cpe, "status": "normalized"})

    primary = normalized[0] if normalized else None
    return CpeNormalizationResult(
        original_cpes=originals,
        normalized_cpes=normalized,
        primary_cpe=primary,
        evidence={"entries": evidence_items, "duplicates_removed": max(0, len(originals) - len(normalized))},
        notes=list(dict.fromkeys(notes)),
    )


def cpe_version(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.split(":")
    if len(parts) == 13 and parts[0] == "cpe" and parts[1] == "2.3":
        version = parts[5]
    elif len(parts) >= 5 and value.startswith("cpe:/"):
        version = parts[4]
    else:
        return None
    if version in {"", "*", "-"}:
        return None
    return version


def _iter_cpe_values(value: Any):
    if value is None:
        return
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            yield cleaned
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_cpe_values(item)


def _normalize_single(value: str) -> str | None:
    text = value.strip()
    parts = text.split(":")
    if len(parts) == 13 and parts[0].lower() == "cpe" and parts[1] == "2.3":
        out = parts[:]
        out[0] = "cpe"
        out[2] = out[2].lower()
        out[3] = _lower_token(out[3])
        out[4] = _lower_token(out[4])
        out[5] = normalize_version(_cpe_unescape(out[5])).normalized_version or out[5]
        return ":".join(out)
    if text.lower().startswith("cpe:/"):
        # Preserve 2.2 form while normalizing safe slots.
        parts = text.split(":")
        if len(parts) < 5:
            return None
        parts[0] = "cpe"
        parts[1] = parts[1].lower()
        parts[2] = _lower_token(parts[2])
        parts[3] = _lower_token(parts[3])
        parts[4] = normalize_version(_cpe_unescape(parts[4])).normalized_version or parts[4]
        return ":".join(parts)
    return None


def _lower_token(value: str) -> str:
    return _cpe_escape(_cpe_unescape(value).lower())


def _cpe_unescape(value: str) -> str:
    return value.replace("\\:", ":").replace("\\-", "-").replace("\\_", "_")


def _cpe_escape(value: str) -> str:
    return value.replace(":", "\\:")
