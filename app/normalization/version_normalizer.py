"""Version normalization for audit-safe component identity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class VersionNormalizationResult:
    original_version: str | None
    normalized_version: str | None
    notes: list[str] = field(default_factory=list)


def normalize_version(value: Any, *, ecosystem: str | None = None) -> VersionNormalizationResult:
    """Normalize version strings without changing package-manager semantics.

    This intentionally avoids float conversion and keeps distro versions such
    as ``1:2.3.4-5ubuntu1`` and ``0.105-33`` as strings.
    """

    if value is None:
        return VersionNormalizationResult(None, None, [])
    original = str(value)
    normalized = " ".join(original.strip().split())
    notes: list[str] = []
    if not normalized:
        return VersionNormalizationResult(original, None, ["empty_version"])
    if normalized.lower().startswith("version "):
        normalized = normalized[8:].strip()
        notes.append("removed_version_prefix")
    if _can_remove_leading_v(normalized, ecosystem):
        normalized = normalized[1:]
        notes.append("removed_leading_v")
    return VersionNormalizationResult(original, normalized, notes)


def _can_remove_leading_v(value: str, ecosystem: str | None) -> bool:
    if len(value) < 2 or value[0] != "v" or not value[1].isdigit():
        return False
    # OS package ecosystems often have epochs/revisions where aggressive
    # version munging is risky; leading "v" is still safe only for semver-ish
    # versions.
    if (ecosystem or "").lower() in {"debian", "rpm", "redhat", "alpine", "apk"}:
        return "." in value[1:]
    return True
