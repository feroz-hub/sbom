"""
Snapshot normalisation helpers.

Endpoint responses contain non-deterministic fields (timestamps, durations,
auto-incrementing run IDs). The snapshot tests need to scrub those before
comparing actual output to the locked golden file, otherwise every test run
would diff.

Keep this list deliberately short — anything we strip here is a contract
that the *value* doesn't matter, only the *presence and type* matter.
"""

from __future__ import annotations

from typing import Any


# Field names that vary per run and must never appear in a snapshot.
_VOLATILE_KEYS = {
    "completedOn",
    "durationMs",
    "duration_ms",
    "started_on",
    "completed_on",
    "runId",
    "run_id",
    "id",  # AnalysisRunOut.id is auto-increment
    "sbom_id",  # depends on test seed order
    "lastModified",
}


def normalize(value: Any) -> Any:
    """Recursively replace volatile fields with sentinel placeholders."""
    if isinstance(value, dict):
        return {
            k: ("<volatile>" if k in _VOLATILE_KEYS else normalize(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value
