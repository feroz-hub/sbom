"""
Source adapter contract.

Every vulnerability source (NVD, OSV, GitHub Advisories, VulDB, future Snyk / OSS Index)
implements the same shape:

    class XSource:
        name: str = "X"
        def __init__(self, **credentials): ...
        async def query(self, components: list[dict], settings) -> SourceResult: ...

This file defines the ``VulnSource`` runtime-checkable Protocol and the
``SourceResult`` TypedDict that every adapter returns. Phase 3 (`sboms_crud.py`
cut-over) and Phase 4 (`analyze_endpoints.py` cut-over) consume this contract
via ``app.sources.registry.SOURCE_REGISTRY``.

Why a Protocol instead of an ABC:
  Python is duck-typed, and forcing every adapter through inheritance creates
  unnecessary coupling. A Protocol lets external implementations (e.g. a test
  fake or a future plugin) satisfy the contract structurally.

Why a TypedDict instead of a dataclass:
  Adapters already produce ``(findings, errors, warnings)`` triples; wrapping
  in a TypedDict gives static documentation without changing the runtime
  representation, so downstream code can still treat the return value as a
  plain dict.
"""

from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable


class SourceResult(TypedDict):
    """Uniform return shape for every ``VulnSource.query`` call."""

    findings: list[dict]
    errors: list[dict]
    warnings: list[dict]


def empty_result() -> SourceResult:
    """Convenience constructor for the empty success case."""
    return SourceResult(findings=[], errors=[], warnings=[])


@runtime_checkable
class VulnSource(Protocol):
    """
    Structural contract that every source adapter must satisfy.

    ``settings`` is intentionally typed as ``Any`` because:
      * during Phase 2 the legacy ``app.analysis._MultiSettings`` dataclass
        is still the canonical config object,
      * future adapters may want their own per-source settings type.
    Adapters that need specific attributes should access them with
    ``getattr(settings, ..., default)`` for forward compatibility.
    """

    name: str

    async def query(
        self,
        components: list[dict],
        settings: Any,
    ) -> SourceResult: ...
