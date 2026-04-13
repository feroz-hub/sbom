"""
Pipeline context for multi-source SBOM analysis.

``run_multi_source_analysis_async`` in ``multi_source.py`` implements the
orchestration; this dataclass documents the data carried through stages
(parse → enrich → query → dedupe → aggregate) for tests and future stage splits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MultiSourcePipelineContext:
    """Mutable state for an SBOM multi-source analysis run."""

    sbom_json: str
    sources: list[str] | None = None
    settings: Any = None
    components: list[dict] = field(default_factory=list)
    components_with_cpe: list[dict] = field(default_factory=list)
    generated_cpe_count: int = 0
    all_findings: list[dict] = field(default_factory=list)
    query_errors: list[dict] = field(default_factory=list)
    query_warnings: list[dict] = field(default_factory=list)
    result: dict[str, Any] | None = None
