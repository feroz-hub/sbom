"""VEX reconciliation and investigation services.

Introduced by the VEX Dashboard & Investigation workstream; see
``docs/requirements/vex-dashboard-investigation.md`` and
``docs/plans/vex-implementation-plan.md``.

This package holds the *new* context/reconciliation layer. Import, statement
mapping and manual overrides continue to live in
``app/services/lifecycle/vex_provider.py`` — the workstream extends that
architecture rather than replacing it.
"""

from __future__ import annotations

from .enums import (
    AnalyzerDetectionState,
    EffectiveVexStatus,
    MappingConfidence,
    ReconciliationStatus,
)
from .identity import CanonicalVulnerability, canonical_vulnerability
from .matching import ComponentMatch, match_component, version_applies
from .reconciliation import recompute_for_sbom

__all__ = [
    "AnalyzerDetectionState",
    "CanonicalVulnerability",
    "ComponentMatch",
    "EffectiveVexStatus",
    "MappingConfidence",
    "ReconciliationStatus",
    "canonical_vulnerability",
    "match_component",
    "recompute_for_sbom",
    "version_applies",
]
