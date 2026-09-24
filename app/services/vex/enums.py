"""Canonical VEX investigation enums (spec sections 7, 10, 15, 18).

These are stored as plain strings in the database — the codebase uses
``Column(String)`` throughout rather than native PG enums, so adding a value
later is a code change, not a migration.
"""

from __future__ import annotations

from enum import Enum


class EffectiveVexStatus(str, Enum):
    """The four canonical investigation outcomes (VEX-STAT-001).

    There is deliberately no ``UNKNOWN`` member. Per spec section 8 an imported
    ``unknown`` is source evidence only; its effective status is
    :attr:`UNDER_INVESTIGATION`. The legacy ``unknown`` value survives on
    ``VexStatement.status`` / ``source_status`` and in ``unknown_count`` on the
    dashboard response, both kept for backward compatibility.
    """

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    FIXED = "FIXED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"


class ReconciliationStatus(str, Enum):
    """How analyser evidence and VEX assertions line up (VEX-REC-001)."""

    MATCHED = "MATCHED"
    ANALYZER_ONLY = "ANALYZER_ONLY"
    VEX_ONLY = "VEX_ONLY"
    CONFLICT_REVIEW_REQUIRED = "CONFLICT_REVIEW_REQUIRED"
    REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"
    UNRESOLVED_MAPPING = "UNRESOLVED_MAPPING"


#: Reconciliation states that put a context in the review queue (VEX-DASH-003).
NEEDS_REVIEW_STATUSES: frozenset[ReconciliationStatus] = frozenset(
    {
        ReconciliationStatus.CONFLICT_REVIEW_REQUIRED,
        ReconciliationStatus.REVALIDATION_REQUIRED,
    }
)


class AnalyzerDetectionState(str, Enum):
    """Why the analyser did or did not report a vulnerability (VEX-REC-004).

    A provider timeout is not a negative determination: ``SOURCE_ERROR`` and
    ``SOURCE_UNAVAILABLE`` must never be rendered as ``NOT_DETECTED``.
    """

    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    NOT_QUERIED = "NOT_QUERIED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_ERROR = "SOURCE_ERROR"


class MappingConfidence(str, Enum):
    """Strength of the component match behind a VEX assertion (VEX-MAP-001).

    ``WEAK`` marks name-only and other non-identifying strategies. More than one
    candidate on a weak strategy yields ``UNRESOLVED_MAPPING`` rather than an
    arbitrary first-candidate binding.
    """

    EXACT = "EXACT"
    STRONG = "STRONG"
    WEAK = "WEAK"
    UNRESOLVED = "UNRESOLVED"


class VexMatchStrategy(str, Enum):
    """Component-mapping strategies in priority order (VEX-MAP-001)."""

    BOM_REF = "BOM_REF"
    PURL = "PURL"
    CPE = "CPE"
    PACKAGE_IDENTITY_VERSION = "PACKAGE_IDENTITY_VERSION"
    SUPPLIER_NAME_VERSION = "SUPPLIER_NAME_VERSION"
    NAME_VERSION = "NAME_VERSION"
    NAME_ONLY = "NAME_ONLY"
    NONE = "NONE"


#: Strategies considered weak: a single candidate may bind, several may not.
WEAK_MATCH_STRATEGIES: frozenset[VexMatchStrategy] = frozenset(
    {VexMatchStrategy.NAME_VERSION, VexMatchStrategy.NAME_ONLY}
)


__all__ = [
    "NEEDS_REVIEW_STATUSES",
    "WEAK_MATCH_STRATEGIES",
    "AnalyzerDetectionState",
    "EffectiveVexStatus",
    "MappingConfidence",
    "ReconciliationStatus",
    "VexMatchStrategy",
]
