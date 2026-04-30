"""
Pydantic models for the Compare Runs v2 service (ADR-0008).

Wire format the frontend `<CompareView />` consumes. Three deliberate
simplifications vs the original prompt, justified in ADR-0008 §11:

  PB-1  No ``risk_score`` scalar. ``PostureDelta`` carries three
        independently-defensible counts (KEV exposure, fix-available
        coverage, high+critical exposure) anchored to public sources.
  PB-2  ``severity_distribution_a/b`` plus per-row ``severity_changed``
        events — both, in different regions of the UI.
  PB-3  ``FindingChangeKind.kev_added`` is intentionally omitted. KEV
        state is not snapshotted at scan time, so an honest at-scan-time
        delta is impossible. KEV becomes a row-level annotation
        (``kev_current``) and a Region 2 tile.

Run identifiers are ``int``, not ``UUID`` — the existing
``analysis_run.id`` is an integer primary key (Phase 1 §1).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .schemas_cve import CveSeverity

# =============================================================================
# Stable error codes — frontend branches on these, not on free-text messages.
# =============================================================================

ERR_COMPARE_RUN_NOT_FOUND = "COMPARE_E001_RUN_NOT_FOUND"
ERR_COMPARE_RUN_NOT_READY = "COMPARE_E002_RUN_NOT_READY"
ERR_COMPARE_SAME_RUN = "COMPARE_E003_SAME_RUN"
ERR_COMPARE_PERMISSION_DENIED = "COMPARE_E004_PERMISSION_DENIED"
ERR_COMPARE_BAD_REQUEST = "COMPARE_E005_BAD_REQUEST"

#: Run statuses that are "ready to diff." Anything else returns 409 with
#: ``ERR_COMPARE_RUN_NOT_READY``. RUNNING / PENDING are explicitly ineligible
#: per ADR-0008 §10 OOS — comparing in-progress runs returns nonsense.
COMPARABLE_RUN_STATUSES: frozenset[str] = frozenset({"OK", "FINDINGS", "PARTIAL"})


# =============================================================================
# Enumerations
# =============================================================================


class FindingChangeKind(str, Enum):
    """
    Per-finding diff event class.

    Identity for the diff is ``(canonical_vuln_id, component_name,
    component_version)`` — see ADR-0008 §7.2 for why we don't use the
    finding's ``cpe`` (often missing for non-OS packages) or ``component_id``
    FK (nullable).

    ``kev_added`` is intentionally absent. See ADR-0008 §11 PB-3.
    """

    ADDED = "added"
    RESOLVED = "resolved"
    SEVERITY_CHANGED = "severity_changed"
    UNCHANGED = "unchanged"


class ComponentChangeKind(str, Enum):
    """
    Per-component diff event class.

    Identity for the diff is ``(name_lower, ecosystem)`` where ecosystem is
    derived from the PURL via ``app.services.cve_service._purl_ecosystem``.
    Falls back to ``(name_lower, "unknown")`` when PURL is missing — see
    ADR-0008 §7.1 for the documented limitation.

    ``LICENSE_CHANGED`` and ``HASH_CHANGED`` are stubs. They never fire today
    because the underlying columns aren't stored. They're additionally hard-
    guarded behind ``Settings.compare_license_hash_enabled`` so that if
    someone adds the columns without finishing the wiring, the change_kinds
    still won't quietly activate. See ADR-0008 §10 OOS and Phase 3 user
    clarification §4.
    """

    ADDED = "added"
    REMOVED = "removed"
    VERSION_BUMPED = "version_bumped"
    LICENSE_CHANGED = "license_changed"
    HASH_CHANGED = "hash_changed"
    UNCHANGED = "unchanged"


# =============================================================================
# Building blocks
# =============================================================================


class RunSummary(BaseModel):
    """Compact view of a run for the compare header / picker."""

    model_config = ConfigDict(extra="forbid")

    id: int
    sbom_id: int | None = None
    sbom_name: str | None = None
    project_id: int | None = None
    project_name: str | None = None
    run_status: str
    completed_on: str | None = None
    started_on: str | None = None
    total_findings: int = 0
    total_components: int = 0


class RunRelationship(BaseModel):
    """
    How A and B relate. Drives the one-line descriptor under the pickers.
    """

    model_config = ConfigDict(extra="forbid")

    same_project: bool
    same_sbom: bool
    days_between: float | None = None
    direction_warning: str | None = Field(
        default=None,
        description="Set when run B is older than run A (likely user picked the wrong order).",
    )


class FindingDiffRow(BaseModel):
    """One row in the Findings tab of the Compare view."""

    model_config = ConfigDict(extra="forbid")

    change_kind: FindingChangeKind

    #: Canonical vuln id (CVE-…, GHSA-…, PYSEC-…, RUSTSEC-…, GO-…) or the
    #: raw input when the classifier returns UNKNOWN.
    vuln_id: str

    severity_a: CveSeverity | None = None
    severity_b: CveSeverity | None = None

    #: Current KEV status from ``kev_entry`` lookup. NOT at-scan-time —
    #: see ADR-0008 §11 PB-3. Tooltip on the chip says so.
    kev_current: bool = False

    #: Current EPSS values from ``cve_cache.payload.exploitation`` if cached.
    #: NOT at-scan-time. Both fields are independently nullable: cache miss
    #: leaves them None, never refetches.
    epss_current: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile_current: float | None = Field(default=None, ge=0.0, le=1.0)

    component_name: str
    component_version_a: str | None = None
    component_version_b: str | None = None
    component_purl: str | None = None
    component_ecosystem: str | None = None

    #: True iff ``analysis_finding.fixed_versions`` is non-empty for the
    #: surviving finding row (B if change_kind in {ADDED, SEVERITY_CHANGED,
    #: UNCHANGED}, A if change_kind == RESOLVED).
    fix_available: bool = False

    #: Human-readable attribution string. See ADR-0008 §7.5.
    attribution: str | None = None


class ComponentDiffRow(BaseModel):
    """One row in the Components tab of the Compare view."""

    model_config = ConfigDict(extra="forbid")

    change_kind: ComponentChangeKind

    name: str
    ecosystem: str
    purl: str | None = None

    version_a: str | None = None
    version_b: str | None = None

    #: Always None today. Reserved for the future migration that adds
    #: license + hash columns to ``sbom_component``.
    license_a: str | None = None
    license_b: str | None = None
    hash_a: str | None = None
    hash_b: str | None = None

    #: Number of findings whose RESOLVED event is attributable to this
    #: component change.
    findings_resolved: int = 0
    #: Number of findings whose ADDED event is attributable to this
    #: component change.
    findings_added: int = 0


# =============================================================================
# Posture (ADR-0008 §6) — three independently-defensible deltas, no scalar
# =============================================================================


class PostureDelta(BaseModel):
    """
    Region 2 of the Compare UI. Three count-based deltas anchored to public
    sources, plus the v1 distribution bar promoted, plus side-by-side
    severity composition for Tab 3.

    No multiplicative scalar. No portfolio "risk score." See
    ADR-0008 §11 PB-1 — reintroducing the scalar would contradict the
    Risk Index removal recorded in ``docs/risk-index.md``.
    """

    model_config = ConfigDict(extra="forbid")

    # --- KEV exposure (Region 2 tile) -----------------------------------
    kev_count_a: int = Field(default=0, ge=0)
    kev_count_b: int = Field(default=0, ge=0)
    kev_count_delta: int = 0  # may be negative

    # --- Fix-available coverage (Region 2 tile) -------------------------
    #: Percentage in [0, 100]. NOT a fraction.
    fix_available_pct_a: float = Field(default=0.0, ge=0.0, le=100.0)
    fix_available_pct_b: float = Field(default=0.0, ge=0.0, le=100.0)
    fix_available_pct_delta: float = 0.0

    # --- High+Critical exposure (Region 2 tile) -------------------------
    high_critical_count_a: int = Field(default=0, ge=0)
    high_critical_count_b: int = Field(default=0, ge=0)
    high_critical_count_delta: int = 0

    # --- Distribution bar (Region 2, promoted from v1 C7) ---------------
    findings_added_count: int = Field(default=0, ge=0)
    findings_resolved_count: int = Field(default=0, ge=0)
    findings_severity_changed_count: int = Field(default=0, ge=0)
    findings_unchanged_count: int = Field(default=0, ge=0)

    # --- Component composition counts -----------------------------------
    components_added_count: int = Field(default=0, ge=0)
    components_removed_count: int = Field(default=0, ge=0)
    components_version_bumped_count: int = Field(default=0, ge=0)
    components_unchanged_count: int = Field(default=0, ge=0)

    # --- Severity composition (Tab 3 side-by-side bar — kept v1 C9) -----
    #: Keys are uppercase severity strings: CRITICAL / HIGH / MEDIUM / LOW
    #: / UNKNOWN. NONE is collapsed into UNKNOWN to match the existing
    #: ``analysis_run`` aggregate columns.
    severity_distribution_a: dict[str, int] = Field(default_factory=dict)
    severity_distribution_b: dict[str, int] = Field(default_factory=dict)

    # --- Top contributors (Tab 3) — ordinal rank, NOT a scalar ----------
    top_resolutions: list[FindingDiffRow] = Field(default_factory=list, max_length=5)
    top_regressions: list[FindingDiffRow] = Field(default_factory=list, max_length=5)


# =============================================================================
# Top-level compare result
# =============================================================================


class CompareResult(BaseModel):
    """Full payload returned by ``POST /api/v1/compare``."""

    model_config = ConfigDict(extra="forbid")

    #: ``sha256(f"{min(a,b)}:{max(a,b)}")`` hex digest. Lookup key for
    #: ``compare_cache`` and for ``POST /api/v1/compare/{cache_key}/export``.
    cache_key: str = Field(..., min_length=64, max_length=64)

    run_a: RunSummary
    run_b: RunSummary
    relationship: RunRelationship
    posture: PostureDelta

    findings: list[FindingDiffRow] = Field(default_factory=list)
    components: list[ComponentDiffRow] = Field(default_factory=list)

    computed_at: datetime
    schema_version: int = Field(default=1, ge=1)

    @field_validator("cache_key")
    @classmethod
    def _hex_only(cls, v: str) -> str:
        try:
            int(v, 16)
        except ValueError as exc:
            raise ValueError("cache_key must be a 64-char hex string") from exc
        return v.lower()


# =============================================================================
# Request DTOs
# =============================================================================


class CompareRequest(BaseModel):
    """Body for ``POST /api/v1/compare``."""

    model_config = ConfigDict(extra="forbid")

    run_a_id: int = Field(..., gt=0)
    run_b_id: int = Field(..., gt=0)


class CompareExportRequest(BaseModel):
    """Body for ``POST /api/v1/compare/{cache_key}/export``."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["markdown", "csv", "json"]
