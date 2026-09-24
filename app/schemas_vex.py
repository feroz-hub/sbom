"""Pydantic contracts for the portfolio VEX investigation API.

Spec sections 27-29 and 44 (VEX-UI-001/002/003, VEX-API-001).

The detail payload keeps the three evidence streams in **separate** sections
rather than merging them into one flattened row. That separation is the point
of the feature: an analyst has to be able to see what the scanner found, what
each supplier asserted (including assertions that lost, do not apply, or
conflict) and what the organisation decided, without any of the three quietly
overwriting the others.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SortOrder = Literal["asc", "desc"]

#: ``severity`` is deliberately absent: it lives on AnalysisFinding and is
#: resolved per row, so there is nothing to ORDER BY. The endpoint rejects it
#: with 400 rather than silently returning an arbitrary order.
InvestigationSortField = Literal[
    "vulnerability_id",
    "component",
    "effective_status",
    "reconciliation_status",
    "last_seen_at",
    "first_seen_at",
    "updated_at",
]


class InvestigationRow(BaseModel):
    """One row of the investigation queue (spec section 27)."""

    id: int
    canonical_vulnerability_id: str
    aliases: list[str] = Field(default_factory=list)
    severity: str | None = None

    component_id: int | None = None
    component_name: str | None = None
    component_version: str | None = None

    project_id: int | None = None
    project_name: str | None = None
    product_id: int | None = None
    product_name: str | None = None
    sbom_id: int
    sbom_name: str | None = None

    analyzer_detection_state: str | None = None
    analyzer_sources: list[str] = Field(default_factory=list)

    vex_source: str | None = None
    native_vex_status: str | None = None
    effective_status: str
    reconciliation_status: str
    justification: str | None = None

    assigned_to: str | None = None
    reviewed_by: str | None = None
    last_seen_at: str | None = None
    updated_at: str | None = None
    row_version: int = 1
    needs_review: bool = False


class InvestigationListResponse(BaseModel):
    """Envelope matching the repo's other server-paginated lists."""

    total: int
    limit: int
    offset: int
    items: list[InvestigationRow] = Field(default_factory=list)


class VulnerabilitySection(BaseModel):
    canonical_vulnerability_id: str
    aliases: list[str] = Field(default_factory=list)
    severity: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    references: list[str] = Field(default_factory=list)


class ComponentSection(BaseModel):
    component_id: int | None = None
    name: str | None = None
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    bom_ref: str | None = None
    supplier: str | None = None


class AnalyzerEvidenceSection(BaseModel):
    detection_state: str | None = None
    sources: list[str] = Field(default_factory=list)
    analysis_run_id: int | None = None
    match_strategy: str | None = None
    match_confidence: str | None = None
    matched_range: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


class ImportedVexAssertion(BaseModel):
    """One imported assertion.

    Every assertion is listed, including ones that are not applicable to this
    component version and ones that conflict with another source — hiding them
    is what VEX-INV-005 forbids.
    """

    statement_id: int
    source_format: str | None = None
    source_status: str | None = None
    normalized_status: str | None = None
    author: str | None = None
    source_document_id: str | None = None
    source_document_version: str | None = None
    asserted_at: str | None = None
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    mitigation: str | None = None
    fixed_version: str | None = None
    evidence_url: str | None = None
    mapping_confidence: str | None = None
    match_strategy: str | None = None
    version_applicable: bool | None = None
    is_effective: bool = False
    superseded: bool = False


class InternalDecisionSection(BaseModel):
    effective_status: str | None = None
    reviewer: str | None = None
    assigned_to: str | None = None
    reason: str | None = None
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    evidence_url: str | None = None
    updated_at: str | None = None


class HistoryEntry(BaseModel):
    at: str | None = None
    kind: Literal["import", "decision"]
    actor: str | None = None
    summary: str | None = None
    previous_status: str | None = None
    new_status: str | None = None
    reason: str | None = None


class InvestigationDetail(BaseModel):
    """Spec section 29 — evidence kept side by side, never merged."""

    id: int
    sbom_id: int
    project_name: str | None = None
    product_name: str | None = None
    sbom_name: str | None = None

    vulnerability: VulnerabilitySection
    component: ComponentSection
    analyzer_evidence: AnalyzerEvidenceSection
    imported_vex: list[ImportedVexAssertion] = Field(default_factory=list)
    internal_decision: InternalDecisionSection
    reconciliation_status: str
    effective_status: str
    history: list[HistoryEntry] = Field(default_factory=list)
    row_version: int = 1


class InvestigationDecisionRequest(BaseModel):
    """A manual determination on one context (VEX-INV-003, VEX-AUD-001/002).

    ``row_version`` is required: an analyst must be editing the version they
    were shown. A mismatch returns 409 with the current row rather than
    overwriting someone else's decision.
    """

    status: Literal["AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION"]
    row_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2000)
    justification: str | None = Field(default=None, max_length=2000)
    impact_statement: str | None = Field(default=None, max_length=2000)
    action_statement: str | None = Field(default=None, max_length=2000)
    fixed_version: str | None = Field(default=None, max_length=255)
    evidence_url: str | None = Field(default=None, max_length=2000)
    assigned_to: str | None = Field(default=None, max_length=255)


class InvestigationConflict(BaseModel):
    """409 body — carries the current row so the client can re-present it."""

    detail: str = "Investigation was updated by someone else"
    current: InvestigationDetail


__all__ = [
    "AnalyzerEvidenceSection",
    "ComponentSection",
    "HistoryEntry",
    "ImportedVexAssertion",
    "InternalDecisionSection",
    "InvestigationConflict",
    "InvestigationDecisionRequest",
    "InvestigationDetail",
    "InvestigationListResponse",
    "InvestigationRow",
    "InvestigationSortField",
    "SortOrder",
    "VulnerabilitySection",
]
