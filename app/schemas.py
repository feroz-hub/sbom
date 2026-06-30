# schemas.py

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


def _coerce_project_status(v) -> int:
    """Accept 'Active'/'Inactive' strings or 0/1 integers."""
    if isinstance(v, str):
        return 1 if v.strip().lower() == "active" else 0
    return int(v)


class ORMModel(BaseModel):
    class Config:
        from_attributes = True


class ProjectCreate(BaseModel):
    project_name: str
    project_details: str | None = None
    project_status: int | str = Field(1, description="1 or 'Active' / 0 or 'Inactive'")
    created_by: str | None = None

    @field_validator("project_status", mode="before")
    @classmethod
    def coerce_status(cls, v):
        return _coerce_project_status(v)


class ProjectOut(ORMModel):
    id: int
    project_name: str
    project_details: str | None = None
    project_status: int = Field(1, description="1-Active, 0-Inactive")
    created_on: str | None = None
    created_by: str | None = None
    modified_on: str | None = None
    modified_by: str | None = None
    sbom_count: int = 0


class SBOMTypeOut(ORMModel):
    id: int
    typename: str
    type_details: str | None = None
    created_on: str | None = None
    created_by: str | None = None
    modified_on: str | None = None
    modified_by: str | None = None


class SBOMSourceCreate(BaseModel):
    sbom_name: str
    sbom_data: str | None = None
    sbom_type: int | None = None
    projectid: int | None = None
    sbom_version: str | None = None
    created_by: str | None = None
    productver: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_project_id_alias(cls, data):
        if isinstance(data, dict) and "project_id" in data and "projectid" not in data:
            data = dict(data)
            data["projectid"] = data.get("project_id")
        return data


class LatestAnalysisOut(BaseModel):
    run_id: int
    status: str
    result: str
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float | None = None
    risk_level: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None


class SBOMSourceOut(ORMModel):
    id: int
    sbom_name: str
    sbom_data: str | None = None
    sbom_type: int | None = None
    projectid: int | None = None
    project_id: int | None = None
    project_name: str | None = None
    component_count: int = 0
    created_on: str | None = None
    sbom_version: str | None = None
    parent_id: int | None = None
    change_summary: str | None = None
    completeness_score: float | None = None
    completeness_report: dict[str, Any] | None = None
    created_by: str | None = None
    productver: str | None = None
    modified_on: str | None = None
    modified_by: str | None = None
    name: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    format: str | None = None
    spec_version: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    description: str | None = None

    # 8-stage validation outcome — populated by POST /api/sboms and
    # POST /api/sboms/upload. Older rows that predate migration 012 carry
    # the server defaults: status='validated', counts=0, validation_errors
    # absent.
    status: str = "validated"
    failed_stage: str | None = None
    validation_errors: list[dict] | None = None
    error_count: int = 0
    warning_count: int = 0
    validated_at: str | None = None
    workspace_id: int | str | None = None
    validation_session_id: int | str | None = None
    repair_workspace_url: str | None = None
    workspace_available: bool = False
    workspace_source: str | None = None
    workspace_unavailable_reason: str | None = None
    validation_status: str | None = None
    detected_format: str | None = None
    detected_spec_version: str | None = None
    original_size_bytes: int | None = None
    original_sha256: str | None = None

    # SPDX → CycloneDX conversion tracking
    original_format: str | None = None
    current_format: str | None = None
    converted_from_format: str | None = None
    source_sbom_id: int | None = None
    converted_sbom_id: int | None = None
    conversion_status: str | None = None
    conversion_warnings_json: list[dict[str, Any]] | None = None
    conversion_report_json: dict[str, Any] | None = None
    converted_at: str | None = None
    converted_by: str | None = None
    enrichment_status: str | None = None
    conversion_started_at: str | None = None
    conversion_completed_at: str | None = None
    enrichment_started_at: str | None = None
    enrichment_completed_at: str | None = None
    last_enriched_at: str | None = None
    conversion_error: str | None = None
    enrichment_error: str | None = None
    component_extraction_status: str | None = None
    component_extraction_error: str | None = None
    component_extraction_attempted_at: str | None = None
    component_extraction_completed_at: str | None = None
    latest_analysis: LatestAnalysisOut | None = None

    @model_validator(mode="before")
    @classmethod
    def populate_project_id_alias(cls, data):
        if hasattr(data, "projectid"):
            return data
        if isinstance(data, dict) and "project_id" not in data and "projectid" in data:
            data = dict(data)
            data["project_id"] = data.get("projectid")
        return data


class SbomDocumentStatsResponse(BaseModel):
    sbom_id: int
    sbom_name: str
    format: str | None = None
    spec_version: str | None = None
    file_size_bytes: int = 0
    line_count: int = 0
    parsed_component_count: int = 0
    component_count: int = 0
    component_total_rows: int = 0
    duplicate_component_count: int = 0
    dependency_count: int = 0
    relationship_count: int = 0
    content_sha256: str | None = None
    validation_status: str | None = None


class SbomRawChunkResponse(BaseModel):
    sbom_id: int
    offset: int
    limit: int
    total_lines: int
    lines: list[str]
    preview: bool = False
    truncated: bool = False


class ValidationErrorEntry(BaseModel):
    """One entry of the persisted validation report, enriched for the UI.

    Mirrors :class:`app.validation.errors.ValidationError` plus
    ``stage_number`` (1-8 from the canonical pipeline). The frontend's
    error card renders these fields verbatim — every field on this model
    must reach the DOM somewhere.
    """

    code: str
    severity: str
    stage: str
    stage_number: int
    path: str
    message: str
    remediation: str
    spec_reference: str | None = None


class ValidationReportResponse(BaseModel):
    """Full validation report for an SBOM detail page.

    The detail page leads with this when ``status != 'validated'``. The
    summary aggregations (``severity_summary`` / ``stage_summary``) are
    pre-computed server-side so the UI can render badges without
    re-walking ``entries`` for 100+-error reports.
    """

    sbom_id: int
    filename: str
    status: str
    failed_stage: str | None = None
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    entries: list[ValidationErrorEntry] = []
    validated_at: str | None = None
    spec_detected: str | None = None
    spec_version_detected: str | None = None
    severity_summary: dict[str, int] = Field(default_factory=dict)
    stage_summary: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False
    session_id: str | None = None
    workspace_id: int | str | None = None
    validation_session_id: int | str | None = None
    repair_workspace_url: str | None = None
    validation_status: str | None = None
    can_edit: bool = False


class SBOMComponentOut(ORMModel):
    id: int
    sbom_id: int
    bom_ref: str | None = None
    component_type: str | None = None
    component_group: str | None = None
    name: str
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    supplier: str | None = None
    scope: str | None = None
    created_on: str | None = None
    ecosystem: str | None = None
    original_name: str | None = None
    normalized_name: str | None = None
    original_version: str | None = None
    normalized_version: str | None = None
    normalized_ecosystem: str | None = None
    original_purl: str | None = None
    normalized_purl: str | None = None
    purl_type: str | None = None
    purl_namespace: str | None = None
    purl_name: str | None = None
    purl_version: str | None = None
    purl_qualifiers_json: dict[str, Any] | None = None
    purl_subpath: str | None = None
    normalized_cpes: list[str] | None = None
    primary_cpe: str | None = None
    cpe_evidence_json: dict[str, Any] | None = None
    normalized_supplier: str | None = None
    normalized_package_key: str | None = None
    canonical_identity_confidence: str | None = None
    license: str | None = None
    hashes: str | None = None
    lifecycle_status: str | None = None
    eos_date: str | None = None
    eol_date: str | None = None
    eof_date: str | None = None
    is_deprecated: bool | None = None
    deprecated: bool | None = None
    unsupported: bool | None = None
    maintenance_status: str | None = None
    latest_version: str | None = None
    latest_supported_version: str | None = None
    recommended_version: str | None = None
    lifecycle_recommendation: str | None = None
    lifecycle_source: str | None = None
    lifecycle_source_url: str | None = None
    lifecycle_confidence: str | None = None
    lifecycle_checked_at: str | None = None
    lifecycle_evidence_json: dict[str, Any] | None = None
    lifecycle_is_stale: bool | None = None
    lifecycle_manual_override: bool | None = None
    normalized_component_key: str | None = None
    dedupe_canonical_id: str | None = None
    dedupe_group_id: str | None = None
    is_duplicate: bool | None = False
    duplicate_of_component_id: int | None = None
    dedupe_reason: str | None = None
    dedupe_confidence: str | None = None
    normalization_notes_json: list[str] | None = None
    dedupe_evidence_json: dict[str, Any] | None = None


class SBOMComponentListItem(SBOMComponentOut):
    """Component row enriched for list views (canonical duplicate references)."""

    canonical_component_name: str | None = None
    canonical_component_version: str | None = None
    duplicate_reason: str | None = None


class SBOMComponentListResponse(BaseModel):
    items: list[SBOMComponentListItem]
    total_count: int
    unique_count: int
    duplicate_count: int
    include_duplicates: bool
    page: int
    page_size: int


class AnalysisRunOut(ORMModel):
    id: int
    sbom_id: int
    project_id: int | None = None
    run_status: str
    sbom_name: str | None = None
    source: str
    started_on: str
    completed_on: str
    duration_ms: int
    total_components: int
    components_with_cpe: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unknown_count: int
    query_error_count: int
    raw_report: str | None = None


class RunsAggregateBuckets(BaseModel):
    """Run-status outcome counts. Sums to ``total_runs`` (I-A invariant)."""

    no_issues: int  # OK
    with_findings: int  # FINDINGS
    source_errors: int  # PARTIAL
    failed: int  # ERROR
    other: int  # RUNNING / PENDING / NO_DATA / future codes


class RunsAggregateOut(BaseModel):
    """Server-side aggregate for the Analysis Runs page tiles.

    Replaces the FE-side reduce that filtered on legacy ``PASS``/``FAIL``
    strings (audit §I0.4-F1) and silently undercounted above 100 runs (F2).
    """

    total_runs: int
    by_outcome: RunsAggregateBuckets
    total_findings: int


class VulnerabilityRemediationOut(ORMModel):
    id: int | None = None
    status: str
    owner: str | None = None
    due_date: str | None = None
    resolution_date: str | None = None
    fix_notes: str | None = None
    fixed_version: str | None = None
    updated_on: str | None = None


class AnalysisFindingOut(ORMModel):
    id: int
    analysis_run_id: int
    component_id: int | None = None
    vuln_id: str
    source: str | None = None
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    score: float | None = None
    vector: str | None = None
    published_on: str | None = None
    reference_url: str | None = None
    cwe: str | None = None
    cpe: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    fixed_versions: str | None = None  # raw JSON string
    attack_vector: str | None = None
    cvss_version: str | None = None
    aliases: str | None = None  # JSON string
    remediation: VulnerabilityRemediationOut | None = None


class ProjectUpdate(BaseModel):
    project_name: str | None = None
    project_details: str | None = None
    project_status: int | str | None = Field(default=None)
    modified_by: str | None = None

    @field_validator("project_status", mode="before")
    @classmethod
    def coerce_status(cls, v):
        if v is None:
            return None
        return _coerce_project_status(v)


class SBOMSourceUpdate(BaseModel):
    sbom_name: str | None = None
    sbom_data: str | None = None
    sbom_type: int | None = None
    projectid: int | None = None
    sbom_version: str | None = None
    productver: str | None = None
    modified_by: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_project_id_alias(cls, data):
        if isinstance(data, dict) and "project_id" in data and "projectid" not in data:
            data = dict(data)
            data["projectid"] = data.get("project_id")
        return data


class SbomPatchRequest(BaseModel):
    project_id: int | None = None
    name: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    sbom_version: str | None = None
    description: str | None = None
    change_reason: str | None = None


# ---------------------------------------------------------------------------
# Periodic analysis schedules
# ---------------------------------------------------------------------------

_VALID_CADENCES = {"DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "CUSTOM"}


class ScheduleUpsert(BaseModel):
    """
    Friendly create/update payload — the API accepts cadence presets and
    derives the cron expression server-side. CUSTOM cadence is for power
    users only and surfaces under an "Advanced" disclosure in the UI.
    """

    cadence: str = Field(..., description="DAILY|WEEKLY|BIWEEKLY|MONTHLY|QUARTERLY|CUSTOM")
    cron_expression: str | None = Field(None, description="5-field cron, only when cadence=CUSTOM")
    day_of_week: int | None = Field(None, ge=0, le=6, description="0=Mon..6=Sun (WEEKLY/BIWEEKLY)")
    day_of_month: int | None = Field(None, ge=1, le=28, description="1..28 (MONTHLY/QUARTERLY)")
    hour_utc: int = Field(2, ge=0, le=23)
    timezone: str = Field("UTC", description="IANA name; display only — firing is computed in UTC")
    enabled: bool = True
    min_gap_minutes: int = Field(
        60,
        ge=0,
        le=24 * 60,
        description="Skip a tick if a manual or prior run completed within this many minutes",
    )
    modified_by: str | None = None

    @field_validator("cadence", mode="before")
    @classmethod
    def _upper_cadence(cls, v: str) -> str:
        if not isinstance(v, str):
            return v
        return v.strip().upper()

    @field_validator("cadence")
    @classmethod
    def _check_cadence(cls, v: str) -> str:
        if v not in _VALID_CADENCES:
            raise ValueError(f"cadence must be one of {sorted(_VALID_CADENCES)}")
        return v


class ScheduleOut(ORMModel):
    id: int
    scope: str  # 'PROJECT' | 'SBOM'
    project_id: int | None = None
    sbom_id: int | None = None
    cadence: str
    cron_expression: str | None = None
    day_of_week: int | None = None
    day_of_month: int | None = None
    hour_utc: int
    timezone: str
    enabled: bool
    next_run_at: str | None = None
    last_run_at: str | None = None
    last_run_status: str | None = None
    last_run_id: int | None = None
    consecutive_failures: int = 0
    min_gap_minutes: int = 60
    created_on: str | None = None
    created_by: str | None = None
    modified_on: str | None = None
    modified_by: str | None = None


class ScheduleResolved(BaseModel):
    """
    Returned by ``GET /api/sboms/{id}/schedule``. The ``schedule`` field
    is the effective row (own override or inherited from project), or
    ``None`` if neither exists. ``inherited`` is true when the SBOM is
    currently following its project's cascade.
    """

    inherited: bool
    schedule: ScheduleOut | None = None


# --- SBOM Lifecycle Management Platform schemas ---


class LifecycleInfoUpdate(BaseModel):
    lifecycle_status: str
    eos_date: str | None = None
    eol_date: str | None = None
    eof_date: str | None = None
    is_deprecated: bool = False
    deprecated: bool | None = None
    unsupported: bool | None = None
    maintenance_status: str | None = None
    latest_version: str | None = None
    latest_supported_version: str | None = None
    recommended_version: str | None = None
    recommendation: str | None = None
    lifecycle_recommendation: str | None = None
    evidence_url: str | None = None
    lifecycle_source_url: str | None = None
    reason: str | None = None
    note: str | None = None
    evidence: dict[str, Any] | None = None
    updated_by: str | None = None


class VulnerabilityRemediationUpsert(BaseModel):
    vuln_id: str
    component_name: str
    component_version: str
    fixed_version: str | None = None
    status: str  # Open, In Progress, Fixed, Accepted Risk, Closed
    owner: str | None = None
    due_date: str | None = None  # YYYY-MM-DD
    resolution_date: str | None = None  # YYYY-MM-DD
    fix_notes: str | None = None


class VulnerabilityRemediationOut(ORMModel):
    id: int
    project_id: int
    vuln_id: str
    component_name: str
    component_version: str
    fixed_version: str | None = None
    status: str
    owner: str | None = None
    due_date: str | None = None
    resolution_date: str | None = None
    fix_notes: str | None = None
    created_on: str
    updated_on: str


class VulnerabilityRemediationAuditOut(ORMModel):
    id: int
    remediation_id: int
    project_id: int
    vuln_id: str
    component_name: str
    component_version: str
    old_status: str | None = None
    new_status: str
    changed_by: str | None = None
    changed_at: str
    note: str | None = None


class ComponentEditPayload(BaseModel):
    bom_ref: str
    name: str | None = None
    version: str | None = None
    supplier: str | None = None
    license: str | None = None
    hashes: str | None = None
    lifecycle: dict[str, Any] | None = None


class SbomEditPayload(BaseModel):
    metadata: dict[str, Any] | None = None
    components: list[ComponentEditPayload] = []
    change_summary: str = "Manual edit via UI"


class SbomConversionResponse(BaseModel):
    source_sbom_id: int
    converted_sbom_id: int
    source_format: str
    target_format: str
    status: str
    conversion_status: str
    enrichment_status: str
    message: str
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    conversion_report: dict[str, Any] = Field(default_factory=dict)


class SbomConversionReportResponse(BaseModel):
    source_format: str | None = None
    target_format: str | None = None
    converted_at: str | None = None
    converted_by: str | None = None
    source_sbom_id: int | None = None
    converted_sbom_id: int | None = None
    conversion_status: str | None = None
    enrichment_status: str | None = None
    package_count: int = 0
    component_count: int = 0
    mapped_relationships: int = 0
    unmapped_relationships: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    unmapped_fields: list[str] = Field(default_factory=list)
    component_mapping: dict[str, str] = Field(default_factory=dict)
    relationship_mapping: list[dict[str, Any]] = Field(default_factory=list)
    conversion_report: dict[str, Any] = Field(default_factory=dict)
