# schemas.py

from typing import Optional, Union

from pydantic import BaseModel, Field, field_validator


def _coerce_project_status(v) -> int:
    """Accept 'Active'/'Inactive' strings or 0/1 integers."""
    if isinstance(v, str):
        return 1 if v.strip().lower() == 'active' else 0
    return int(v)


class ORMModel(BaseModel):
    class Config:
        from_attributes = True


class ProjectCreate(BaseModel):
    project_name: str
    project_details: Optional[str] = None
    project_status: Union[int, str] = Field(1, description="1 or 'Active' / 0 or 'Inactive'")
    created_by: Optional[str] = None

    @field_validator('project_status', mode='before')
    @classmethod
    def coerce_status(cls, v):
        return _coerce_project_status(v)


class ProjectOut(ORMModel):
    id: int
    project_name: str
    project_details: Optional[str] = None
    project_status: int = Field(1, description="1-Active, 0-Inactive")
    created_on: Optional[str] = None
    created_by: Optional[str] = None
    modified_on: Optional[str] = None
    modified_by: Optional[str] = None


class SBOMTypeCreate(BaseModel):
    typename: str
    type_details: Optional[str] = None
    created_by: Optional[str] = None


class SBOMTypeOut(ORMModel):
    id: int
    typename: str
    type_details: Optional[str] = None
    created_on: Optional[str] = None
    created_by: Optional[str] = None
    modified_on: Optional[str] = None
    modified_by: Optional[str] = None


class SBOMSourceCreate(BaseModel):
    sbom_name: str
    sbom_data: Optional[str] = None
    sbom_type: Optional[int] = None
    projectid: Optional[int] = None
    sbom_version: Optional[str] = None
    created_by: Optional[str] = None
    productver: Optional[str] = None


class SBOMSourceOut(ORMModel):
    id: int
    sbom_name: str
    sbom_data: Optional[str] = None
    sbom_type: Optional[int] = None
    projectid: Optional[int] = None
    created_on: Optional[str] = None
    sbom_version: Optional[str] = None
    created_by: Optional[str] = None
    productver: Optional[str] = None
    modified_on: Optional[str] = None
    modified_by: Optional[str] = None


class SBOMComponentOut(ORMModel):
    id: int
    sbom_id: int
    bom_ref: Optional[str] = None
    component_type: Optional[str] = None
    component_group: Optional[str] = None
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    supplier: Optional[str] = None
    scope: Optional[str] = None
    created_on: Optional[str] = None


class AnalysisRunOut(ORMModel):
    id: int
    sbom_id: int
    project_id: Optional[int] = None
    run_status: str
    sbom_name: Optional[str] = None
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
    raw_report: Optional[str] = None


class AnalysisFindingOut(ORMModel):
    id: int
    analysis_run_id: int
    component_id: Optional[int] = None
    vuln_id: str
    source: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    vector: Optional[str] = None
    published_on: Optional[str] = None
    reference_url: Optional[str] = None
    cwe: Optional[str] = None
    cpe: Optional[str] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    fixed_versions: Optional[str] = None    # raw JSON string
    attack_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    aliases: Optional[str] = None           # JSON string


class AnalysisRunSummary(ORMModel):
    """Lightweight run summary for list endpoints — excludes raw_report."""
    id: int
    sbom_id: int
    project_id: Optional[int] = None
    run_status: str
    sbom_name: Optional[str] = None
    source: str
    started_on: str
    completed_on: str
    duration_ms: int
    total_components: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class SBOMAnalysisReportCreate(BaseModel):
    sbom_ref_id: Optional[int] = None
    sbom_result: Optional[str] = None
    project_id: Optional[str] = None
    analysis_details: Optional[str] = None
    reference_source: Optional[str] = None
    sbom_analysis_level: Optional[int] = None


class ProjectUpdate(BaseModel):
    project_name: Optional[str] = None
    project_details: Optional[str] = None
    project_status: Optional[Union[int, str]] = Field(default=None)
    modified_by: Optional[str] = None

    @field_validator('project_status', mode='before')
    @classmethod
    def coerce_status(cls, v):
        if v is None:
            return None
        return _coerce_project_status(v)


class SBOMSourceUpdate(BaseModel):
    sbom_name: Optional[str] = None
    sbom_data: Optional[str] = None
    sbom_type: Optional[int] = None
    projectid: Optional[int] = None
    sbom_version: Optional[str] = None
    productver: Optional[str] = None
    modified_by: Optional[str] = None


class SBOMAnalysisReportOut(ORMModel):
    id: int
    sbom_ref_id: Optional[int] = None
    sbom_result: Optional[str] = None
    project_id: Optional[str] = None
    created_on: Optional[str] = None
    analysis_details: Optional[str] = None
    reference_source: Optional[str] = None
    sbom_analysis_level: Optional[int] = None
