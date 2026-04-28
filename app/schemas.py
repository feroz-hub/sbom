# schemas.py


from pydantic import BaseModel, Field, field_validator


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


class SBOMSourceOut(ORMModel):
    id: int
    sbom_name: str
    sbom_data: str | None = None
    sbom_type: int | None = None
    projectid: int | None = None
    created_on: str | None = None
    sbom_version: str | None = None
    created_by: str | None = None
    productver: str | None = None
    modified_on: str | None = None
    modified_by: str | None = None


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
