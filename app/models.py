# models.py

from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .db import Base


class Projects(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, nullable=False, index=True)
    project_details = Column(String, nullable=True)
    project_status = Column(Integer, nullable=False, default=1)  # 1-Active, 0-Inactive
    created_on = Column(String, nullable=True)
    created_by = Column(String, nullable=True, index=True)
    modified_on = Column(String, nullable=True)
    modified_by = Column(String, nullable=True)

    sboms = relationship("SBOMSource", back_populates="project")
    analysis_runs = relationship("AnalysisRun", back_populates="project")


class SBOMType(Base):
    __tablename__ = "sbom_type"

    id = Column(Integer, primary_key=True, index=True)
    typename = Column(String, nullable=False, unique=True)
    type_details = Column(String, nullable=True)
    created_on = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    modified_on = Column(String, nullable=True)
    modified_by = Column(String, nullable=True)

    sboms = relationship("SBOMSource", back_populates="sbom_type_rel")


class SBOMSource(Base):
    __tablename__ = "sbom_source"

    id = Column(Integer, primary_key=True, index=True)
    sbom_name = Column(String, nullable=False, index=True)
    sbom_data = Column(Text, nullable=True)
    sbom_type = Column(Integer, ForeignKey("sbom_type.id"), nullable=True)
    projectid = Column(Integer, ForeignKey("projects.id"), nullable=True)
    created_on = Column(String, nullable=True)
    sbom_version = Column(String, nullable=True)
    created_by = Column(String, nullable=True, index=True)
    productver = Column(String, nullable=True)
    modified_on = Column(String, nullable=True)
    modified_by = Column(String, nullable=True)

    project = relationship("Projects", back_populates="sboms")
    sbom_type_rel = relationship("SBOMType", back_populates="sboms")
    analysis_reports = relationship("SBOMAnalysisReport", back_populates="sbom")
    components = relationship("SBOMComponent", back_populates="sbom")
    analysis_runs = relationship("AnalysisRun", back_populates="sbom")


class SBOMAnalysisReport(Base):
    __tablename__ = "sbom_analysis_report"

    id = Column(Integer, primary_key=True, index=True)
    sbom_ref_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=True)
    sbom_result = Column(String, nullable=True)
    project_id = Column(String, nullable=True)  # kept for backward compatibility
    created_on = Column(String, nullable=True)
    analysis_details = Column(Text, nullable=True)
    reference_source = Column(String, nullable=True)
    sbom_analysis_level = Column(Integer, nullable=True)

    sbom = relationship("SBOMSource", back_populates="analysis_reports")


class SBOMComponent(Base):
    __tablename__ = "sbom_component"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=False, index=True)
    bom_ref = Column(String, nullable=True)
    component_type = Column(String, nullable=True)
    component_group = Column(String, nullable=True)
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True, index=True)
    purl = Column(String, nullable=True)
    cpe = Column(String, nullable=True, index=True)
    supplier = Column(String, nullable=True)
    scope = Column(String, nullable=True)
    created_on = Column(String, nullable=True)

    sbom = relationship("SBOMSource", back_populates="components")
    findings = relationship("AnalysisFinding", back_populates="component")

    __table_args__ = (
        UniqueConstraint(
            "sbom_id",
            "bom_ref",
            "name",
            "version",
            "cpe",
            name="uq_sbom_component_fingerprint",
        ),
        Index("ix_sbom_component_sbom_name", "sbom_id", "name"),
    )


class AnalysisRun(Base):
    __tablename__ = "analysis_run"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=False, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)

    run_status = Column(String, nullable=False, index=True)
    sbom_name = Column(String, nullable=True)
    source = Column(String, nullable=False, default="NVD")

    started_on = Column(String, nullable=False)
    completed_on = Column(String, nullable=False)
    duration_ms = Column(Integer, nullable=False, default=0)

    total_components = Column(Integer, nullable=False, default=0)
    components_with_cpe = Column(Integer, nullable=False, default=0)
    total_findings = Column(Integer, nullable=False, default=0)

    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    unknown_count = Column(Integer, nullable=False, default=0)
    query_error_count = Column(Integer, nullable=False, default=0)

    raw_report = Column(Text, nullable=True)

    sbom = relationship("SBOMSource", back_populates="analysis_runs")
    project = relationship("Projects", back_populates="analysis_runs")
    findings = relationship("AnalysisFinding", back_populates="analysis_run")


class AnalysisFinding(Base):
    __tablename__ = "analysis_finding"

    id = Column(Integer, primary_key=True, index=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_run.id"), nullable=False, index=True)
    component_id = Column(Integer, ForeignKey("sbom_component.id"), nullable=True, index=True)

    vuln_id = Column(String, nullable=False, index=True)
    source = Column(String, nullable=True)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True, index=True)
    score = Column(Float, nullable=True)
    vector = Column(String, nullable=True)
    published_on = Column(String, nullable=True)
    reference_url = Column(String, nullable=True)
    cwe = Column(Text, nullable=True)

    cpe = Column(String, nullable=True, index=True)
    component_name = Column(String, nullable=True)
    component_version = Column(String, nullable=True)

    fixed_versions = Column(Text, nullable=True)   # JSON array stored as string
    attack_vector = Column(String, nullable=True)
    cvss_version = Column(String, nullable=True)
    aliases = Column(Text, nullable=True)           # JSON array as string

    analysis_run = relationship("AnalysisRun", back_populates="findings")
    component = relationship("SBOMComponent", back_populates="findings")

    __table_args__ = (
        UniqueConstraint(
            "analysis_run_id", "vuln_id", "cpe", name="uq_analysis_finding_run_vuln_cpe"
        ),
        Index("ix_analysis_finding_run_severity", "analysis_run_id", "severity"),
    )


class RunCache(Base):
    """
    Persists the raw JSON payload returned by the ad-hoc analysis endpoints
    (NVD / GitHub / OSV / Consolidated).  The id returned here IS the runId
    clients use to request a PDF report — no more in-memory-only storage.
    """
    __tablename__ = "run_cache"

    id = Column(Integer, primary_key=True, index=True)
    run_json = Column(Text, nullable=False)
    created_on = Column(String, nullable=True)
    source = Column(String, nullable=True)      # "consolidated"|"nvd"|"osv"|"ghsa"
    sbom_id = Column(Integer, nullable=True)    # for cache invalidation
