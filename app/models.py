# models.py

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
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

    fixed_versions = Column(Text, nullable=True)  # JSON array stored as string
    attack_vector = Column(String, nullable=True)
    cvss_version = Column(String, nullable=True)
    aliases = Column(Text, nullable=True)  # JSON array as string

    analysis_run = relationship("AnalysisRun", back_populates="findings")
    component = relationship("SBOMComponent", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("analysis_run_id", "vuln_id", "cpe", name="uq_analysis_finding_run_vuln_cpe"),
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
    source = Column(String, nullable=True)  # "consolidated"|"nvd"|"osv"|"ghsa"
    sbom_id = Column(Integer, nullable=True)  # for cache invalidation


class KevEntry(Base):
    """
    Cached row from the CISA Known Exploited Vulnerabilities catalog
    (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

    We refresh once per 24h. Presence of a row implies the CVE is on the
    KEV list — which is the single highest-signal exploitability indicator
    in public vulnerability data.
    """

    __tablename__ = "kev_entry"

    cve_id = Column(String, primary_key=True, index=True)
    vendor_project = Column(String, nullable=True)
    product = Column(String, nullable=True)
    vulnerability_name = Column(String, nullable=True)
    date_added = Column(String, nullable=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(Text, nullable=True)
    due_date = Column(String, nullable=True)
    known_ransomware_use = Column(String, nullable=True)  # "Known"/"Unknown"
    refreshed_at = Column(String, nullable=False)  # ISO timestamp


class AnalysisSchedule(Base):
    """
    Periodic analysis schedule. One row per scope target (PROJECT or SBOM).

    A project-level row applies to every SBOM in the project at tick time;
    an SBOM-level row overrides the cascade for that one SBOM.
    """

    __tablename__ = "analysis_schedule"

    id = Column(Integer, primary_key=True, index=True)
    scope = Column(String(16), nullable=False)  # 'PROJECT' | 'SBOM'

    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=True, index=True)

    cadence = Column(String(16), nullable=False)  # DAILY|WEEKLY|BIWEEKLY|MONTHLY|QUARTERLY|CUSTOM
    cron_expression = Column(String(128), nullable=True)  # set only when cadence='CUSTOM'
    day_of_week = Column(Integer, nullable=True)  # 0=Mon..6=Sun for WEEKLY/BIWEEKLY
    day_of_month = Column(Integer, nullable=True)  # 1..28 for MONTHLY/QUARTERLY
    hour_utc = Column(Integer, nullable=False, default=2)
    timezone = Column(String(64), nullable=False, default="UTC")

    enabled = Column(Boolean, nullable=False, default=True)

    next_run_at = Column(String, nullable=True, index=True)
    last_run_at = Column(String, nullable=True)
    last_run_status = Column(String(16), nullable=True)
    last_run_id = Column(Integer, ForeignKey("analysis_run.id", ondelete="SET NULL"), nullable=True)

    consecutive_failures = Column(Integer, nullable=False, default=0)
    min_gap_minutes = Column(Integer, nullable=False, default=60)

    created_on = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    modified_on = Column(String, nullable=True)
    modified_by = Column(String, nullable=True)

    project = relationship("Projects", foreign_keys=[project_id])
    sbom = relationship("SBOMSource", foreign_keys=[sbom_id])

    __table_args__ = (
        CheckConstraint("scope IN ('PROJECT','SBOM')", name="ck_analysis_schedule_scope"),
        CheckConstraint(
            "cadence IN ('DAILY','WEEKLY','BIWEEKLY','MONTHLY','QUARTERLY','CUSTOM')",
            name="ck_analysis_schedule_cadence",
        ),
        CheckConstraint(
            "(scope = 'PROJECT' AND project_id IS NOT NULL AND sbom_id IS NULL) "
            "OR (scope = 'SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL)",
            name="ck_analysis_schedule_target",
        ),
        CheckConstraint("hour_utc BETWEEN 0 AND 23", name="ck_analysis_schedule_hour_range"),
        CheckConstraint(
            "day_of_week IS NULL OR day_of_week BETWEEN 0 AND 6",
            name="ck_analysis_schedule_dow_range",
        ),
        CheckConstraint(
            "day_of_month IS NULL OR day_of_month BETWEEN 1 AND 28",
            name="ck_analysis_schedule_dom_range",
        ),
        Index("ix_analysis_schedule_due", "enabled", "next_run_at"),
    )


class EpssScore(Base):
    """
    Cached EPSS (Exploit Prediction Scoring System) score for a CVE.
    Source: FIRST.org EPSS API (https://api.first.org/data/v1/epss).

    Each row is a per-CVE snapshot. We refresh per-CVE on-demand on a
    24h TTL to keep the cache hot for active SBOMs without bulk-syncing
    the full ~250k-CVE catalog. Missing rows = "not yet looked up" — the
    scorer treats them as 0.0 (median EPSS is ~0.001 anyway, so the
    impact of a miss is small).
    """

    __tablename__ = "epss_score"

    cve_id = Column(String, primary_key=True, index=True)
    epss = Column(Float, nullable=False, default=0.0)  # probability 0..1
    percentile = Column(Float, nullable=True)  # 0..1
    score_date = Column(String, nullable=True)  # date EPSS published
    refreshed_at = Column(String, nullable=False)  # ISO timestamp of our pull


class CveCache(Base):
    """
    Merged CVE detail payload (OSV + GHSA + NVD + EPSS + KEV).

    Keyed by canonical ``CVE-YYYY-NNNN+`` ID. Holds the full ``CveDetail``
    JSON the modal renders. TTL is enforced at upsert time by
    ``CveDetailService`` — readers just compare ``expires_at`` to ``now()``.
    A row with non-null ``fetch_error`` is a negative cache entry kept for a
    short window (15 min) so we don't hammer upstreams during outages.
    """

    __tablename__ = "cve_cache"

    cve_id = Column(String(32), primary_key=True, index=True)
    payload = Column(JSON, nullable=False)
    sources_used = Column(String(128), nullable=False)  # comma-joined
    fetched_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    fetch_error = Column(Text, nullable=True)
    schema_version = Column(Integer, nullable=False, default=1)


class CompareCache(Base):
    """
    Cached ``CompareResult`` payload (ADR-0008).

    Keyed by ``sha256(f"{min(a,b)}:{max(a,b)}")`` so the same cache row is
    reused regardless of which order the user picks the runs. Run-id indices
    on both sides support O(1) invalidation when either run is reanalysed
    (Celery completion hook deletes ``WHERE run_a_id = :id OR run_b_id = :id``).
    """

    __tablename__ = "compare_cache"

    cache_key = Column(String(64), primary_key=True)
    run_a_id = Column(Integer, nullable=False, index=True)
    run_b_id = Column(Integer, nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    computed_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    schema_version = Column(Integer, nullable=False, default=1)
