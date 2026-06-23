# models.py

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    text as sql_text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from .db import Base
from .models_mixins import SoftDeleteMixin, TenantOwnedMixin


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), nullable=False, index=True)
    external_iam_tenant_id = Column(String(255), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="ACTIVE")
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("slug", name="uq_tenants_slug"),
        UniqueConstraint("external_iam_tenant_id", name="uq_tenants_external_iam_tenant_id"),
    )


class IAMUser(Base):
    __tablename__ = "iam_users"

    id = Column(Integer, primary_key=True)
    external_iam_user_id = Column(String(255), nullable=False, index=True)
    email = Column(String(320), nullable=True, index=True)
    display_name = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE")
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("external_iam_user_id", name="uq_iam_users_external_iam_user_id"),)


class TenantUser(Base):
    __tablename__ = "tenant_users"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE")
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)

    tenant = relationship("Tenant")
    user = relationship("IAMUser")

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_users_tenant_user"),
        Index("ix_tenant_users_tenant_status", "tenant_id", "status"),
    )


class Projects(Base, SoftDeleteMixin, TenantOwnedMixin):
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
    schedules = relationship(
        "AnalysisSchedule",
        primaryjoin="Projects.id == foreign(AnalysisSchedule.project_id)",
        viewonly=True,
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_name", name="uq_projects_tenant_name"),
        Index("ix_projects_tenant_created", "tenant_id", "created_on"),
    )

    @property
    def sbom_count(self) -> int:
        return len([sbom for sbom in (self.sboms or []) if not getattr(sbom, "deleted_at", None)])


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


class SBOMSource(Base, SoftDeleteMixin, TenantOwnedMixin):
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
    parent_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=True)
    change_summary = Column(String, nullable=True)
    completeness_score = Column(Float, nullable=True, default=100.0)
    completeness_report = Column(JSON, nullable=True)
    dedupe_report_json = Column(JSON, nullable=True)
    product_name = Column(String, nullable=True)
    description = Column(String, nullable=True)

    # 8-stage validation outcome — see migration 012.
    # ``server_default`` mirrors migration 012's literals so test-path
    # schemas built via ``Base.metadata.create_all`` carry the same
    # NOT NULL safety net that production migrations install.
    status = Column(
        String(24),
        nullable=False,
        default="validated",
        server_default="validated",
        index=True,
    )
    failed_stage = Column(String(32), nullable=True, index=True)
    validation_errors = Column(JSON, nullable=True)
    error_count = Column(Integer, nullable=False, default=0, server_default="0")
    warning_count = Column(Integer, nullable=False, default=0, server_default="0")
    validated_at = Column(String, nullable=True)

    # SPDX → CycloneDX conversion tracking — see migration 029.
    original_format = Column(String(32), nullable=True)
    current_format = Column(String(32), nullable=True)
    converted_from_format = Column(String(32), nullable=True)
    source_sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=True, index=True)
    converted_sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=True, index=True)
    conversion_status = Column(String(32), nullable=True, index=True)
    conversion_warnings_json = Column(JSON, nullable=True)
    conversion_report_json = Column(JSON, nullable=True)
    converted_at = Column(String, nullable=True)
    converted_by = Column(String, nullable=True)
    enrichment_status = Column(String(32), nullable=True, index=True)
    conversion_started_at = Column(String, nullable=True)
    conversion_completed_at = Column(String, nullable=True)
    enrichment_started_at = Column(String, nullable=True)
    enrichment_completed_at = Column(String, nullable=True)
    conversion_error = Column(Text, nullable=True)
    enrichment_error = Column(Text, nullable=True)

    project = relationship("Projects", back_populates="sboms")
    sbom_type_rel = relationship("SBOMType", back_populates="sboms")
    analysis_reports = relationship("SBOMAnalysisReport", back_populates="sbom")
    components = relationship("SBOMComponent", back_populates="sbom")
    vex_documents = relationship("VexDocument", back_populates="sbom")
    analysis_runs = relationship("AnalysisRun", back_populates="sbom")
    schedules = relationship(
        "AnalysisSchedule",
        primaryjoin="SBOMSource.id == foreign(AnalysisSchedule.sbom_id)",
        viewonly=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "sbom_name",
            "sbom_version",
            name="uq_sbom_source_tenant_name_version",
        ),
        Index("ix_sbom_source_tenant_project", "tenant_id", "projectid"),
        Index("ix_sbom_source_tenant_created", "tenant_id", "created_on"),
    )

    @property
    def project_id(self) -> int | None:
        return self.projectid

    @property
    def project_name(self) -> str | None:
        return self.project.project_name if self.project else None

    @property
    def component_count(self) -> int:
        return len([component for component in (self.components or []) if not getattr(component, "deleted_at", None)])

    @property
    def name(self) -> str:
        return self.sbom_name

    @property
    def product_version(self) -> str | None:
        return self.productver

    @property
    def created_at(self) -> str | None:
        return self.created_on

    @property
    def updated_at(self) -> str | None:
        return self.modified_on

    @property
    def last_enriched_at(self) -> str | None:
        return self.enrichment_completed_at

    @property
    def format(self) -> str:
        import json

        if not self.sbom_data:
            return "—"
        try:
            as_dict = json.loads(self.sbom_data) if isinstance(self.sbom_data, str) else self.sbom_data
            if isinstance(as_dict, dict):
                if as_dict.get("bomFormat") == "CycloneDX":
                    return "cyclonedx"
                if "spdxVersion" in as_dict:
                    return "spdx"
        except Exception:
            pass
        return "—"

    @property
    def spec_version(self) -> str:
        import json

        if not self.sbom_data:
            return "—"
        try:
            as_dict = json.loads(self.sbom_data) if isinstance(self.sbom_data, str) else self.sbom_data
            if isinstance(as_dict, dict):
                if as_dict.get("bomFormat") == "CycloneDX":
                    return str(as_dict.get("specVersion") or "—")
                if "spdxVersion" in as_dict:
                    return str(as_dict.get("spdxVersion") or "—")
        except Exception:
            pass
        return "—"


class SBOMValidationSession(Base, TenantOwnedMixin):
    """Temporary repair workspace for SBOMs that failed validation.

    Rows in this table are not trusted SBOM records. They hold staged content
    only until the same validation pipeline passes and import creates an
    ``SBOMSource`` row.
    """

    __tablename__ = "sbom_validation_sessions"

    id = Column(String(36), primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)
    user_id = Column(String(128), nullable=True, index=True)
    original_filename = Column(String(255), nullable=True)
    sbom_name = Column(String(255), nullable=True)
    sbom_type = Column(Integer, ForeignKey("sbom_type.id"), nullable=True)
    detected_format = Column(String(64), nullable=True)
    detected_version = Column(String(64), nullable=True)
    sanitized_content = Column(Text, nullable=True)
    current_content = Column(Text, nullable=True)
    validation_status = Column(String(32), nullable=False, default="failed", server_default="failed", index=True)
    latest_error_report_json = Column(JSON, nullable=True)
    can_edit = Column(Boolean, nullable=False, default=True, server_default=expression.true())
    can_ai_fix = Column(Boolean, nullable=False, default=True, server_default=expression.true())
    security_blocked_reason = Column(Text, nullable=True)
    content_sha256 = Column(String(64), nullable=True, index=True)
    created_at = Column(String, nullable=False, index=True)
    updated_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    imported_sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=True, index=True)

    events = relationship(
        "SBOMValidationSessionEvent",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="SBOMValidationSessionEvent.id",
    )
    imported_sbom = relationship("SBOMSource", foreign_keys=[imported_sbom_id])


class SBOMValidationSessionEvent(Base, TenantOwnedMixin):
    """Append-only audit history for validation repair sessions."""

    __tablename__ = "sbom_validation_session_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(
        String(36),
        ForeignKey("sbom_validation_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(64), nullable=False, index=True)
    actor_user_id = Column(String(128), nullable=True, index=True)
    timestamp = Column(String, nullable=False, index=True)
    summary = Column(Text, nullable=True)
    before_hash = Column(String(64), nullable=True)
    after_hash = Column(String(64), nullable=True)
    metadata_json = Column(JSON, nullable=True)

    session = relationship("SBOMValidationSession", back_populates="events")


class SBOMAnalysisReport(Base, SoftDeleteMixin, TenantOwnedMixin):
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


class SBOMComponent(Base, SoftDeleteMixin, TenantOwnedMixin):
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
    cpe_source = Column(String(32), nullable=True, index=True)
    supplier = Column(String, nullable=True)
    scope = Column(String, nullable=True)
    created_on = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True, index=True)

    license = Column(String, nullable=True)
    hashes = Column(Text, nullable=True)
    lifecycle_status = Column(String, nullable=True)
    eos_date = Column(String, nullable=True)
    eol_date = Column(String, nullable=True)
    eof_date = Column(String, nullable=True)
    is_deprecated = Column(Boolean, default=False)
    deprecated = Column(Boolean, nullable=True, default=False)
    unsupported = Column(Boolean, nullable=True, default=False)
    maintenance_status = Column(String, nullable=True)
    latest_version = Column(String, nullable=True)
    latest_supported_version = Column(String, nullable=True)
    recommended_version = Column(String, nullable=True)
    lifecycle_recommendation = Column(Text, nullable=True)
    lifecycle_source = Column(String, nullable=True)
    lifecycle_source_url = Column(String, nullable=True)
    lifecycle_confidence = Column(String, nullable=True)
    lifecycle_checked_at = Column(String, nullable=True, index=True)
    lifecycle_evidence_json = Column(JSON, nullable=True)
    lifecycle_is_stale = Column(Boolean, nullable=False, default=False)
    lifecycle_manual_override = Column(Boolean, nullable=False, default=False)

    normalized_component_key = Column(String, nullable=True, index=True)
    is_duplicate = Column(Boolean, nullable=False, default=False)
    duplicate_of_component_id = Column(Integer, ForeignKey("sbom_component.id", ondelete="CASCADE"), nullable=True)

    sbom = relationship("SBOMSource", back_populates="components")
    findings = relationship("AnalysisFinding", back_populates="component")
    vex_statements = relationship("VexStatement", back_populates="component")

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "sbom_id",
            "bom_ref",
            "name",
            "version",
            "cpe",
            name="uq_sbom_component_fingerprint",
        ),
        Index("ix_sbom_component_sbom_name", "sbom_id", "name"),
        Index("ix_sbom_component_lifecycle", "lifecycle_status", "ecosystem"),
    )


class ComponentLifecycleCache(Base):
    """Normalized lifecycle enrichment cache shared across SBOMs."""

    __tablename__ = "component_lifecycle_cache"

    id = Column(Integer, primary_key=True, index=True)
    lookup_key = Column(String, nullable=True, index=True)
    normalized_name = Column(String, nullable=False, index=True)
    normalized_version = Column(String, nullable=True, index=True)
    ecosystem = Column(String, nullable=True, index=True)
    purl = Column(String, nullable=True, index=True)
    cpe = Column(String, nullable=True, index=True)
    lifecycle_status = Column(String, nullable=True)
    eos_date = Column(String, nullable=True)
    eol_date = Column(String, nullable=True)
    eof_date = Column(String, nullable=True)
    deprecated = Column(Boolean, nullable=True, default=False)
    unsupported = Column(Boolean, nullable=True, default=False)
    maintenance_status = Column(String, nullable=True)
    latest_version = Column(String, nullable=True)
    latest_supported_version = Column(String, nullable=True)
    recommended_version = Column(String, nullable=True)
    recommendation = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    source_url = Column(String, nullable=True)
    evidence_json = Column(JSON, nullable=True)
    confidence = Column(String, nullable=True)
    checked_at = Column(String, nullable=False, index=True)
    expires_at = Column(String, nullable=False, index=True)
    is_stale = Column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint(
            "normalized_name",
            "normalized_version",
            "ecosystem",
            "purl",
            name="uq_component_lifecycle_cache_identity",
        ),
        Index("ix_component_lifecycle_cache_lookup", "ecosystem", "normalized_name", "normalized_version"),
    )


class VexDocument(Base, TenantOwnedMixin):
    """Imported VEX document scoped to an SBOM/product context."""

    __tablename__ = "vex_documents"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type = Column(String, nullable=False, default="uploaded", index=True)
    format = Column(String, nullable=True, index=True)
    author = Column(String, nullable=True)
    source_url = Column(String, nullable=True)
    discovery_evidence_json = Column(JSON, nullable=True)
    last_refresh_status = Column(String, nullable=True)
    provider_errors_json = Column(JSON, nullable=True)
    uploaded_by = Column(String, nullable=True, index=True)
    uploaded_at = Column(String, nullable=False, index=True)
    raw_document_json = Column(JSON, nullable=True)
    validation_status = Column(String, nullable=False, default="accepted", index=True)

    sbom = relationship("SBOMSource", back_populates="vex_documents")
    statements = relationship(
        "VexStatement",
        back_populates="vex_document",
        cascade="all, delete-orphan",
        order_by="VexStatement.id",
    )


class VexStatement(Base, TenantOwnedMixin):
    """Component/vulnerability exploitability statement."""

    __tablename__ = "vex_statements"

    id = Column(Integer, primary_key=True, index=True)
    vex_document_id = Column(Integer, ForeignKey("vex_documents.id", ondelete="CASCADE"), nullable=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id", ondelete="CASCADE"), nullable=False, index=True)
    component_id = Column(Integer, ForeignKey("sbom_component.id", ondelete="SET NULL"), nullable=True, index=True)
    vulnerability_id = Column(String, nullable=False, index=True)
    cve_id = Column(String, nullable=True, index=True)
    status = Column(String, nullable=False, index=True)
    justification = Column(Text, nullable=True)
    impact_statement = Column(Text, nullable=True)
    action_statement = Column(Text, nullable=True)
    fixed_version = Column(String, nullable=True)
    mitigation = Column(Text, nullable=True)
    source_name = Column(String, nullable=True)
    source_url = Column(String, nullable=True)
    confidence = Column(String, nullable=True)
    evidence_json = Column(JSON, nullable=True)
    created_at = Column(String, nullable=False, index=True)

    vex_document = relationship("VexDocument", back_populates="statements")
    component = relationship("SBOMComponent", back_populates="vex_statements")

    __table_args__ = (
        Index("ix_vex_statement_sbom_status", "sbom_id", "status"),
        Index("ix_vex_statement_component_vuln", "component_id", "vulnerability_id"),
    )


class ComponentLifecycleOverrideAudit(Base, TenantOwnedMixin):
    """Dedicated audit trail for lifecycle override changes."""

    __tablename__ = "component_lifecycle_override_audit"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("sbom_component.id", ondelete="CASCADE"), nullable=False, index=True)
    old_value_json = Column(JSON, nullable=True)
    new_value_json = Column(JSON, nullable=True)
    reason = Column(Text, nullable=False)
    evidence_url = Column(String, nullable=True)
    changed_by = Column(String, nullable=True, index=True)
    changed_at = Column(String, nullable=False, index=True)


class VexOverrideAudit(Base, TenantOwnedMixin):
    """Dedicated audit trail for manual VEX overrides."""

    __tablename__ = "vex_override_audit"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("sbom_component.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(String, nullable=False, index=True)
    old_value_json = Column(JSON, nullable=True)
    new_value_json = Column(JSON, nullable=True)
    reason = Column(Text, nullable=False)
    evidence_url = Column(String, nullable=True)
    changed_by = Column(String, nullable=True, index=True)
    changed_at = Column(String, nullable=False, index=True)


class AnalysisRun(Base, SoftDeleteMixin, TenantOwnedMixin):
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
    ai_fix_batches = relationship(
        "AiFixBatch",
        primaryjoin="AnalysisRun.id == foreign(AiFixBatch.run_id)",
        viewonly=True,
    )


class AnalysisFinding(Base, SoftDeleteMixin, TenantOwnedMixin):
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

    # Version-range match verdict from app.sources.version_range. NULL
    # for rows written before migration 016; PR3 populates these going
    # forward. Width VARCHAR(32) accommodates the longest MatchReason
    # literal (`exact_version_mismatch`, 22 chars) with headroom for
    # roadmap #6 additions. No CHECK constraint — the Literal is
    # enforced in Python, not at the DB layer.
    match_reason = Column(String(32), nullable=True, index=True)
    matched_range = Column(String(128), nullable=True)

    # Roadmap #3 — name/version/vendor token-overlap score in [0.0, 1.0].
    # NULL on pre-migration-017 rows and on sources not yet wired into
    # the scorer; the scorer in PR-B is the source of truth for the
    # bound (no DB CHECK, matching migration 016's posture — see
    # migration 017's docstring for the rationale).
    match_confidence = Column(Float, nullable=True)

    # Roadmap #6 — which search strategy produced this finding.
    # Values (enforced in Python, not the DB): cpe_name,
    # virtual_match_string, keyword_search (NVD); purl_direct (OSV);
    # ghsa_alias (GHSA). Width VARCHAR(32) fits the longest token
    # (``virtual_match_string`` = 21 chars) with headroom for future
    # source-strategy additions. Indexed so triage queries
    # ("show everything produced by keyword_search") don't table-scan.
    match_strategy = Column(String(32), nullable=True, index=True)

    analysis_run = relationship("AnalysisRun", back_populates="findings")
    component = relationship("SBOMComponent", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("analysis_run_id", "vuln_id", "cpe", name="uq_analysis_finding_run_vuln_cpe"),
        Index("ix_analysis_finding_run_severity", "analysis_run_id", "severity"),
    )


class RunCache(Base, TenantOwnedMixin):
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


class AnalysisSchedule(Base, SoftDeleteMixin, TenantOwnedMixin):
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


class SourceResponseCache(Base):
    """
    Per-(source, component) RAW response cache (roadmap #2, PR-A).

    Composite primary key on (source, component_key); ``component_key`` is
    the canonical PURL string so identical components across SBOMs share one
    cached row. ``payload`` holds the source's raw response — opaque JSON
    that PR-B's wiring step reprocesses on hit, so #1/#3/#6 logic stays
    fresh on every read.

    TTL is enforced at the repository layer at READ time: a row whose
    ``expires_at`` is in the past is treated as a miss (and silently
    overwritten on the next ``set``). ``ix_source_response_cache_expires_at``
    supports a future periodic sweep job for housekeeping; today's readers
    don't depend on it.

    NOT to be confused with ``cve_cache`` (per-CVE-ID detail payloads) or
    ``run_cache`` (per-SBOM whole-run JSON) — both are different concerns
    with different key spaces.
    """

    __tablename__ = "source_response_cache"

    source = Column(String(32), primary_key=True)
    component_key = Column(String(512), primary_key=True)
    payload = Column(JSON, nullable=False)
    fetched_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)

    __table_args__ = (Index("ix_source_response_cache_expires_at", "expires_at"),)


class NvdLookupCache(Base):
    """Cache of NVD lookup results and short-lived provider failures."""

    __tablename__ = "nvd_lookup_cache"

    id = Column(Integer, primary_key=True)
    lookup_type = Column(String(16), nullable=False)
    identifier = Column(String(2048), nullable=False)
    identifier_hash = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False)
    response_json = Column(JSON, nullable=True)
    http_status = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    checked_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("lookup_type", "identifier_hash", name="uq_nvd_lookup_cache_type_hash"),
        Index("ix_nvd_lookup_cache_expires_at", "expires_at"),
        Index("ix_nvd_lookup_cache_status", "status"),
        Index("ix_nvd_lookup_cache_identifier", "identifier"),
    )


class CompareCache(Base, TenantOwnedMixin):
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


class AiUsageLog(Base, TenantOwnedMixin):
    """
    Append-only ledger of every LLM call (success and failure).

    Phase 1 of the AI-driven remediation feature. Every provider call —
    cache hit, cache miss, or failure — writes one row. Reads are always
    aggregations (cost dashboards, daily totals, cache hit ratio); the
    table is therefore optimised for fast inserts and time-range scans.
    """

    __tablename__ = "ai_usage_log"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(64), nullable=False)
    provider = Column(String(32), nullable=False, index=True)
    model = Column(String(96), nullable=False)
    purpose = Column(String(48), nullable=False, index=True)
    finding_cache_key = Column(String(64), nullable=True, index=True)
    input_tokens = Column(Integer, nullable=False, default=0)
    output_tokens = Column(Integer, nullable=False, default=0)
    cost_usd = Column(Float, nullable=False, default=0.0)
    latency_ms = Column(Integer, nullable=False, default=0)
    cache_hit = Column(Boolean, nullable=False, default=False)
    error = Column(Text, nullable=True)
    created_at = Column(String, nullable=False, index=True)


class AiProviderConfig(Base):
    """
    Per-provider runtime overrides for the AI subsystem.

    Env vars in ``Settings`` provide the safe defaults; rows in this table
    let an admin toggle providers, change models, or adjust concurrency
    without a redeploy. Secrets (API keys) deliberately do NOT live here —
    they remain in env / vault, see ``ProviderRegistry.apply_db_overrides``.
    """

    __tablename__ = "ai_provider_config"

    provider_name = Column(String(32), primary_key=True)
    enabled = Column(Boolean, nullable=True)
    default_model = Column(String(96), nullable=True)
    base_url = Column(String(256), nullable=True)
    max_concurrent = Column(Integer, nullable=True)
    rate_per_minute = Column(Float, nullable=True)
    notes = Column(Text, nullable=True)
    updated_at = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)


class AiFixCache(Base):
    """
    Cached AI fix bundle, keyed on (vuln_id, component, version, prompt_version).

    The cache is tenant-shared by design — the AI advice for
    ``CVE-2021-44832`` on ``log4j-core@2.16.0`` is the same regardless of
    which user asks. This is the lever that makes the feature affordable:
    a 1,000-finding scan typically reduces to ~50-150 net-new generations
    with even a modest population of historical runs.

    TTL policy enforced at upsert time:
      * KEV-listed CVE → 7 days  (KEV status / exploitability narrative
                                  may change)
      * Non-KEV        → 30 days
      * Negative cache → 1 hour  (LLM call failed; retry sooner)
    """

    __tablename__ = "ai_fix_cache"

    cache_key = Column(String(64), primary_key=True)
    vuln_id = Column(String(64), nullable=False, index=True)
    component_name = Column(String(255), nullable=False)
    component_version = Column(String(128), nullable=False)
    prompt_version = Column(String(32), nullable=False)
    schema_version = Column(Integer, nullable=False, default=1)

    remediation_prose = Column(JSON, nullable=False)
    upgrade_command = Column(JSON, nullable=False)
    decision_recommendation = Column(JSON, nullable=False)
    # Model's self-assessed confidence in the whole bundle ("high"/"medium"/
    # "low"). Nullable so historical rows (pre-019) and fresh-install paths
    # that skip the migration read back as the neutral default in
    # ``app.ai.cache.read_cache``. New rows are always written non-null.
    overall_confidence = Column(String(16), nullable=True)

    provider_used = Column(String(32), nullable=False)
    model_used = Column(String(96), nullable=False)
    total_cost_usd = Column(Float, nullable=False, default=0.0)

    generated_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    last_accessed_at = Column(String, nullable=False)

    __table_args__ = (
        Index(
            "ix_ai_fix_cache_vuln_component",
            "vuln_id",
            "component_name",
            "component_version",
        ),
    )


class AiFixBatch(Base, SoftDeleteMixin, TenantOwnedMixin):
    """
    Durable record of a scope-aware AI fix batch (Phase 2 multi-batch).

    Up to 3 active batches may exist for a single ``run_id`` at a time
    (enforced at the router); this row holds the immutable
    "what was the scope, when did it start, what was the outcome" data.
    Live progress (counts updating in real time) lives in the
    progress store; this row is the source of truth for batch identity
    and historical lookups.

    ``finding_ids_json`` is denormalised on purpose: the resolved set
    at batch-creation time is the source of truth for what was
    processed, even if findings are deleted later.
    """

    __tablename__ = "ai_fix_batch"

    # 36-char UUID (hex with dashes), generated by the application.
    id = Column(String(36), primary_key=True)
    run_id = Column(
        Integer,
        ForeignKey("analysis_run.id", ondelete="CASCADE"),
        nullable=False,
    )
    status = Column(String(24), nullable=False)
    scope_label = Column(String(120), nullable=True)
    scope_json = Column(JSON, nullable=True)
    finding_ids_json = Column(JSON, nullable=False)
    provider_name = Column(String(64), nullable=False)
    total = Column(Integer, nullable=False, default=0)
    cached_count = Column(Integer, nullable=False, default=0)
    generated_count = Column(Integer, nullable=False, default=0)
    failed_count = Column(Integer, nullable=False, default=0)
    cost_usd = Column(Float, nullable=False, default=0.0)
    started_at = Column(String, nullable=True)
    completed_at = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    last_error = Column(String(240), nullable=True)

    __table_args__ = (
        Index("ix_ai_fix_batch_run_status", "run_id", "status"),
        Index("ix_ai_fix_batch_created_at", "created_at"),
    )


class AiProviderCredential(Base):
    """
    AES-GCM-encrypted API credential for one AI provider (Phase 2 §2.2).

    Tenant-shared by design (single-admin v1). The ``label`` column
    scaffolds for the future "multiple keys per provider" feature; v1
    UI keeps every row at ``label='default'``.

    Hard rule: ``api_key_encrypted`` must NEVER be returned by any
    endpoint. The router exposes ``api_key_preview`` (first 6 + last 4)
    and ``api_key_present`` only.
    """

    __tablename__ = "ai_provider_credential"

    id = Column(Integer, primary_key=True, index=True)
    provider_name = Column(String(32), nullable=False, index=True)
    label = Column(String(64), nullable=False, default="default")
    api_key_encrypted = Column(Text, nullable=True)
    base_url = Column(String(512), nullable=True)
    default_model = Column(String(128), nullable=True)
    tier = Column(String(16), nullable=False, default="paid")
    is_default = Column(Boolean, nullable=False, default=False)
    is_fallback = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    cost_per_1k_input_usd = Column(Float, nullable=False, default=0.0)
    cost_per_1k_output_usd = Column(Float, nullable=False, default=0.0)
    is_local = Column(Boolean, nullable=False, default=False)
    max_concurrent = Column(Integer, nullable=True)
    rate_per_minute = Column(Float, nullable=True)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
    last_test_at = Column(String, nullable=True)
    last_test_success = Column(Boolean, nullable=True)
    last_test_error = Column(Text, nullable=True)

    __table_args__ = (UniqueConstraint("provider_name", "label", name="uq_ai_provider_credential_provider_label"),)


class AiSettings(Base):
    """
    Singleton AI settings row (Phase 2 §2.3).

    Enforced via ``CHECK (id = 1)`` and the migration's ``INSERT`` of
    the seed row. Reads always succeed; writes update the singleton in
    place.
    """

    __tablename__ = "ai_settings"

    id = Column(Integer, primary_key=True, default=1)
    feature_enabled = Column(Boolean, nullable=False, default=True)
    kill_switch_active = Column(Boolean, nullable=False, default=False)
    budget_per_request_usd = Column(Float, nullable=False, default=0.10)
    budget_per_scan_usd = Column(Float, nullable=False, default=5.00)
    budget_daily_usd = Column(Float, nullable=False, default=5.00)
    updated_at = Column(String, nullable=False)
    updated_by_user_id = Column(String, nullable=True)

    __table_args__ = (CheckConstraint("id = 1", name="ck_ai_settings_singleton"),)


class AiCredentialAuditLog(Base):
    """
    Append-only audit trail for credential / settings mutations
    (Phase 2 §2.6).

    Hard rule: this table NEVER stores credential payloads. Only the
    user, action, target, provider name, and a short context string.
    """

    __tablename__ = "ai_credential_audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(128), nullable=True)
    action = Column(String(48), nullable=False)
    target_kind = Column(String(24), nullable=False)  # "credential" | "settings"
    target_id = Column(Integer, nullable=True)
    provider_name = Column(String(32), nullable=True)
    detail = Column(String(240), nullable=True)
    created_at = Column(String, nullable=False, index=True)


class AuditLog(Base, TenantOwnedMixin):
    """
    Append-only general-purpose audit trail.

    Distinct from ``AiCredentialAuditLog`` (which is the
    security-specific surface for credential/settings mutations).
    This table records lifecycle events on user-owned data —
    soft-deletes, permanent deletes, and restores — so an admin can
    answer "what happened to project X" after the fact.

    Action vocabulary (Phase 3 of the soft-delete refactor):

      * ``project.soft_delete`` / ``project.permanent_delete`` /
        ``project.restore``
      * ``sbom.soft_delete`` / ``sbom.permanent_delete`` / ``sbom.restore``
      * ``schedule.soft_delete`` / ``schedule.permanent_delete``

    The cascade row count is stored in ``metadata_json`` so an admin
    can answer "how many findings were tombstoned with this run" without
    re-walking the tree.
    """

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(128), nullable=True)
    action = Column(String(48), nullable=False, index=True)
    target_kind = Column(String(24), nullable=False, index=True)
    target_id = Column(Integer, nullable=True, index=True)
    detail = Column(String(240), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    user_ref_id = Column(Integer, ForeignKey("iam_users.id", ondelete="SET NULL"), nullable=True, index=True)
    entity_type = Column(String(64), nullable=True, index=True)
    entity_id = Column(String(128), nullable=True, index=True)
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(String, nullable=False, index=True)


class VulnerabilityRemediation(Base, TenantOwnedMixin):
    """
    Tracks vulnerability fix / remediation status for findings.
    """

    __tablename__ = "vulnerability_remediation"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id = Column(String, nullable=False, index=True)
    component_name = Column(String, nullable=False, index=True)
    component_version = Column(String, nullable=False)
    fixed_version = Column(String, nullable=True)
    status = Column(String, nullable=False, default="Open")  # Open, In Progress, Fixed, Accepted Risk, Closed
    owner = Column(String, nullable=True)
    due_date = Column(String, nullable=True)  # YYYY-MM-DD
    resolution_date = Column(String, nullable=True)  # YYYY-MM-DD
    fix_notes = Column(Text, nullable=True)
    created_on = Column(String, nullable=False)
    updated_on = Column(String, nullable=False)

    history = relationship(
        "VulnerabilityRemediationAudit",
        back_populates="remediation",
        cascade="all, delete-orphan",
        order_by="VulnerabilityRemediationAudit.id",
    )


class VulnerabilityRemediationAudit(Base, TenantOwnedMixin):
    """Append-only status/change trail for vulnerability remediation records."""

    __tablename__ = "vulnerability_remediation_audit"

    id = Column(Integer, primary_key=True, index=True)
    remediation_id = Column(
        Integer,
        ForeignKey("vulnerability_remediation.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id = Column(String, nullable=False, index=True)
    component_name = Column(String, nullable=False, index=True)
    component_version = Column(String, nullable=False)
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=False)
    changed_by = Column(String(128), nullable=True)
    changed_at = Column(String, nullable=False, index=True)
    note = Column(Text, nullable=True)
    remediation = relationship("VulnerabilityRemediation", back_populates="history")


# Indexes created by historical Alembic revisions are declared here as
# well so fresh metadata-created test schemas and Alembic autogeneration
# agree with production. Partial predicates are dialect-specific but the
# index names and covered columns remain identical across engines.
for _model in (
    Projects,
    SBOMSource,
    SBOMAnalysisReport,
    SBOMComponent,
    AnalysisRun,
    AnalysisFinding,
    AnalysisSchedule,
    AiFixBatch,
):
    Index(
        f"ix_{_model.__tablename__}_deactivated",
        _model.is_active,
        postgresql_where=sql_text("is_active = false"),
        sqlite_where=sql_text("is_active = 0"),
    )

for _tenant_model in (
    Projects,
    SBOMSource,
    SBOMValidationSession,
    SBOMValidationSessionEvent,
    SBOMAnalysisReport,
    SBOMComponent,
    VexDocument,
    VexStatement,
    ComponentLifecycleOverrideAudit,
    VexOverrideAudit,
    AnalysisRun,
    AnalysisFinding,
    RunCache,
    AnalysisSchedule,
    CompareCache,
    AiUsageLog,
    AiFixBatch,
    AuditLog,
    VulnerabilityRemediation,
    VulnerabilityRemediationAudit,
):
    _pk_column = next(iter(_tenant_model.__table__.primary_key.columns))
    Index(
        f"ix_{_tenant_model.__tablename__}_tenant_identity",
        _tenant_model.tenant_id,
        _pk_column,
    )

Index("ix_ai_usage_log_provider_created", AiUsageLog.provider, AiUsageLog.created_at)
Index("ix_ai_usage_log_purpose_created", AiUsageLog.purpose, AiUsageLog.created_at)
Index("ix_sbom_component_bom_ref", SBOMComponent.bom_ref)
Index("ix_sbom_component_duplicate_of_component_id", SBOMComponent.duplicate_of_component_id)
Index("ix_sbom_source_converted_from_format", SBOMSource.converted_from_format)
Index("ix_sbom_source_parent_id", SBOMSource.parent_id)
Index("ix_sbom_source_sbom_type", SBOMSource.sbom_type)
Index(
    "ix_ai_only_one_default",
    AiProviderCredential.is_default,
    unique=True,
    postgresql_where=sql_text("is_default = true"),
    sqlite_where=sql_text("is_default = 1"),
)
Index(
    "ix_ai_only_one_fallback",
    AiProviderCredential.is_fallback,
    unique=True,
    postgresql_where=sql_text("is_fallback = true"),
    sqlite_where=sql_text("is_fallback = 1"),
)
