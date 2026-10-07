from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class QualitySeverity(StrEnum):
    BLOCKING = "BLOCKING"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFORMATIONAL = "INFORMATIONAL"


class QualityFinding(BaseModel):
    code: str
    dimension: str
    severity: QualitySeverity
    path: str | None = None
    message: str
    remediation: str
    repairable: bool = False
    repairability_assessed: bool = True
    repair_classification: str = "MANUAL_ONLY"
    quality_impact: float = 0


class QualityDimensionScore(BaseModel):
    code: str
    name: str
    score: float = Field(ge=0, le=100)
    weight: float = Field(ge=0, le=100)
    finding_count: int = 0
    metrics: dict[str, Any] = Field(default_factory=dict)


class SbomQualityScore(BaseModel):
    overall_score: float = Field(ge=0, le=100)
    grade: str
    dimensions: list[QualityDimensionScore]
    findings: list[QualityFinding]
    calculated_at: datetime
    engine_version: str = "2.0.0"
    artifact_hash: str
    configuration_hash: str
    configuration: dict[str, Any] = Field(default_factory=dict)
    format: str = "CYCLONEDX_JSON"
    spec_version: str | None = None
    validation_status: str
    validation_report_truncated: bool = False
    supported: bool = True
    reason: str | None = None
    findings_truncated: bool = False
