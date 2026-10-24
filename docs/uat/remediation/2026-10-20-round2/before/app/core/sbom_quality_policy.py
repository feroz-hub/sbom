import hashlib
import json
import math

from pydantic import BaseModel, Field, model_validator

NAMES = {
    "QD-01": "Schema Compliance",
    "QD-02": "Identifier Integrity",
    "QD-03": "Dependency Integrity",
    "QD-04": "Component Completeness",
    "QD-05": "PURL Coverage",
    "QD-06": "CPE Coverage",
    "QD-07": "License Completeness",
    "QD-08": "Hash Coverage",
    "QD-09": "Metadata Completeness",
}
DEFAULT_WEIGHTS = dict(zip(NAMES, (20, 15, 15, 15, 10, 5, 7.5, 5, 7.5), strict=True))
DEFAULT_THRESHOLDS = {"EXCELLENT": 90, "GOOD": 80, "FAIR": 70, "POOR": 50, "CRITICAL_QUALITY": 0}


class QualityPolicy(BaseModel):
    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS), validate_default=True)
    thresholds: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_THRESHOLDS), validate_default=True)
    max_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_findings: int = Field(default=500, ge=1, le=5000)
    repair_enabled: bool = True

    @model_validator(mode="after")
    def valid_configuration(self):
        if set(self.weights) != set(NAMES) or any(not math.isfinite(v) or v < 0 for v in self.weights.values()):
            raise ValueError("Quality weights must define all nine dimensions with finite nonnegative values")
        if not math.isclose(sum(self.weights.values()), 100, abs_tol=1e-6):
            raise ValueError("Quality weights must total 100 percent")
        if set(self.thresholds) != set(DEFAULT_THRESHOLDS):
            raise ValueError("Quality thresholds must define all grades")
        values = [self.thresholds[k] for k in DEFAULT_THRESHOLDS]
        if any(not math.isfinite(v) or not 0 <= v <= 100 for v in values) or values[-1] != 0:
            raise ValueError("Invalid quality grade thresholds")
        if any(a <= b for a, b in zip(values, values[1:], strict=False)):
            raise ValueError("Quality grade thresholds must descend")
        return self

    @classmethod
    def configured(cls):
        from app.settings import get_settings

        settings = get_settings()
        return cls(weights=settings.sbom_quality_weights, thresholds=settings.sbom_quality_thresholds,
                   repair_enabled=settings.sbom_auto_repair_enabled)

    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()

    def grade(self, score):
        return next(k for k in DEFAULT_THRESHOLDS if score >= self.thresholds[k])
