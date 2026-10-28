"""Quality policy shared with platform settings without validator/service coupling."""

from app.core.sbom_quality_policy import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, NAMES, QualityPolicy

__all__ = ["DEFAULT_THRESHOLDS", "DEFAULT_WEIGHTS", "NAMES", "QualityPolicy"]
