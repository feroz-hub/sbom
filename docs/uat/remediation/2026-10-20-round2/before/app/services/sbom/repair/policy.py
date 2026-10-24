from dataclasses import dataclass

from app.settings import get_settings


@dataclass(frozen=True)
class RepairPolicy:
    enabled: bool = True
    max_passes: int = 3
    confidence: float = 1.0
    strict_ntia: bool = False
    verify_signature: bool = False
    max_bytes: int = 5 * 1024 * 1024
    max_seconds: float = 30.0

    def __post_init__(self):
        if (
            not 1 <= self.max_passes <= 10
            or not 0 <= self.confidence <= 1
            or self.max_bytes <= 0
            or self.max_seconds <= 0
        ):
            raise ValueError("Invalid repair policy")

    @classmethod
    def configured(cls, **validation_options):
        settings = get_settings()
        return cls(
            settings.sbom_auto_repair_enabled,
            settings.sbom_repair_max_passes,
            settings.sbom_repair_auto_apply_confidence,
            max_bytes=settings.sbom_repair_max_bytes,
            max_seconds=settings.sbom_repair_max_seconds,
            **validation_options,
        )
