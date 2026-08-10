"""Domain layer — pure dataclasses, no I/O.

Importable from anywhere (use cases, tests, even adapters) without
paying for httpx, SQLAlchemy, or DB setup.
"""

from .mappers import MalformedCveError, map_batch, map_cve
from .models import (
    CpeCriterion,
    CveBatch,
    CveRecord,
    FreshnessVerdict,
    MirrorWatermark,
    MirrorWindow,
    NvdSettingsSnapshot,
    SyncReport,
)

__all__ = [
    "CpeCriterion",
    "CveBatch",
    "CveRecord",
    "FreshnessVerdict",
    "MalformedCveError",
    "MirrorWatermark",
    "MirrorWindow",
    "NvdSettingsSnapshot",
    "SyncReport",
    "map_batch",
    "map_cve",
]
