"""Provider-based component lifecycle enrichment."""

from .deps_dev_provider import DepsDevProvider
from .endoflife_date_provider import EndOfLifeDateProvider
from .lifecycle_enrichment_service import (
    LifecycleEnrichmentService,
    component_lifecycle_dict,
    lifecycle_report_csv,
    refresh_component_lifecycle,
    summarize_components,
    sync_lifecycle_for_sbom,
)
from .normalizer import normalize_component
from .osv_provider import OSVProvider
from .package_registry_provider import PackageRegistryProvider
from .repository_health_provider import RepositoryHealthProvider
from .types import (
    ALLOWED_LIFECYCLE_STATUSES,
    LifecycleResult,
    NormalizedComponent,
    VexResult,
    canonical_status,
)

__all__ = [
    "ALLOWED_LIFECYCLE_STATUSES",
    "EndOfLifeDateProvider",
    "DepsDevProvider",
    "LifecycleEnrichmentService",
    "LifecycleResult",
    "NormalizedComponent",
    "OSVProvider",
    "PackageRegistryProvider",
    "RepositoryHealthProvider",
    "canonical_status",
    "component_lifecycle_dict",
    "lifecycle_report_csv",
    "normalize_component",
    "refresh_component_lifecycle",
    "summarize_components",
    "sync_lifecycle_for_sbom",
    "VexResult",
]
