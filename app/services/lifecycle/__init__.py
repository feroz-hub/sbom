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
from .openeox_report import lifecycle_report_openeox
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
from .vendor_lifecycle_provider import VendorLifecycleProvider
from .xeol_provider import XeolProvider

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
    "VendorLifecycleProvider",
    "XeolProvider",
    "canonical_status",
    "component_lifecycle_dict",
    "lifecycle_report_csv",
    "lifecycle_report_openeox",
    "normalize_component",
    "refresh_component_lifecycle",
    "summarize_components",
    "sync_lifecycle_for_sbom",
    "VexResult",
]
