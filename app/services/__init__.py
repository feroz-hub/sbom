"""
Services Layer - Business logic and orchestration.

This module contains service classes and functions that implement business logic,
coordinate between repositories and models, and handle cross-cutting concerns.
"""

# SBOM Service
from .sbom_service import (
    coerce_sbom_data,
    load_json_bytes_with_fallback,
    load_sbom_from_ref,
    normalized_key,
    now_iso,
    resolve_component_id,
    safe_int,
    sync_sbom_components,
)

# Analysis Service
from .analysis_service import (
    backfill_analytics_tables,
    compute_report_status,
    legacy_analysis_level,
    normalize_details,
    persist_analysis_run,
)

# PDF Service
from .pdf_service import (
    generate_pdf_report,
    load_run_cache,
    rebuild_run_from_db,
    store_run_cache,
)

# Dashboard Service
from .dashboard_service import (
    get_activity,
    get_component_stats,
    get_recent_sboms,
    get_run_status_distribution,
    get_severity_distribution,
    get_stats,
    get_top_vulnerable_components,
    get_top_vulnerabilities,
)

__all__ = [
    # SBOM Service
    "coerce_sbom_data",
    "load_json_bytes_with_fallback",
    "load_sbom_from_ref",
    "normalized_key",
    "now_iso",
    "resolve_component_id",
    "safe_int",
    "sync_sbom_components",
    # Analysis Service
    "backfill_analytics_tables",
    "compute_report_status",
    "legacy_analysis_level",
    "normalize_details",
    "persist_analysis_run",
    # PDF Service
    "generate_pdf_report",
    "load_run_cache",
    "rebuild_run_from_db",
    "store_run_cache",
    # Dashboard Service
    "get_activity",
    "get_component_stats",
    "get_recent_sboms",
    "get_run_status_distribution",
    "get_severity_distribution",
    "get_stats",
    "get_top_vulnerable_components",
    "get_top_vulnerabilities",
]
