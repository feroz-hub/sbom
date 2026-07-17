"""
Services Layer - Business logic and orchestration.

This module contains service classes and functions that implement business logic,
coordinate between repositories and models, and handle cross-cutting concerns.
"""

_EXPORTS = {
    # SBOM Service
    "coerce_sbom_data": ("sbom_service", "coerce_sbom_data"),
    "load_json_bytes_with_fallback": ("sbom_service", "load_json_bytes_with_fallback"),
    "load_sbom_from_ref": ("sbom_service", "load_sbom_from_ref"),
    "normalized_key": ("sbom_service", "normalized_key"),
    "now_iso": ("sbom_service", "now_iso"),
    "resolve_component_id": ("sbom_service", "resolve_component_id"),
    "safe_int": ("sbom_service", "safe_int"),
    "sync_sbom_components": ("sbom_service", "sync_sbom_components"),
    # Analysis Service
    "backfill_analytics_tables": ("analysis_service", "backfill_analytics_tables"),
    "compute_report_status": ("analysis_service", "compute_report_status"),
    "legacy_analysis_level": ("analysis_service", "legacy_analysis_level"),
    "normalize_details": ("analysis_service", "normalize_details"),
    "persist_analysis_run": ("analysis_service", "persist_analysis_run"),
    # PDF Service
    "generate_pdf_report": ("pdf_service", "generate_pdf_report"),
    "load_run_cache": ("pdf_service", "load_run_cache"),
    "rebuild_run_from_db": ("pdf_service", "rebuild_run_from_db"),
    "store_run_cache": ("pdf_service", "store_run_cache"),
}


def __getattr__(name: str):
    """Lazy-load service exports so importing one service has no side effects."""
    try:
        module_name, attr_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    from importlib import import_module

    value = getattr(import_module(f"{__name__}.{module_name}"), attr_name)
    globals()[name] = value
    return value

__all__ = [
    *_EXPORTS,
]
