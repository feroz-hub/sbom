"""
Health and configuration endpoint router.

Routes:
  GET /           service_info
  GET /health     health check
  GET /api/analysis/config   analysis configuration
  GET /api/types  list SBOM types
"""
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SBOMType
from ..schemas import SBOMTypeOut
from ..settings import get_settings
from ..analysis import get_analysis_settings_multi
import os
import logging

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])
_settings = get_settings()
APP_VERSION = _settings.APP_VERSION


def legacy_analysis_level() -> int:
    """Get legacy analysis level from environment."""
    import os
    raw_value = os.getenv("ANALYSIS_LEGACY_LEVEL", "1")
    try:
        parsed = int(raw_value)
    except ValueError:
        return 1
    return parsed if parsed > 0 else 1


def public_analysis_config() -> dict:
    """
    Expose multi-source analysis settings (NVD + OSV + GHSA + concurrency).
    """
    s = get_analysis_settings_multi()
    return {
        # Legacy-ish keys still useful in UI
        "source_name": getattr(s, "source_name", "NVD"),
        "http_user_agent": getattr(s, "http_user_agent", "SBOM-Analyzer/enterprise-2.0"),
        "nvd_api_base_url": getattr(s, "nvd_api_base_url", None),
        "nvd_detail_base_url": getattr(s, "nvd_detail_base_url", None),
        "nvd_api_key_env": getattr(s, "nvd_api_key_env", "NVD_API_KEY"),
        "nvd_results_per_page": getattr(s, "nvd_results_per_page", 2000),
        "nvd_request_timeout_seconds": getattr(s, "nvd_request_timeout_seconds", 60),
        "nvd_max_retries": getattr(s, "nvd_max_retries", 3),
        "nvd_retry_backoff_seconds": getattr(s, "nvd_retry_backoff_seconds", 1.5),
        "nvd_request_delay_with_key_seconds": getattr(s, "nvd_request_delay_with_key_seconds", 0.7),
        "nvd_request_delay_without_key_seconds": getattr(s, "nvd_request_delay_without_key_seconds", 6.0),
        "cvss_critical_threshold": getattr(s, "cvss_critical_threshold", 9.0),
        "cvss_high_threshold": getattr(s, "cvss_high_threshold", 7.0),
        "cvss_medium_threshold": getattr(s, "cvss_medium_threshold", 4.0),
        "analysis_max_findings_per_cpe": getattr(s, "analysis_max_findings_per_cpe", 5000),
        "analysis_max_findings_total": getattr(s, "analysis_max_findings_total", 50000),
        # Multi-source specific
        "osv_api_base_url": getattr(s, "osv_api_base_url", None),
        "osv_results_per_batch": getattr(s, "osv_results_per_batch", 1000),
        "gh_graphql_url": getattr(s, "gh_graphql_url", None),
        "gh_token_env": getattr(s, "gh_token_env", "GITHUB_TOKEN"),
        "analysis_sources_env": getattr(s, "analysis_sources_env", "ANALYSIS_SOURCES"),
        "max_concurrency": getattr(s, "max_concurrency", 10),
        "analysis_legacy_level": legacy_analysis_level(),
        # Feature flags — whether optional credentials are configured
        "github_configured": bool(os.getenv("GITHUB_TOKEN", "").strip()),
        "nvd_key_configured": bool(os.getenv("NVD_API_KEY", "").strip()),
    }


@router.get("/")
def service_info() -> dict:
    return {
        "service": "sbom-analyzer-api",
        "version": APP_VERSION,
        "docs_url": "/docs",
        "health_url": "/health",
    }


@router.get("/health")
def health() -> dict:
    log.debug("Health check requested")
    return {"status": "ok"}


@router.get("/api/analysis/config")
def get_analysis_config() -> dict:
    return public_analysis_config()


@router.get("/api/types", response_model=List[SBOMTypeOut])
def list_sbom_types(db: Session = Depends(get_db)):
    """List SBOM types (e.g. CycloneDX, SPDX) for upload/edit dropdowns."""
    return db.execute(select(SBOMType).order_by(SBOMType.typename.asc())).scalars().all()
