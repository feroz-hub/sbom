"""
Health and configuration endpoint router.

Routes:
  GET /           service_info
  GET /health     health check
  GET /api/analysis/config   analysis configuration
  GET /api/types  list SBOM types
"""

import logging
from datetime import UTC

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analysis import get_analysis_settings_multi
from ..auth import require_auth
from ..db import get_db
from ..models import SBOMType
from ..schemas import SBOMTypeOut
from ..settings import get_analysis_legacy_level, get_settings

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])
_settings = get_settings()
APP_VERSION = _settings.APP_VERSION


def public_analysis_config() -> dict:
    """
    Expose multi-source analysis settings (NVD + OSV + GHSA + VulDB + concurrency).
    """
    s = get_analysis_settings_multi()
    app_settings = get_settings()
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
        "vulndb_api_base_url": getattr(s, "vulndb_api_base_url", None),
        "vulndb_api_key_env": getattr(s, "vulndb_api_key_env", "VULNDB_API_KEY"),
        "vulndb_limit": getattr(s, "vulndb_limit", 5),
        "analysis_sources_env": getattr(s, "analysis_sources_env", "ANALYSIS_SOURCES"),
        "max_concurrency": getattr(s, "max_concurrency", 10),
        "analysis_legacy_level": get_analysis_legacy_level(),
        # Feature flags — whether optional credentials are configured
        "github_configured": app_settings.github_configured,
        "nvd_key_configured": app_settings.nvd_key_configured,
        "vulndb_configured": app_settings.vulndb_configured,
        # Feature flag for the in-app CVE detail modal (Phase 5 rollback path).
        "cve_modal_enabled": app_settings.cve_modal_enabled,
        # AI fix generator master flag + default provider name. When the
        # flag is false the frontend hides the AI surface entirely. Default
        # provider is surfaced for the empty-state CTA copy.
        "ai_fixes_enabled": app_settings.ai_fixes_enabled and not app_settings.ai_fixes_kill_switch,
        "ai_default_provider": app_settings.ai_default_provider,
        # Phase 4 rollout flag — true when the Settings → AI UI surface is
        # available. Frontend reads this to gate /settings/ai.
        "ai_ui_config_enabled": bool(app_settings.ai_fixes_ui_config_enabled),
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
def health(db: Session = Depends(get_db)) -> dict:
    log.debug("Health check requested")
    return {
        "status": "ok",
        "nvd_mirror": _nvd_mirror_health(db),
    }


def _nvd_mirror_health(db: Session) -> dict:
    """Lightweight mirror status for liveness/readiness probes.

    Wrapped in try/except so any DB or import error returns
    ``{"available": False}`` rather than failing the whole health check —
    /health must NEVER be the reason a deploy rolls back.
    """
    from datetime import datetime

    try:
        from ..nvd_mirror.adapters.secrets import (
            FernetSecretsAdapter,
            MissingFernetKeyError,
        )
        from ..nvd_mirror.adapters.settings_repository import (
            SqlAlchemySettingsRepository,
        )
        from ..nvd_mirror.application.freshness import compute_freshness
        from ..nvd_mirror.observability import mirror_counters
        from ..nvd_mirror.settings import load_mirror_settings_from_env
        from ..nvd_mirror.tasks import _StubSecrets

        env_defaults = load_mirror_settings_from_env()
        try:
            secrets = FernetSecretsAdapter.from_env(
                env_var=env_defaults.fernet_key_env_var
            )
        except MissingFernetKeyError:
            secrets = _StubSecrets(env_defaults.fernet_key_env_var)

        repo = SqlAlchemySettingsRepository(db, secrets, env_defaults=env_defaults)
        snap = repo.load()
        # Don't commit a seed write inside /health — let the next admin
        # call do it. Health stays read-only as far as caller observation
        # goes; the SQLAlchemy Session may flush the seed but that's a
        # transient detail.

        verdict = compute_freshness(snap, datetime.now(tz=UTC))
        return {
            "enabled": snap.enabled,
            "last_success_at": (
                snap.last_successful_sync_at.isoformat()
                if snap.last_successful_sync_at
                else None
            ),
            "watermark": (
                snap.last_modified_utc.isoformat() if snap.last_modified_utc else None
            ),
            "stale": not verdict.is_fresh,
            "counters": mirror_counters.snapshot(),
        }
    except Exception as exc:
        log.warning("nvd_mirror_health_unavailable", extra={"error": str(exc)})
        return {"available": False, "error": str(exc)}


# Finding A: `/api/analysis/config` and `/api/types` carry route-level
# auth so they are protected while the sibling `/` and `/health` routes
# in this same router stay open for liveness probes and FastAPI `/docs`.
@router.get("/api/analysis/config", dependencies=[Depends(require_auth)])
def get_analysis_config() -> dict:
    return public_analysis_config()


@router.get(
    "/api/types",
    response_model=list[SBOMTypeOut],
    dependencies=[Depends(require_auth)],
)
def list_sbom_types(db: Session = Depends(get_db)):
    """List SBOM types (e.g. CycloneDX, SPDX) for upload/edit dropdowns."""
    return db.execute(select(SBOMType).order_by(SBOMType.typename.asc())).scalars().all()
