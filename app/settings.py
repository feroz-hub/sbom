"""
Settings module for SBOM Analyzer.

Centralizes all environment variable reads using Pydantic BaseSettings.
Provides a single source of truth for application configuration.

Supports both pydantic v2 with pydantic-settings and standalone pydantic v2.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

# Detect and import BaseSettings
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    HAS_SETTINGS_CONFIG_DICT = True
except ImportError:
    try:
        from pydantic.settings import BaseSettings, SettingsConfigDict

        HAS_SETTINGS_CONFIG_DICT = True
    except ImportError:
        # Fallback: BaseSettings is just BaseModel, no SettingsConfigDict
        BaseSettings = BaseModel
        SettingsConfigDict = None
        HAS_SETTINGS_CONFIG_DICT = False


class Settings(BaseSettings):
    """
    Application settings backed by environment variables.

    Centralizes all configuration from environment variables with
    sensible defaults and validation.
    """

    # API Keys and Credentials
    nvd_api_key: str = Field(default="", description="NVD API key for enhanced rate limits")
    github_token: str = Field(default="", description="GitHub token for GraphQL API access")
    vulndb_api_key: str = Field(default="", description="VulDB API key for VulnDB/VulDB vulnerability lookups")

    # Analysis Configuration
    analysis_sources: str = Field(
        default="NVD,OSV,GITHUB",
        description="Comma-separated list of analysis sources (NVD, OSV, GITHUB, VULNDB)",
    )

    # CORS Configuration
    cors_origins: str = Field(default="*", description="Comma-separated list of allowed CORS origins")

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8000, description="Server port")
    reload: bool = Field(default=False, description="Enable auto-reload on code changes")

    # Database Configuration (postgresql+psycopg:// or sqlite:///…)
    database_url: str = Field(
        default="",
        description="SQLAlchemy database URL; empty uses sbom_api.db SQLite beside project root",
    )

    # Analysis Settings
    analysis_legacy_level: int = Field(default=1, description="Legacy analysis level (0=new, 1+=compatibility)")

    # Authentication Configuration (Finding A — opt-in bearer token auth)
    #
    # `api_auth_mode` is "none" by default so existing dev environments are
    # not broken. Set it to "bearer" in production to require an
    # `Authorization: Bearer <token>` header on every state-touching or
    # data-exposing endpoint. `api_auth_tokens` is a comma-separated allowlist
    # of valid tokens — multiple values let you rotate per-client without
    # downtime.
    api_auth_mode: str = Field(
        default="none",
        description="Auth: none | bearer (allowlist) | jwt (HS256 via JWT_SECRET_KEY).",
    )
    api_auth_tokens: str = Field(
        default="",
        description="Comma-separated allowlist of valid bearer tokens. Required when api_auth_mode='bearer'.",
    )

    # JWT (when api_auth_mode=jwt)
    jwt_secret_key: str = Field(default="", description="HMAC secret for JWT validation (HS256)")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_audience: str = Field(default="", description="Optional expected aud claim")
    jwt_issuer: str = Field(default="", description="Optional expected iss claim")

    # Celery / Redis
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis URL for Celery broker/backend")
    celery_broker_url: str = Field(
        default="",
        description="Override broker; defaults to redis_url when empty",
    )

    # CVE Detail Modal — enrichment service knobs
    #
    # The ``CveDetailService`` aggregates OSV / GHSA / NVD / EPSS / KEV into a
    # single normalised payload, cached in the ``cve_cache`` table. These
    # knobs tune TTLs, source enablement, the NVD throttle, and the kill
    # switch for the in-app modal. Defaults are tuned for staging; bumps
    # belong in environment overrides.
    cve_modal_enabled: bool = Field(
        default=True,
        description="Feature flag for the in-app CVE detail modal. When false, the frontend keeps the old GitHub/NVD external link.",
    )
    cve_sources_enabled: str = Field(
        default="osv,ghsa,nvd,epss,kev",
        description="Comma-separated list of enabled CVE detail sources.",
    )
    cve_cache_ttl_kev_seconds: int = Field(
        default=6 * 60 * 60,
        description="Cache TTL for CVEs that are on the CISA KEV list.",
    )
    cve_cache_ttl_recent_seconds: int = Field(
        default=24 * 60 * 60,
        description="Cache TTL for recent CVEs (published within cve_recent_window_days).",
    )
    cve_cache_ttl_stable_seconds: int = Field(
        default=7 * 24 * 60 * 60,
        description="Cache TTL for older CVEs.",
    )
    cve_cache_ttl_error_seconds: int = Field(
        default=15 * 60,
        description="Negative-cache TTL for fetch errors (avoid hammering upstream during outages).",
    )
    cve_recent_window_days: int = Field(
        default=90,
        description="A CVE published this many days ago or less is treated as 'recent' for TTL bucketing.",
    )
    cve_http_connect_timeout: float = Field(
        default=3.0,
        description="Connect timeout for outbound CVE source HTTP calls.",
    )
    cve_http_read_timeout: float = Field(
        default=5.0,
        description="Read timeout for outbound CVE source HTTP calls.",
    )
    cve_http_retries: int = Field(
        default=2,
        description="Per-call retry budget on transient failures (5xx, timeouts).",
    )
    cve_circuit_breaker_threshold: int = Field(
        default=5,
        description="Consecutive failures that trip a source's circuit breaker.",
    )
    cve_circuit_breaker_reset_seconds: float = Field(
        default=60.0,
        description="How long an open circuit stays open before half-open probing.",
    )
    cve_nvd_unauth_throttle_seconds: float = Field(
        default=6.0,
        description="Min spacing between NVD calls when no API key is set (NVD allows 5 req / 30s).",
    )
    cve_nvd_auth_throttle_seconds: float = Field(
        default=0.6,
        description="Min spacing between NVD calls with an API key (50 req / 30s).",
    )

    # Compare Runs v2 (ADR-0008) — knobs and kill-switches
    #
    # ``compare_v1_fallback`` is the operational kill-switch. It is read by the
    # frontend (via ``NEXT_PUBLIC_COMPARE_V1_FALLBACK``) at build time AND by
    # this backend so ``GET /health`` can echo the current value back to ops
    # for staging verification. When true, the frontend renders the preserved
    # v1 implementation at ``frontend/src/app/analysis/compare/_v1/page.tsx``
    # instead of the v2 page. See ADR-0008 §1 and the runbook.
    compare_v1_fallback: bool = Field(
        default=False,
        description="Operational kill-switch: when true, frontend renders the preserved v1 compare page. Must be set on BOTH backend (this) and frontend (NEXT_PUBLIC_COMPARE_V1_FALLBACK) to take effect.",
    )
    compare_license_hash_enabled: bool = Field(
        default=False,
        description="When false, license_changed and hash_changed component change_kinds NEVER fire even if the underlying columns get added. Hard guard on stubbed change_kinds. ADR-0008 §10 OOS.",
    )
    compare_streaming_threshold: int = Field(
        default=5000,
        description="If findings_a + findings_b + components_a + components_b exceeds this, the API streams via SSE instead of returning a single JSON response. Tunable without code change.",
    )
    compare_cache_ttl_seconds: int = Field(
        default=24 * 60 * 60,
        description="TTL for compare_cache rows. Cache is also invalidated immediately when either run is reanalyzed (Celery hook).",
    )

    # =========================================================================
    # AI-driven remediation (Phase 1 — provider abstraction & cost model)
    # =========================================================================
    #
    # Foundational settings for the AI fix generator. Phase 1 ships the
    # provider layer + cost ledger + budget caps. Higher-level orchestrator
    # / cache settings land in Phase 2.
    #
    # Design intent:
    #   * ``ai_default_provider`` is the only knob most operators ever touch.
    #     Switching from Anthropic to OpenAI to local Ollama is a single env
    #     change with zero code edits.
    #   * Per-provider knobs (model, concurrency, rpm) are provider-scoped so
    #     defaults can move independently as upstream APIs evolve.
    #   * Budget caps default to conservative values; production rollout
    #     starts with even tighter values per the rollout plan in §6.

    ai_fixes_enabled: bool = Field(
        default=False,
        description="Master feature flag for the AI fix generator. Phase 1 ships off-by-default.",
    )
    ai_fixes_kill_switch: bool = Field(
        default=False,
        description="When true, every AI call is rejected at the registry. Operator panic button.",
    )
    ai_fixes_ui_config_enabled: bool = Field(
        default=False,
        description=(
            "Phase 4 §4.3 rollout flag. When true the Settings → AI UI surface "
            "(/settings/ai) is enabled and DB-backed credentials are the "
            "primary source. When false the frontend shows a 'not enabled' "
            "fallback and the registry continues to read env config. The "
            "API-side credential endpoints work either way so admin tooling "
            "and the migration script can run before the flag is flipped."
        ),
    )
    ai_default_provider: str = Field(
        default="anthropic",
        description="Provider name used when LlmRequest.provider_name is None.",
    )
    ai_providers: str = Field(
        default="anthropic,openai,gemini,grok,ollama,vllm,custom_openai",
        description="Comma-separated list of providers to wire up. Disabled providers are reported but not callable.",
    )

    # Anthropic
    anthropic_api_key: str = Field(default="", description="Anthropic Messages API key.")
    ai_anthropic_model: str = Field(default="claude-sonnet-4-5", description="Default Anthropic model.")
    ai_anthropic_max_concurrent: int = Field(default=10, description="Max in-flight requests for Anthropic.")
    ai_anthropic_rpm: float = Field(default=50.0, description="Requests per minute soft limit for Anthropic.")

    # OpenAI / OpenAI-compatible
    openai_api_key: str = Field(default="", description="OpenAI API key.")
    ai_openai_model: str = Field(default="gpt-4o-mini", description="Default OpenAI model.")
    ai_openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        description="Override for OpenAI-compatible endpoints (Together, Groq, Azure).",
    )
    ai_openai_organization: str = Field(default="", description="Optional OpenAI org id.")
    ai_openai_max_concurrent: int = Field(default=20, description="Max in-flight requests for OpenAI.")
    ai_openai_rpm: float = Field(default=200.0, description="Requests per minute soft limit for OpenAI.")

    # Ollama
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama HTTP API base URL. Empty disables Ollama.",
    )
    ai_ollama_model: str = Field(default="llama3.3:70b", description="Default Ollama model.")
    ai_ollama_max_concurrent: int = Field(
        default=8,
        description="Max in-flight requests for Ollama. Local inference is GPU-bound; over-saturation hurts.",
    )
    ai_ollama_rpm: float = Field(default=1000.0, description="Effectively unlimited; local infra dictates throughput.")

    # vLLM
    vllm_base_url: str = Field(default="", description="Self-hosted vLLM base URL. Empty disables vLLM.")
    vllm_api_key: str = Field(default="EMPTY", description="vLLM accepts any non-empty token by default.")
    ai_vllm_model: str = Field(default="meta-llama/Meta-Llama-3.1-70B-Instruct", description="Default vLLM model.")
    ai_vllm_max_concurrent: int = Field(default=32, description="Max in-flight requests for vLLM.")
    ai_vllm_rpm: float = Field(default=5000.0, description="vLLM batches efficiently on GPU.")

    # Google Gemini
    gemini_api_key: str = Field(default="", description="Google AI Studio API key.")
    ai_gemini_model: str = Field(default="gemini-2.5-flash", description="Default Gemini model.")
    ai_gemini_tier: str = Field(
        default="free",
        description="Gemini tier ('free' or 'paid'). Free tier clamps RPM to 15.",
    )
    ai_gemini_max_concurrent: int = Field(default=4, description="Max in-flight requests for Gemini.")
    ai_gemini_rpm: float = Field(
        default=15.0,
        description="RPM cap. Free tier clamps to 15; bump for paid tier (default ~1500 paid).",
    )

    # xAI Grok
    grok_api_key: str = Field(default="", description="xAI Grok API key.")
    ai_grok_model: str = Field(default="grok-2-mini", description="Default Grok model.")
    ai_grok_tier: str = Field(
        default="free",
        description="Grok tier ('free' or 'paid'). Free tier clamps RPM to 60.",
    )
    ai_grok_max_concurrent: int = Field(default=4, description="Max in-flight requests for Grok.")
    ai_grok_rpm: float = Field(default=60.0, description="RPM cap. Free tier clamps to 60.")

    # Custom OpenAI-compatible (LM Studio / LocalAI / LiteLLM proxy / etc.)
    ai_custom_openai_base_url: str = Field(
        default="",
        description="Base URL for the custom endpoint. Empty disables. Must start with https:// or http://localhost.",
    )
    ai_custom_openai_api_key: str = Field(
        default="EMPTY",
        description="Optional API key. Most local setups don't need one.",
    )
    ai_custom_openai_model: str = Field(
        default="",
        description="Free-text model name as understood by the custom endpoint.",
    )
    ai_custom_openai_max_concurrent: int = Field(default=8, description="Max in-flight requests.")
    ai_custom_openai_rpm: float = Field(default=5000.0, description="RPM cap. No limit by default.")
    ai_custom_openai_cost_per_1k_input: float = Field(
        default=0.0,
        description="Optional per-1k-token input cost (USD). Defaults to $0 since most local setups are free.",
    )
    ai_custom_openai_cost_per_1k_output: float = Field(
        default=0.0,
        description="Optional per-1k-token output cost (USD).",
    )
    ai_custom_openai_is_local: bool = Field(
        default=True,
        description="Treat as local for cost reporting. Set false for remote (paid) endpoints.",
    )

    # Budget caps (USD)
    ai_budget_per_request_usd: float = Field(
        default=0.10,
        description="Hard cap on a single LLM call. Estimated cost > cap → request rejected pre-flight.",
    )
    ai_budget_per_scan_usd: float = Field(
        default=5.00,
        description="Hard cap on a single batch generate-fixes job.",
    )
    ai_budget_per_day_org_usd: float = Field(
        default=5.00,
        description=(
            "Daily org-wide cap. Reset at UTC midnight. Defaults to $5 "
            "for the first 14 days of rollout per the §6.3 cost guardrail; "
            "raise to $50+ once telemetry shows steady-state behaviour."
        ),
    )

    # Phased rollout knob — see app/ai/rollout.py and docs/rollout-ai-fixes.md.
    # 0   → AI returns 409 even with the master flag on (canary not yet started)
    # 100 → AI returns to all eligible callers
    # 1-99 → deterministic hash of the rollout key (run / finding / user) decides
    ai_canary_percentage: int = Field(
        default=100,
        ge=0,
        le=100,
        description=(
            "Canary rollout percentage (0-100). Hashes the rollout key "
            "for stable per-key inclusion. Default 100 ships everything; "
            "set to 10 / 50 during the canary ramp."
        ),
    )

    # Logging Configuration
    log_level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    log_format: str = Field(default="text", description="Log format (text or json)")
    log_file: str = Field(default="", description="Optional log file path")
    log_max_mb: int = Field(default=10, description="Max size of log file in MB before rotation")
    log_backups: int = Field(default=5, description="Number of backup log files to keep")

    # Configure model for environment variable loading
    if HAS_SETTINGS_CONFIG_DICT:
        model_config = SettingsConfigDict(
            env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
        )
    else:

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            case_sensitive = False
            extra = "ignore"

    # =========================================================================
    # Field Validators
    # =========================================================================

    @field_validator("analysis_sources", mode="after")
    @classmethod
    def validate_analysis_sources(cls, v: str) -> str:
        """Ensure analysis_sources is a valid comma-separated string."""
        if not isinstance(v, str):
            return str(v)
        return v.strip() if v else "NVD,OSV,GITHUB"

    @field_validator("cors_origins", mode="after")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """Ensure cors_origins is a valid comma-separated string."""
        if not isinstance(v, str):
            return str(v)
        return v.strip() if v else "*"

    @field_validator("reload", mode="before")
    @classmethod
    def validate_reload(cls, v) -> bool:
        """Parse reload from string or bool."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes", "on")
        return False

    @field_validator("analysis_legacy_level", mode="before")
    @classmethod
    def validate_analysis_legacy_level(cls, v: Any) -> int:
        """Coerce ANALYSIS_LEGACY_LEVEL to a positive int (default 1)."""
        if v is None:
            return 1
        try:
            n = int(v)
        except (TypeError, ValueError):
            return 1
        return n if n > 0 else 1

    # =========================================================================
    # Computed/Derived Properties
    # =========================================================================

    @property
    def nvd_key_configured(self) -> bool:
        """Whether NVD_API_KEY is configured and non-empty."""
        return bool(self.nvd_api_key.strip())

    @property
    def github_configured(self) -> bool:
        """Whether GITHUB_TOKEN is configured and non-empty."""
        return bool(self.github_token.strip())

    @property
    def vulndb_configured(self) -> bool:
        """Whether VULNDB_API_KEY is configured and non-empty."""
        return bool(self.vulndb_api_key.strip())

    @property
    def analysis_sources_list(self) -> list[str]:
        """Parse ANALYSIS_SOURCES into a list of source names."""
        if not self.analysis_sources:
            return ["NVD", "OSV", "GITHUB"]
        sources = [s.strip().upper() for s in self.analysis_sources.split(",") if s.strip()]
        return sources or ["NVD", "OSV", "GITHUB"]

    @property
    def cve_sources_enabled_list(self) -> list[str]:
        """Parse cve_sources_enabled into a normalised lowercase list."""
        if not self.cve_sources_enabled:
            return []
        out = [s.strip().lower() for s in self.cve_sources_enabled.split(",") if s.strip()]
        valid = {"osv", "ghsa", "nvd", "epss", "kev"}
        return [s for s in out if s in valid]

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ORIGINS into a list of allowed origins."""
        if not self.cors_origins or self.cors_origins == "*":
            return ["*"]
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        return origins or ["*"]


# =========================================================================
# API Constants (module-level or attached to Settings for access)
# =========================================================================

# NVD API endpoint
Settings.NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# GitHub GraphQL endpoint
Settings.GITHUB_GRAPHQL = "https://api.github.com/graphql"

# OSV API endpoint
Settings.OSV_API = "https://api.osv.dev/v1"

# VulDB API endpoint
Settings.VULNDB_API = "https://vuldb.com/?api"

# OSV batch query limit
Settings.OSV_MAX_BATCH = 1000

# Maximum uploaded SBOM size — raised to 50 MB per ADR-0007 §4.1.
# Bodies above this are rejected at the ASGI middleware with HTTP 413.
Settings.MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# Maximum decompressed SBOM size — defends against decompression bombs.
# Stage 1 (ingress) tracks gzip / deflate output incrementally and aborts
# as soon as the cumulative byte count exceeds this number.
Settings.MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024

# Maximum compression-ratio (decompressed / compressed) accepted by stage 1.
# Real SBOMs are between 2:1 and 20:1; 100:1 is well above any legitimate
# document and well below the ratios produced by zip / gzip bombs.
Settings.MAX_DECOMPRESSION_RATIO = 100

# Below this byte count, validation runs synchronously inside the request.
# Above it, the request handler enqueues a Celery job and returns 202 with
# a ``validation_job_id`` so the user is not blocked. (Phase 4 perf-tests
# pin the threshold; ADR-0007 §6 makes it a knob, not a constant.)
Settings.SBOM_SYNC_VALIDATION_BYTES = 5 * 1024 * 1024

# Stage 8 feature flag. When false, the signature stage is a no-op even on
# documents that carry a signature block. Default OFF in v1.
Settings.SBOM_SIGNATURE_VERIFICATION = False

# Default pagination size
Settings.DEFAULT_RESULTS_PER_PAGE = 20

# Application version
Settings.APP_VERSION = "2.0.0"


# =========================================================================
# Singleton Factory
# =========================================================================

_settings_instance: Settings | None = None


def get_analysis_legacy_level() -> int:
    """Single source for legacy analysis level (maps env ANALYSIS_LEGACY_LEVEL via Settings)."""
    return get_settings().analysis_legacy_level


def get_settings() -> Settings:
    """
    Get or create the global Settings singleton.

    This function caches the Settings instance to avoid repeated
    environment variable parsing.

    Returns:
        Settings: The application settings instance.
    """
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance


def reset_settings() -> None:
    """
    Reset the cached settings singleton.

    Useful for testing or forcing a reload from environment variables.
    """
    global _settings_instance
    _settings_instance = None
