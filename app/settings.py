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

    # S3-compatible object storage (optional)
    aws_access_key_id: str = Field(default="", description="S3 access key")
    aws_secret_access_key: str = Field(default="", description="S3 secret key")
    aws_region: str = Field(default="us-east-1", description="AWS region")
    aws_s3_bucket: str = Field(default="", description="SBOM artifact bucket")
    aws_s3_endpoint_url: str = Field(
        default="",
        description="Custom S3 endpoint (MinIO, etc.); empty uses AWS default",
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

# Maximum upload size (20 MB)
Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024

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
