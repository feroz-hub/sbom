"""
Settings module for SBOM Analyzer.

Centralizes all environment variable reads using Pydantic BaseSettings.
Provides a single source of truth for application configuration.

Supports both pydantic v2 with pydantic-settings and standalone pydantic v2.
"""

from typing import Optional, List
import os

from pydantic import Field, field_validator, BaseModel


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

    # Analysis Configuration
    analysis_sources: str = Field(
        default="NVD",
        description="Comma-separated list of analysis sources (NVD, OSV, GITHUB)"
    )

    # CORS Configuration
    cors_origins: str = Field(
        default="*",
        description="Comma-separated list of allowed CORS origins"
    )

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8000, description="Server port")
    reload: bool = Field(default=False, description="Enable auto-reload on code changes")

    # Database Configuration
    database_url: str = Field(
        default="sqlite:///./sbom_analyzer.db",
        description="SQLAlchemy database URL"
    )

    # Analysis Settings
    analysis_legacy_level: int = Field(
        default=1,
        description="Legacy analysis level (0=new, 1+=compatibility)"
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
            env_file=".env",
            env_file_encoding="utf-8",
            case_sensitive=False,
            extra="ignore"
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
        return v.strip() if v else "NVD"

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
    def analysis_sources_list(self) -> List[str]:
        """Parse ANALYSIS_SOURCES into a list of source names."""
        if not self.analysis_sources:
            return ["NVD"]
        sources = [s.strip().upper() for s in self.analysis_sources.split(",") if s.strip()]
        return sources or ["NVD"]

    @property
    def cors_origins_list(self) -> List[str]:
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

_settings_instance: Optional[Settings] = None


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
