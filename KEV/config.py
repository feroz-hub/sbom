"""Application configuration loaded from environment variables (.env supported)."""

from datetime import date, datetime
from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings can be overridden via environment variables or a .env file."""

    # PostgreSQL connection (asyncpg driver)
    database_url: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/kev"
    )

    # Official CISA KEV JSON feed (always the FULL catalog)
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # Optional default cutoff date (YYYY-MM-DD). If set, only KEV entries with
    # dateAdded >= this date are synced when the API caller does not pass one.
    # Leave unset/empty to sync the complete catalog.
    kev_since_date: Optional[date] = None

    # HTTP client timeout in seconds for downloading the feed
    http_timeout: float = 60.0

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("kev_since_date", mode="before")
    @classmethod
    def _parse_date(cls, v):
        if v in (None, "", "null"):
            return None
        if isinstance(v, date):
            return v
        return datetime.strptime(str(v).strip(), "%Y-%m-%d").date()


@lru_cache
def get_settings() -> Settings:
    return Settings()
