"""NVD mirror settings — env-driven defaults.

The mirror has TWO sources of configuration:

  1. Env-driven defaults loaded at process start (this module). These
     populate ``cfg.mirror`` on the existing ``_MultiSettings`` dataclass
     in ``app/analysis.py`` so the rest of the analyzer code path can
     read them without touching the DB.
  2. DB-backed live settings stored in the ``nvd_settings`` row, edited
     by the admin UI in Phase 4. Loaded via ``SettingsRepositoryPort``.

When the DB row does not exist, ``SettingsRepositoryPort.load`` seeds it
from the env defaults. After that, the DB is the source of truth and env
values are ignored at runtime — operators flip the feature on/off via the
admin UI, not by restarting the process.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NvdMirrorSettings:
    """Frozen, env-driven defaults for the NVD mirror.

    Field semantics intentionally match the ``nvd_settings`` table column
    list so a row can be reconstructed from this dataclass on first boot.

    Attributes:
        enabled: Master switch. Default False — the mirror is opt-in and
            the analyzer's existing live-API path keeps working unchanged.
        api_endpoint: NVD CVE 2.0 REST URL. Configurable so air-gapped
            deployments can point at a corporate proxy.
        api_key_env_var: Name of the env var that holds the plaintext NVD
            API key. The key itself is NEVER stored here — adapters read
            it via this indirection so the key cannot leak through repr.
        fernet_key_env_var: Name of the env var holding the Fernet key
            used to encrypt the API key at rest in ``nvd_settings``.
        download_feeds_enabled: Reserved for a future filesystem-feed
            adapter. Phase 2 keeps the field so the column exists; Phase
            3+ ignores it.
        page_size: NVD page size (max 2000). Lower values trade requests
            for memory; default 2000 matches NVD's API ceiling.
        window_days: Width of the lastModified sliding window. NVD caps
            at 120 days; we use 119 to leave headroom for clock skew.
        min_freshness_hours: Beyond this age, ``last_successful_sync_at``
            is considered stale and the Phase 5 facade falls through to
            the live API. Default 24 h.
    """

    enabled: bool = False
    api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key_env_var: str = "NVD_API_KEY"
    fernet_key_env_var: str = "NVD_MIRROR_FERNET_KEY"
    download_feeds_enabled: bool = False
    page_size: int = 2000
    window_days: int = 119
    min_freshness_hours: int = 24


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    stripped = raw.strip()
    return stripped or default


def load_mirror_settings_from_env() -> NvdMirrorSettings:
    """Build NvdMirrorSettings from the process environment.

    Env vars (all optional — defaults match the NvdMirrorSettings dataclass):

      * NVD_MIRROR_ENABLED                   bool   (default False)
      * NVD_MIRROR_API_ENDPOINT              str
      * NVD_MIRROR_API_KEY_ENV_VAR           str    (default 'NVD_API_KEY')
      * NVD_MIRROR_FERNET_KEY_ENV_VAR        str    (default 'NVD_MIRROR_FERNET_KEY')
      * NVD_MIRROR_DOWNLOAD_FEEDS_ENABLED    bool   (default False)
      * NVD_MIRROR_PAGE_SIZE                 int    (1 .. 2000, default 2000)
      * NVD_MIRROR_WINDOW_DAYS               int    (1 .. 119, default 119)
      * NVD_MIRROR_MIN_FRESHNESS_HOURS       int    (>= 0, default 24)
    """
    return NvdMirrorSettings(
        enabled=_env_bool("NVD_MIRROR_ENABLED", False),
        api_endpoint=_env_str(
            "NVD_MIRROR_API_ENDPOINT",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
        api_key_env_var=_env_str("NVD_MIRROR_API_KEY_ENV_VAR", "NVD_API_KEY"),
        fernet_key_env_var=_env_str(
            "NVD_MIRROR_FERNET_KEY_ENV_VAR", "NVD_MIRROR_FERNET_KEY"
        ),
        download_feeds_enabled=_env_bool("NVD_MIRROR_DOWNLOAD_FEEDS_ENABLED", False),
        page_size=_env_int("NVD_MIRROR_PAGE_SIZE", 2000, minimum=1, maximum=2000),
        window_days=_env_int("NVD_MIRROR_WINDOW_DAYS", 119, minimum=1, maximum=119),
        min_freshness_hours=_env_int(
            "NVD_MIRROR_MIN_FRESHNESS_HOURS", 24, minimum=0, maximum=24 * 365
        ),
    )
