"""DB-first / env-fallback configuration resolver.

Phase 2 §2.4 deliverable. Single read-side API that the registry calls
when constructing providers and the orchestrator calls when reading
budget caps. Hides three things from callers:

  1. **Decryption** — credentials live encrypted in the DB; this layer
     decrypts on read (and only on read), so provider clients never
     touch ciphertext.
  2. **Migration fallback** — when no DB row exists for a provider but
     env vars do, env wins. As soon as a DB row is saved, env is
     ignored. This keeps existing deployments working through the
     env-to-DB migration.
  3. **Cache invalidation** — DB writes bump a Redis-tracked version
     counter; readers compare their cached version on each read and
     drop the cache when it changes. Gives instant cross-process
     propagation without a long-running pub/sub subscriber.

The loader is process-local; the version counter lives in Redis (or
the in-memory progress-store fallback when Redis is down).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select

from ..models import AiProviderCredential, AiSettings
from ..security.secrets import SecretCipher, get_cipher
from ..settings import get_settings
from .registry import ProviderConfig, build_configs_from_settings

log = logging.getLogger("sbom.ai.config_loader")


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedSettings:
    """Singleton AI settings — DB-first, env fallback when no DB row."""

    feature_enabled: bool
    kill_switch_active: bool
    budget_per_request_usd: float
    budget_per_scan_usd: float
    budget_daily_usd: float
    source: str  # "db" | "env"


@dataclass(frozen=True)
class _CacheEntry:
    """One in-memory cache entry guarded by ``_VERSION_KEY``."""

    configs: list[ProviderConfig]
    settings: ResolvedSettings
    version: int
    cached_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Cache + version coordination
# ---------------------------------------------------------------------------


_VERSION_KEY = "ai:config:version"
_CACHE_TTL_SECONDS = 60.0  # safety net even when Redis is unavailable


class _VersionCounter:
    """Cross-process invalidation counter.

    Backed by Redis when available; falls back to a process-local int
    when Redis is unreachable (acceptable in single-process dev). The
    interface is read+bump — readers fetch, writers increment.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._local: int = 0

    def _client(self):
        # Reuse the progress store's Redis discovery: try Redis, fall
        # back to None. We don't import the store class to avoid a
        # circular dep — call ``redis.from_url`` directly with a short
        # connect timeout.
        try:
            import redis

            from ..settings import get_settings

            url = get_settings().redis_url
            client = redis.Redis.from_url(url, socket_timeout=1.0, socket_connect_timeout=0.5)
            client.ping()
            return client
        except Exception:  # noqa: BLE001
            return None

    def get(self) -> int:
        client = self._client()
        if client is not None:
            try:
                raw = client.get(_VERSION_KEY)
                if raw is None:
                    return 0
                if isinstance(raw, bytes):
                    raw = raw.decode("ascii", errors="replace")
                return int(raw)
            except Exception as exc:  # noqa: BLE001
                log.debug("ai.config.version_read_failed: %s", exc)
        with self._lock:
            return self._local

    def bump(self) -> int:
        """Increment the version. Called by every credential / settings write."""
        client = self._client()
        if client is not None:
            try:
                return int(client.incr(_VERSION_KEY))
            except Exception as exc:  # noqa: BLE001
                log.warning("ai.config.version_bump_failed: %s — falling back to local", exc)
        with self._lock:
            self._local += 1
            return self._local


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class AiConfigLoader:
    """Resolves AI configuration from DB first, env as fallback.

    Singleton instance returned by :func:`get_loader`. Tests can
    construct a fresh instance with their own session_factory.
    """

    def __init__(
        self,
        session_factory,
        *,
        cipher: SecretCipher | None = None,
        version_counter: _VersionCounter | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cipher = cipher
        self._version = version_counter or _VersionCounter()
        self._cache: _CacheEntry | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def invalidate(self) -> None:
        """Drop the in-memory cache. Called by writes after a DB commit."""
        with self._lock:
            self._cache = None
        # Bump the version so other processes drop their caches too.
        self._version.bump()

    def _cache_is_fresh(self) -> bool:
        if self._cache is None:
            return False
        if time.monotonic() - self._cache.cached_at > _CACHE_TTL_SECONDS:
            return False
        # Cross-process check: did anyone else bump the version since we cached?
        try:
            current = self._version.get()
        except Exception:  # noqa: BLE001
            current = self._cache.version
        return current == self._cache.version

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self) -> tuple[list[ProviderConfig], ResolvedSettings]:
        """Return the current resolved configs + settings.

        Cached for up to 60s and invalidated on any write or version bump.
        """
        with self._lock:
            if self._cache_is_fresh():
                assert self._cache is not None
                return self._cache.configs, self._cache.settings

        configs, settings = self._resolve_uncached()
        with self._lock:
            self._cache = _CacheEntry(
                configs=configs,
                settings=settings,
                version=self._version.get(),
            )
        return configs, settings

    def resolve_configs(self) -> list[ProviderConfig]:
        return self.resolve()[0]

    def resolve_settings(self) -> ResolvedSettings:
        return self.resolve()[1]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_uncached(self) -> tuple[list[ProviderConfig], ResolvedSettings]:
        env_configs = build_configs_from_settings()
        env_by_name = {c.name: c for c in env_configs}

        db_configs: dict[str, ProviderConfig] = {}
        db_settings: ResolvedSettings | None = None

        try:
            with self._session_factory() as session:
                rows = session.execute(select(AiProviderCredential)).scalars().all()
                for row in rows:
                    cfg = self._row_to_config(row)
                    if cfg is not None:
                        db_configs[cfg.name] = cfg
                settings_row = session.execute(select(AiSettings).where(AiSettings.id == 1)).scalar_one_or_none()
                if settings_row is not None:
                    db_settings = ResolvedSettings(
                        feature_enabled=bool(settings_row.feature_enabled),
                        kill_switch_active=bool(settings_row.kill_switch_active),
                        budget_per_request_usd=float(settings_row.budget_per_request_usd or 0.0),
                        budget_per_scan_usd=float(settings_row.budget_per_scan_usd or 0.0),
                        budget_daily_usd=float(settings_row.budget_daily_usd or 0.0),
                        source="db",
                    )
        except Exception as exc:  # noqa: BLE001 — DB unavailable falls back to env
            log.warning("ai.config.db_read_failed: %s — falling back to env", exc)
            db_configs = {}
            db_settings = None

        # DB rows win over env. Providers present in env but not in DB
        # keep their env config (the migration path).
        merged_configs: dict[str, ProviderConfig] = dict(env_by_name)
        merged_configs.update(db_configs)

        # Settings: DB row wins; otherwise pull from env.
        if db_settings is not None:
            settings = db_settings
        else:
            s = get_settings()
            settings = ResolvedSettings(
                feature_enabled=bool(s.ai_fixes_enabled),
                kill_switch_active=bool(s.ai_fixes_kill_switch),
                budget_per_request_usd=float(s.ai_budget_per_request_usd),
                budget_per_scan_usd=float(s.ai_budget_per_scan_usd),
                budget_daily_usd=float(s.ai_budget_per_day_org_usd),
                source="env",
            )

        return list(merged_configs.values()), settings

    def _row_to_config(self, row: AiProviderCredential) -> ProviderConfig | None:
        """Decrypt + map one DB row into a registry-shaped ProviderConfig.

        Returns ``None`` (skips) if the row is disabled or has a
        decryption failure (logged but not raised — bad rows shouldn't
        bring down the whole loader).
        """
        if not bool(row.enabled):
            return None

        api_key = ""
        if row.api_key_encrypted:
            try:
                cipher = self._cipher or get_cipher()
                api_key = cipher.decrypt(row.api_key_encrypted)
            except Exception:  # noqa: BLE001
                # Hard rule: never log the ciphertext or plaintext. The
                # exception type is enough for triage; the provider /
                # row id pinpoints which credential needs re-entry.
                log.error(
                    "ai.config.decrypt_failed: provider=%s id=%s — row skipped",
                    row.provider_name,
                    row.id,
                )
                return None

        # The registry inspects ``organization == "__default__"`` to pick
        # the default provider when one is flagged in the DB. ``"__fallback__"``
        # encodes the secondary. Both are sentinel values that never reach
        # the OpenAI provider's actual ``OpenAI-Organization`` header
        # (only the ``openai`` provider sets that header at all).
        org_marker = ""
        if bool(row.is_default):
            org_marker = "__default__"
        elif bool(row.is_fallback):
            org_marker = "__fallback__"

        return ProviderConfig(
            name=row.provider_name,
            enabled=True,
            default_model=row.default_model or "",
            api_key=api_key,
            base_url=(row.base_url or "").strip(),
            organization=org_marker,
            max_concurrent=int(row.max_concurrent) if row.max_concurrent else 10,
            rate_per_minute=float(row.rate_per_minute) if row.rate_per_minute else 60.0,
            tier=(row.tier or "paid").lower(),
            cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
            cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
            is_local=bool(row.is_local),
        )


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def preview_api_key(plaintext: str | None) -> tuple[str | None, bool]:
    """Return (preview, present). Preview is first 6 + last 4 with ellipsis.

    Used by the read API to give the UI enough context to confirm
    "yes I see my key" without revealing the full secret. Hard rule:
    callers MUST use this; never return the raw plaintext.
    """
    if not plaintext:
        return None, False
    if len(plaintext) <= 10:
        # Pathological short keys (test keys, usually) — avoid revealing
        # most of them. Mask everything after the first 2 chars.
        return plaintext[:2] + "…", True
    return f"{plaintext[:6]}…{plaintext[-4:]}", True


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


_loader: AiConfigLoader | None = None
_loader_lock = threading.Lock()


def get_loader() -> AiConfigLoader:
    """Process-wide loader using the canonical SessionLocal."""
    global _loader
    with _loader_lock:
        if _loader is None:
            from ..db import SessionLocal

            _loader = AiConfigLoader(SessionLocal)
        return _loader


def reset_loader() -> None:
    """Test helper — drops the cached singleton."""
    global _loader
    with _loader_lock:
        _loader = None


__all__ = [
    "AiConfigLoader",
    "ResolvedSettings",
    "get_loader",
    "now_iso",
    "preview_api_key",
    "reset_loader",
]
