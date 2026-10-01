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

import hashlib
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AiProviderCredential, AiSettings
from ..security.secrets import SecretCipher, get_cipher
from ..services.configuration_scope import (
    current_configuration_tenant,
    require_active_configuration_tenant,
    scope_clause,
)
from ..settings import get_settings
from .config_types import EffectiveAiConfig, ProviderConfig

log = logging.getLogger("sbom.ai.config_loader")


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


# Backward-compatible import name.  New runtime code should use the more
# explicit ``EffectiveAiConfig`` name.
ResolvedSettings = EffectiveAiConfig


@dataclass(frozen=True)
class _CacheEntry:
    """One in-memory cache entry guarded by ``_VERSION_KEY``."""

    configs: list[ProviderConfig]
    settings: ResolvedSettings
    version: int
    namespace: str = ""
    cached_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Cache + version coordination
# ---------------------------------------------------------------------------


_VERSION_KEY = "ai:config:version"
_CACHE_TTL_SECONDS = 60.0  # safety net even when Redis is unavailable
_BOUND_SCOPE = object()


class _VersionCounter:
    """Cross-process invalidation counter.

    Backed by Redis when available; falls back to a process-local int
    when Redis is unreachable (acceptable in single-process dev). The
    interface is read+bump — readers fetch, writers increment.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._local: dict[str, int] = {}
        self._redis = None
        self._retry_after = 0.0

    def _client(self):
        # Reuse the progress store's Redis discovery: try Redis, fall
        # back to None. We don't import the store class to avoid a
        # circular dep — call ``redis.from_url`` directly with a short
        # connect timeout.
        if time.monotonic() < self._retry_after:
            return None
        if self._redis is not None:
            return self._redis
        try:
            import redis

            from ..settings import get_settings

            url = get_settings().redis_url
            client = redis.Redis.from_url(url, socket_timeout=1.0, socket_connect_timeout=0.5)
            client.ping()
            self._redis = client
            return client
        except Exception:  # noqa: BLE001
            # Do not pay a connection timeout for every finding in a batch.
            self._retry_after = time.monotonic() + 5.0
            return None

    def get(self, scope=None) -> int:
        key = f"{_VERSION_KEY}:{scope if scope is not None else 'platform'}"
        client = self._client()
        if client is not None:
            try:
                raw = client.get(key)
                if raw is None:
                    return 0
                if isinstance(raw, bytes):
                    raw = raw.decode("ascii", errors="replace")
                return int(raw)
            except Exception as exc:  # noqa: BLE001
                self._redis = None
                self._retry_after = time.monotonic() + 5.0
                log.debug("ai.config.version_read_failed: %s", type(exc).__name__)
        with self._lock:
            return self._local.get(key, 0)

    def bump(self, scope=None) -> int:
        key = f"{_VERSION_KEY}:{scope if scope is not None else 'platform'}"
        """Increment the version. Called by every credential / settings write."""
        client = self._client()
        if client is not None:
            try:
                return int(client.incr(key))
            except Exception as exc:  # noqa: BLE001
                self._redis = None
                self._retry_after = time.monotonic() + 5.0
                log.warning("ai.config.version_bump_failed: %s — falling back to local", type(exc).__name__)
        with self._lock:
            self._local[key] = self._local.get(key, 0) + 1
            return self._local[key]


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
        self._cache: dict[int | None, _CacheEntry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def invalidate(self) -> None:
        """Drop the in-memory cache. Called by writes after a DB commit."""
        with self._lock:
            tenant_id = current_configuration_tenant()
            if tenant_id is None:
                self._cache.clear()
            else:
                self._cache.pop(tenant_id, None)
        # Bump the version so other processes drop their caches too.
        self._version.bump(tenant_id)

    def current_version(self) -> int:
        """Read the cross-process version counter without bumping.

        Downstream caches (e.g. the provider registry) compare against
        this to detect that a credential / settings write has landed and
        rebuild their own snapshots.
        """
        tenant_id = current_configuration_tenant()
        # Pairing avoids collisions and never invalidates another tenant for
        # a tenant-only write. Platform writes invalidate inheriting readers.
        platform = self._version.get()
        tenant = self._version.get(tenant_id) if tenant_id is not None else 0
        return (platform + tenant) * (platform + tenant + 1) // 2 + tenant

    def _cache_is_fresh(self, tenant_id) -> bool:
        entry = self._cache.get(tenant_id)
        if entry is None:
            return False
        if time.monotonic() - entry.cached_at > _CACHE_TTL_SECONDS:
            return False
        # Cross-process check: did anyone else bump the version since we cached?
        try:
            current = self.current_version()
        except Exception:  # noqa: BLE001
            current = entry.version
        return current == entry.version

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self) -> tuple[list[ProviderConfig], ResolvedSettings]:
        """Return the current resolved configs + settings.

        Cached for up to 60s and invalidated on any write or version bump.
        """
        tenant_id = current_configuration_tenant()
        if tenant_id is not None:
            with self._session_factory() as session:
                require_active_configuration_tenant(session, tenant_id)
        with self._lock:
            if self._cache_is_fresh(tenant_id):
                entry = self._cache[tenant_id]
                return entry.configs, entry.settings

        # Capture before reading: a concurrent write must not stamp stale data
        # with its new version and keep it fresh until the TTL expires.
        version = self.current_version()
        configs, settings = self._resolve_uncached()
        namespace = hashlib.sha256(
            json.dumps(
                {"providers": [asdict(config) for config in configs], "settings": asdict(settings)},
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest()
        with self._lock:
            self._cache[tenant_id] = _CacheEntry(
                configs=configs,
                settings=settings,
                version=version,
                namespace=namespace,
            )
        return configs, settings

    def result_cache_namespace(self) -> str:
        """Fingerprint effective configuration even when Redis is unavailable.

        Decrypted credential material is hashed only in memory, never returned
        or logged. A remote write discovered through the safety TTL therefore
        also invalidates persistent result caches, not only provider clients.
        """
        configs, settings = self.resolve()
        with self._lock:
            entry = self._cache.get(current_configuration_tenant())
            if entry is not None and entry.configs is configs:
                return entry.namespace
        # A write may invalidate the entry between resolve and this lookup;
        # retain the fingerprint for the snapshot used by this operation.
        return hashlib.sha256(
            json.dumps(
                {"providers": [asdict(config) for config in configs], "settings": asdict(settings)},
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest()

    def resolve_configs(self) -> list[ProviderConfig]:
        return self.resolve()[0]

    def resolve_settings(self) -> ResolvedSettings:
        return self.resolve()[1]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_uncached(self) -> tuple[list[ProviderConfig], ResolvedSettings]:
        # Local import avoids a config-loader/registry import cycle while
        # retaining the env-only migration path.
        from .registry import build_configs_from_settings

        env_configs = build_configs_from_settings()
        db_configs: list[ProviderConfig] = []
        authoritative_provider_names: set[str] = set()
        db_settings: ResolvedSettings | None = None

        try:
            with self._session_factory() as session:
                tenant_id = current_configuration_tenant()
                tenant_rows = (
                    list(
                        session.scalars(
                            select(AiProviderCredential).where(scope_clause(AiProviderCredential, tenant_id))
                        )
                    )
                    if tenant_id is not None
                    else []
                )
                settings_row = (
                    session.scalar(select(AiSettings).where(scope_clause(AiSettings, tenant_id)))
                    if tenant_id is not None
                    else None
                )
                override = bool(tenant_rows or settings_row is not None)
                rows = (
                    tenant_rows
                    if override
                    else session.scalars(
                        select(AiProviderCredential)
                        .where(AiProviderCredential.tenant_id.is_(None))
                        .order_by(AiProviderCredential.id)
                    ).all()
                )
                for row in rows:
                    authoritative_provider_names.add(str(row.provider_name).strip().lower())
                    cfg = self._row_to_config(row, session=session)
                    db_configs.append(cfg)
                if settings_row is None:
                    settings_row = session.scalar(select(AiSettings).where(AiSettings.tenant_id.is_(None)))
                if settings_row is not None:
                    db_settings = ResolvedSettings(
                        feature_enabled=bool(settings_row.feature_enabled),
                        kill_switch_active=bool(settings_row.kill_switch_active),
                        budget_per_request_usd=float(settings_row.budget_per_request_usd or 0.0),
                        budget_per_scan_usd=float(settings_row.budget_per_scan_usd or 0.0),
                        budget_daily_usd=float(settings_row.budget_daily_usd or 0.0),
                        source="db",
                    )
        except Exception as exc:  # noqa: BLE001
            if current_configuration_tenant() is not None:
                raise RuntimeError("Unable to resolve tenant AI configuration") from None
            log.warning("ai.config.db_read_failed: %s — falling back to env", type(exc).__name__)
            db_configs = []
            authoritative_provider_names = set()
            db_settings = None
            override = False

        # Any DB row is authoritative for that provider name, including an
        # explicitly disabled row or one whose credential cannot be
        # decrypted.  Legacy env credentials are used only when no DB row for
        # that provider exists.
        merged_configs = [cfg for cfg in env_configs if not override and cfg.name not in authoritative_provider_names]
        merged_configs.extend(db_configs)

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

        return merged_configs, settings

    def _row_to_config(self, row: AiProviderCredential, *, session: Session | None = None) -> ProviderConfig:
        """Decrypt + map one DB row into a registry-shaped ProviderConfig.

        Disabled and unreadable rows remain in the resolved model as explicit
        unavailable configurations.  Their presence suppresses legacy env
        fallback for the same provider.
        """
        enabled = bool(row.enabled)
        api_key = ""
        config_error: str | None = None if enabled else "disabled_by_administrator"
        if enabled and row.api_key_encrypted:
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
                config_error = "credential_decryption_failed"

        default_model = row.default_model or ""
        if session is not None:
            from .model_resolver import resolve_model_for_credential

            default_model = resolve_model_for_credential(session, row).model_id

        return ProviderConfig(
            name=str(row.provider_name).strip().lower(),
            enabled=enabled and config_error is None,
            default_model=default_model,
            api_key=api_key,
            base_url=(row.base_url or "").strip(),
            organization="",
            max_concurrent=int(row.max_concurrent) if row.max_concurrent else 10,
            rate_per_minute=float(row.rate_per_minute) if row.rate_per_minute else 60.0,
            tier=(row.tier or "paid").lower(),
            cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
            cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
            is_local=bool(row.is_local),
            credential_id=int(row.id),
            label=row.label or "default",
            is_default=bool(row.is_default),
            is_fallback=bool(row.is_fallback),
            source="db",
            config_error=config_error,
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


def resolve_effective_ai_configuration(tenant_id: int):
    """Explicit workload resolver; never derives an owner from a process cache."""
    from ..core.context import minimal_background_context, tenant_scope

    with tenant_scope(minimal_background_context(tenant_id)):
        return get_loader().resolve()


__all__ = [
    "AiConfigLoader",
    "EffectiveAiConfig",
    "ResolvedSettings",
    "get_loader",
    "now_iso",
    "preview_api_key",
    "reset_loader",
]
