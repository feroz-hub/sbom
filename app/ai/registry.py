"""Provider registry — single read-side entrypoint for the orchestrator.

The registry is the only thing the rest of the app interacts with. It:

  * Reads exact credential configurations from :class:`AiConfigLoader`.
    Database rows are authoritative; environment values are migration
    fallback only when no DB row exists for that provider.
  * Instantiates concrete providers on demand.
  * Hands the orchestrator a :class:`LlmProvider` by name, or the configured
    default.

Why a single registry: it's the seam where "we use Anthropic" stops being
a code fact and becomes a config fact. Any code outside this module that
asks for "the LLM" goes through :func:`get_registry`.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from sqlalchemy.orm import Session

from .config_types import ProviderConfig
from .provider_factory import build_provider
from .providers.base import (
    AiProviderError,
    CircuitBreakerOpenError,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    ProviderInfo,
    ProviderUnavailableError,
)

log = logging.getLogger("sbom.ai.registry")


@dataclass(frozen=True)
class RoutedGeneration:
    """One successful call plus safe primary/fallback routing metadata."""

    response: LlmResponse
    provider: LlmProvider
    primary_provider: LlmProvider
    fallback_used: bool = False
    primary_error: AiProviderError | None = None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ProviderRegistry:
    """Holds a list of configured providers and lazily instantiates them.

    Lazy-instantiation matters: in dev with no API keys set, importing the
    registry shouldn't fail just because Anthropic isn't configured —
    :class:`AnthropicProvider` only raises when it's actually instantiated.
    """

    def __init__(
        self,
        configs: list[ProviderConfig],
        *,
        default_provider: str,
    ) -> None:
        self._configs = {c.selection_key: c for c in configs}
        self._keys_by_name: dict[str, list[str]] = {}
        for cfg in configs:
            self._keys_by_name.setdefault(cfg.name, []).append(cfg.selection_key)
        for keys in self._keys_by_name.values():
            keys.sort(key=self._config_sort_key)
        self._default_selector = default_provider
        self._default_key = self._resolve_key(default_provider, prefer_flag="default")
        self._fallback_key = next(
            (cfg.selection_key for cfg in configs if cfg.is_fallback),
            None,
        )
        self._instances: dict[str, LlmProvider] = {}
        self._lock = threading.Lock()

    @property
    def default_name(self) -> str:
        cfg = self.get_default_config()
        return cfg.name

    @property
    def default_credential_id(self) -> int | None:
        return self.get_default_config().credential_id

    @property
    def fallback_name(self) -> str | None:
        if self._fallback_key is None:
            return None
        return self._configs[self._fallback_key].name

    @staticmethod
    def _config_sort_key(key: str) -> tuple[int, int, str]:
        if key.startswith("credential:"):
            try:
                return (0, int(key.split(":", 1)[1]), key)
            except ValueError:
                pass
        return (1, 0, key)

    def _resolve_key(self, selector: str, *, prefer_flag: str | None = None) -> str | None:
        if selector in self._configs:
            return selector
        keys = self._keys_by_name.get(selector, [])
        if prefer_flag == "default":
            flagged = [key for key in keys if self._configs[key].is_default]
            if flagged:
                return flagged[0]
        enabled = [key for key in keys if self._configs[key].enabled]
        return enabled[0] if enabled else (keys[0] if keys else None)

    def get_default_config(self) -> ProviderConfig:
        key = self._default_key or self._resolve_key(self._default_selector, prefer_flag="default")
        if key is None:
            raise ProviderUnavailableError(f"default provider {self._default_selector!r} is not configured")
        return self._configs[key]

    def get_fallback_config(self) -> ProviderConfig | None:
        if self._fallback_key is None:
            return None
        return self._configs[self._fallback_key]

    def list_available(self) -> list[ProviderInfo]:
        """Public metadata (Settings page consumes this).

        Disabled providers are reported with ``available=False`` so the UI
        can grey them out instead of hiding them.
        """
        out: list[ProviderInfo] = []
        for key, cfg in self._configs.items():
            if not cfg.enabled:
                out.append(
                    ProviderInfo(
                        name=cfg.name,
                        available=False,
                        default_model=cfg.default_model,
                        supports_structured_output=True,
                        is_local=(cfg.name in {"ollama", "vllm"}) or (cfg.name == "custom_openai" and cfg.is_local),
                        notes="Disabled — no credentials configured.",
                    )
                )
                continue
            try:
                out.append(self.get(key).info())
            except Exception as exc:  # noqa: BLE001
                out.append(
                    ProviderInfo(
                        name=cfg.name,
                        available=False,
                        default_model=cfg.default_model,
                        supports_structured_output=True,
                        is_local=(cfg.name in {"ollama", "vllm"}) or (cfg.name == "custom_openai" and cfg.is_local),
                        notes=f"Disabled — {exc}",
                    )
                )
        return out

    def get(self, name: str) -> LlmProvider:
        """Return the provider instance, instantiating on first use.

        Raises :class:`ProviderUnavailableError` for unknown / disabled / mis-configured names.
        """
        key = self._resolve_key(name, prefer_flag="default")
        if key is None:
            raise ProviderUnavailableError(f"unknown provider: {name!r}")
        cfg = self._configs[key]
        if not cfg.enabled:
            reason = cfg.config_error or "no credentials configured"
            raise ProviderUnavailableError(f"provider {cfg.name!r} is not enabled ({reason})")

        with self._lock:
            if key in self._instances:
                return self._instances[key]
            instance = self._build_provider(cfg)
            self._instances[key] = instance
            return instance

    def get_default(self) -> LlmProvider:
        return self.get(self.get_default_config().selection_key)

    def get_fallback(self) -> LlmProvider | None:
        cfg = self.get_fallback_config()
        if cfg is None or not cfg.enabled:
            return None
        if cfg.selection_key == self.get_default_config().selection_key:
            return None
        return self.get(cfg.selection_key)

    async def generate_with_fallback(
        self,
        request: LlmRequest,
        *,
        provider_name: str | None = None,
    ) -> RoutedGeneration:
        """Generate once on primary, then at most once on eligible fallback.

        Fallback is limited to transient provider conditions: an open circuit,
        network outage, throttling/quota exhaustion, or upstream 5xx. Auth,
        model, request/schema, budget, and local configuration errors are
        deterministic and are returned directly.
        """
        primary = self.get(provider_name) if provider_name else self.get_default()
        try:
            response = await primary.generate(request)
            return RoutedGeneration(response=response, provider=primary, primary_provider=primary)
        except AiProviderError as exc:
            if not _fallback_eligible(exc):
                raise
            fallback = self.get_fallback()
            if fallback is None or fallback is primary:
                raise
            log.warning(
                "ai.provider.fallback_selected: primary=%s fallback=%s reason=%s",
                primary.name,
                fallback.name,
                _safe_failure_kind(exc),
            )
            response = await fallback.generate(request)
            return RoutedGeneration(
                response=response,
                provider=fallback,
                primary_provider=primary,
                fallback_used=True,
                primary_error=exc,
            )

    @staticmethod
    def _build_provider(cfg: ProviderConfig) -> LlmProvider:
        return build_provider(cfg)

    # ------------------------------------------------------------------
    # Test / admin helpers
    # ------------------------------------------------------------------

    def register_instance(self, instance: LlmProvider, *, selector: str | None = None) -> None:
        """Inject a pre-built provider (used by tests)."""
        with self._lock:
            key = selector or f"env:{instance.name}"
            config = self._configs.get(key) or ProviderConfig(
                name=instance.name,
                enabled=True,
                default_model=getattr(instance, "default_model", ""),
            )
            if selector is None:
                key = config.selection_key
            self._configs.setdefault(key, config)
            keys = self._keys_by_name.setdefault(instance.name, [])
            if key not in keys:
                keys.append(key)
                keys.sort(key=self._config_sort_key)
            self._instances[key] = instance
            if self._default_key is None and self._default_selector == instance.name:
                self._default_key = key

    def reset(self) -> None:
        with self._lock:
            self._instances.clear()


def _safe_failure_kind(exc: AiProviderError) -> str:
    if isinstance(exc, CircuitBreakerOpenError):
        return "circuit_breaker_open"
    if exc.failure is not None:
        return exc.failure.kind
    return "unknown"


def _fallback_eligible(exc: AiProviderError) -> bool:
    if isinstance(exc, CircuitBreakerOpenError):
        return True
    return bool(
        exc.failure
        and exc.failure.kind
        in {"network_unreachable", "provider_down", "rate_limited", "quota_exceeded"}
    )


# ---------------------------------------------------------------------------
# Configuration loaders
# ---------------------------------------------------------------------------


def build_configs_from_settings() -> list[ProviderConfig]:
    """Build the provider list from environment / Settings.

    A provider is ``enabled=True`` only when the credentials it needs are
    actually present — Anthropic / OpenAI need an API key, Ollama / vLLM
    need a base URL. Anything else is reported as disabled (visible but
    unusable in the UI).
    """
    from ..settings import get_settings

    s = get_settings()
    declared = {n.strip().lower() for n in s.ai_providers.split(",") if n.strip()}

    out: list[ProviderConfig] = []
    if "anthropic" in declared:
        out.append(
            ProviderConfig(
                name="anthropic",
                enabled=bool(s.anthropic_api_key.strip()),
                default_model=s.ai_anthropic_model,
                api_key=s.anthropic_api_key.strip(),
                max_concurrent=s.ai_anthropic_max_concurrent,
                rate_per_minute=s.ai_anthropic_rpm,
            )
        )
    if "openai" in declared:
        out.append(
            ProviderConfig(
                name="openai",
                enabled=bool(s.openai_api_key.strip()),
                default_model=s.ai_openai_model,
                api_key=s.openai_api_key.strip(),
                base_url=s.ai_openai_base_url.strip() or "https://api.openai.com/v1",
                organization=s.ai_openai_organization.strip(),
                max_concurrent=s.ai_openai_max_concurrent,
                rate_per_minute=s.ai_openai_rpm,
            )
        )
    if "ollama" in declared:
        out.append(
            ProviderConfig(
                name="ollama",
                enabled=bool(s.ollama_base_url.strip()),
                default_model=s.ai_ollama_model,
                base_url=s.ollama_base_url.strip(),
                max_concurrent=s.ai_ollama_max_concurrent,
                rate_per_minute=s.ai_ollama_rpm,
            )
        )
    if "vllm" in declared:
        out.append(
            ProviderConfig(
                name="vllm",
                enabled=bool(s.vllm_base_url.strip()),
                default_model=s.ai_vllm_model,
                base_url=s.vllm_base_url.strip(),
                api_key=s.vllm_api_key.strip() or "EMPTY",
                max_concurrent=s.ai_vllm_max_concurrent,
                rate_per_minute=s.ai_vllm_rpm,
            )
        )
    if "gemini" in declared:
        out.append(
            ProviderConfig(
                name="gemini",
                enabled=bool(s.gemini_api_key.strip()),
                default_model=s.ai_gemini_model,
                api_key=s.gemini_api_key.strip(),
                max_concurrent=s.ai_gemini_max_concurrent,
                rate_per_minute=s.ai_gemini_rpm,
                tier="free" if (s.ai_gemini_tier or "").strip().lower() == "free" else "paid",
            )
        )
    if "grok" in declared:
        out.append(
            ProviderConfig(
                name="grok",
                enabled=bool(s.grok_api_key.strip()),
                default_model=s.ai_grok_model,
                api_key=s.grok_api_key.strip(),
                max_concurrent=s.ai_grok_max_concurrent,
                rate_per_minute=s.ai_grok_rpm,
                tier="free" if (s.ai_grok_tier or "").strip().lower() == "free" else "paid",
            )
        )
    if "sarvam" in declared:
        out.append(
            ProviderConfig(
                name="sarvam",
                enabled=bool(s.sarvam_api_key.strip()),
                default_model=s.ai_sarvam_model,
                api_key=s.sarvam_api_key.strip(),
                base_url=(s.ai_sarvam_base_url or "https://api.sarvam.ai/v1").strip(),
                max_concurrent=s.ai_sarvam_max_concurrent,
                rate_per_minute=s.ai_sarvam_rpm,
            )
        )
    if "custom_openai" in declared:
        custom_url = (s.ai_custom_openai_base_url or "").strip()
        custom_model = (s.ai_custom_openai_model or "").strip()
        out.append(
            ProviderConfig(
                name="custom_openai",
                # Both URL + model required to be considered enabled.
                enabled=bool(custom_url) and bool(custom_model),
                default_model=custom_model,
                base_url=custom_url,
                api_key=s.ai_custom_openai_api_key.strip() or "EMPTY",
                max_concurrent=s.ai_custom_openai_max_concurrent,
                rate_per_minute=s.ai_custom_openai_rpm,
                cost_per_1k_input_usd=float(s.ai_custom_openai_cost_per_1k_input or 0.0),
                cost_per_1k_output_usd=float(s.ai_custom_openai_cost_per_1k_output or 0.0),
                is_local=bool(s.ai_custom_openai_is_local),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


_registry_lock = threading.Lock()
_registry: ProviderRegistry | None = None
# Loader version observed when ``_registry`` was last (re)built. Compared
# against the loader's current version on every ``get_registry`` call so
# credential / settings writes propagate without a process restart.
_registry_version: int = -1


def _resolve_default_provider_name(configs: list[ProviderConfig]) -> str:
    """Pick the default provider name.

    Priority:
      1. The exact DB credential carrying ``is_default=True``.
      2. Otherwise fall back to the env-driven ``AI_DEFAULT_PROVIDER``.
    """
    for cfg in configs:
        if cfg.is_default:
            return cfg.name
    from ..settings import get_settings

    return get_settings().ai_default_provider


def get_registry(db: Session | None = None) -> ProviderRegistry:
    """Return the process-wide registry, rebuilding when config changes.

    Resolves provider configs via the Phase 2 :class:`AiConfigLoader`
    (DB-first, env fallback). The registry is cached, but its snapshot
    is keyed on the loader's cross-process version counter — credential
    or settings writes bump that counter and we rebuild on the next
    call so the new default propagates without a process restart.
    ``db`` is accepted for backward compat but no longer used directly —
    the loader owns the session.
    """
    global _registry, _registry_version
    with _registry_lock:
        try:
            from .config_loader import get_loader

            loader = get_loader()
            current_version = loader.current_version()
            if _registry is None or current_version != _registry_version:
                configs = loader.resolve_configs()
                default = _resolve_default_provider_name(configs)
                _registry = ProviderRegistry(configs, default_provider=default)
                _registry_version = current_version
        except Exception as exc:  # noqa: BLE001
            # Fall back to env-only when the loader can't construct
            # (e.g. in early-boot test scenarios with no DB). We hold
            # onto whatever registry we already had; if there's none,
            # build one from env so callers don't get None.
            if _registry is None:
                log.warning("ai.registry.loader_unavailable: %s — env fallback", exc)
                configs = build_configs_from_settings()
                default = _resolve_default_provider_name(configs)
                _registry = ProviderRegistry(configs, default_provider=default)
                _registry_version = -1
        return _registry


def reset_registry() -> None:
    """Drop the cached singleton (testing / config-reload helper)."""
    global _registry, _registry_version
    with _registry_lock:
        _registry = None
        _registry_version = -1
