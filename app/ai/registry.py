"""Provider registry — single read-side entrypoint for the orchestrator.

The registry is the only thing the rest of the app interacts with. It:

  * Reads provider configuration from :class:`~app.settings.Settings`
    (env-driven defaults) and merges per-provider overrides from the
    ``ai_provider_config`` table (loaded lazily on first use).
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

from sqlalchemy import select
from sqlalchemy.orm import Session

from .providers.anthropic import AnthropicProvider
from .providers.base import (
    LlmProvider,
    ProviderInfo,
    ProviderUnavailableError,
)
from .providers.custom_openai_compatible import CustomOpenAiCompatibleProvider
from .providers.gemini import GeminiProvider
from .providers.grok import GrokProvider
from .providers.ollama import OllamaProvider
from .providers.openai import OpenAiProvider
from .providers.vllm import VllmProvider

log = logging.getLogger("sbom.ai.registry")


@dataclass(frozen=True)
class ProviderConfig:
    """Resolved configuration for a single provider.

    Built by :func:`build_configs_from_settings` (env) and optionally
    patched from ``ai_provider_config`` (DB) by the registry.
    """

    name: str
    enabled: bool
    default_model: str
    api_key: str = ""
    base_url: str = ""
    organization: str = ""
    max_concurrent: int = 10
    rate_per_minute: float = 60.0

    # Phase 1 additions for free-tier-aware providers + custom endpoints.
    # ``tier`` is meaningful for Gemini / Grok ("free" or "paid"); ignored
    # by other providers. The cost overrides + ``is_local`` are only used
    # by ``custom_openai`` and default to zero / true (assume self-hosted).
    tier: str = "paid"
    cost_per_1k_input_usd: float = 0.0
    cost_per_1k_output_usd: float = 0.0
    is_local: bool = False


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
        self._configs = {c.name: c for c in configs}
        self._default = default_provider
        self._instances: dict[str, LlmProvider] = {}
        self._lock = threading.Lock()

    @property
    def default_name(self) -> str:
        return self._default

    def list_available(self) -> list[ProviderInfo]:
        """Public metadata (Settings page consumes this).

        Disabled providers are reported with ``available=False`` so the UI
        can grey them out instead of hiding them.
        """
        out: list[ProviderInfo] = []
        for cfg in self._configs.values():
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
                out.append(self.get(cfg.name).info())
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
        cfg = self._configs.get(name)
        if cfg is None:
            raise ProviderUnavailableError(f"unknown provider: {name!r}")
        if not cfg.enabled:
            raise ProviderUnavailableError(f"provider {name!r} is not enabled (no credentials configured)")

        with self._lock:
            if name in self._instances:
                return self._instances[name]
            instance = self._build_provider(cfg)
            self._instances[name] = instance
            return instance

    def get_default(self) -> LlmProvider:
        return self.get(self._default)

    @staticmethod
    def _build_provider(cfg: ProviderConfig) -> LlmProvider:
        if cfg.name == "anthropic":
            return AnthropicProvider(
                api_key=cfg.api_key,
                default_model=cfg.default_model,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "openai":
            return OpenAiProvider(
                api_key=cfg.api_key,
                default_model=cfg.default_model,
                base_url=cfg.base_url or "https://api.openai.com/v1",
                organization=cfg.organization or None,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "ollama":
            return OllamaProvider(
                base_url=cfg.base_url or "http://localhost:11434",
                default_model=cfg.default_model,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "vllm":
            return VllmProvider(
                base_url=cfg.base_url,
                api_key=cfg.api_key or "EMPTY",
                default_model=cfg.default_model,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "gemini":
            return GeminiProvider(
                api_key=cfg.api_key,
                default_model=cfg.default_model,
                tier="free" if cfg.tier == "free" else "paid",
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "grok":
            return GrokProvider(
                api_key=cfg.api_key,
                default_model=cfg.default_model,
                tier="free" if cfg.tier == "free" else "paid",
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
            )
        if cfg.name == "custom_openai":
            return CustomOpenAiCompatibleProvider(
                base_url=cfg.base_url,
                api_key=cfg.api_key or "EMPTY",
                default_model=cfg.default_model,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
                cost_per_1k_input_usd=cfg.cost_per_1k_input_usd,
                cost_per_1k_output_usd=cfg.cost_per_1k_output_usd,
                is_local=cfg.is_local,
            )
        raise ProviderUnavailableError(f"no factory for provider: {cfg.name!r}")

    # ------------------------------------------------------------------
    # Test / admin helpers
    # ------------------------------------------------------------------

    def register_instance(self, instance: LlmProvider) -> None:
        """Inject a pre-built provider (used by tests)."""
        with self._lock:
            self._instances[instance.name] = instance
            self._configs.setdefault(
                instance.name,
                ProviderConfig(
                    name=instance.name,
                    enabled=True,
                    default_model=getattr(instance, "default_model", ""),
                ),
            )

    def reset(self) -> None:
        with self._lock:
            self._instances.clear()


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


def apply_db_overrides(
    configs: list[ProviderConfig],
    db: Session,
) -> list[ProviderConfig]:
    """Patch ``configs`` with values from ``ai_provider_config`` rows.

    Rows in the DB win over env values. This is the seam that lets a
    workspace admin toggle providers / change models from the Settings
    page without a redeploy.

    Errors are swallowed — the env config remains the safe fallback.
    """
    try:
        from ..models import AiProviderConfig
    except Exception:
        return configs

    try:
        rows = db.execute(select(AiProviderConfig)).scalars().all()
    except Exception as exc:
        log.debug("ai.registry.db_overrides_unavailable: %s", exc)
        return configs

    by_name = {c.name: c for c in configs}
    for r in rows:
        existing = by_name.get(r.provider_name)
        if existing is None:
            continue
        # Only fields that have non-empty DB values override the env.
        patched = ProviderConfig(
            name=existing.name,
            enabled=bool(r.enabled if r.enabled is not None else existing.enabled),
            default_model=(r.default_model or existing.default_model),
            api_key=existing.api_key,  # never override key from DB — secrets stay in env / vault
            base_url=(r.base_url or existing.base_url),
            organization=existing.organization,
            max_concurrent=int(r.max_concurrent or existing.max_concurrent),
            rate_per_minute=float(r.rate_per_minute or existing.rate_per_minute),
        )
        by_name[existing.name] = patched
    return list(by_name.values())


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


_registry_lock = threading.Lock()
_registry: ProviderRegistry | None = None


def _resolve_default_provider_name(configs: list[ProviderConfig]) -> str:
    """Pick the default provider name.

    Priority:
      1. The first ``ProviderConfig`` carrying a DB-marked default flag
         — we encode this by setting ``organization='__default__'`` on
         the row coming out of the loader (see ``config_loader._row_to_config``).
         Phase 2 §2.5: only one DB row may carry ``is_default=True`` at
         a time.
      2. Otherwise fall back to the env-driven ``AI_DEFAULT_PROVIDER``.
    """
    for cfg in configs:
        if cfg.organization == "__default__":
            return cfg.name
    from ..settings import get_settings

    return get_settings().ai_default_provider


def get_registry(db: Session | None = None) -> ProviderRegistry:
    """Return the process-wide registry, building it on first call.

    Resolves provider configs via the Phase 2 :class:`AiConfigLoader`
    (DB-first, env fallback). ``db`` is accepted for backward compat
    but no longer used directly — the loader owns the session.
    """
    global _registry
    with _registry_lock:
        if _registry is None:
            try:
                from .config_loader import get_loader

                configs = get_loader().resolve_configs()
            except Exception as exc:  # noqa: BLE001
                # Fall back to env-only when the loader can't construct
                # (e.g. in early-boot test scenarios with no DB).
                log.warning("ai.registry.loader_unavailable: %s — env fallback", exc)
                configs = build_configs_from_settings()
            default = _resolve_default_provider_name(configs)
            _registry = ProviderRegistry(configs, default_provider=default)
        return _registry


def reset_registry() -> None:
    """Drop the cached singleton (testing / config-reload helper)."""
    global _registry
    with _registry_lock:
        _registry = None
