"""Single provider construction and validation path.

Runtime registry construction and Settings -> Test Connection both use this
module, preventing the catalog and test/runtime implementations from drifting.
"""

from __future__ import annotations

from typing import Any

from .catalog import get_catalog_entry
from .config_types import ProviderConfig
from .providers.anthropic import AnthropicProvider
from .providers.base import LlmProvider, ProviderUnavailableError
from .providers.custom_openai_compatible import CustomOpenAiCompatibleProvider, _validate_base_url
from .providers.gemini import GeminiProvider
from .providers.grok import GrokProvider
from .providers.ollama import OllamaProvider
from .providers.openai import OpenAiProvider
from .providers.sarvam import SarvamProvider
from .providers.vllm import VllmProvider


def validate_provider_config(config: ProviderConfig) -> None:
    """Validate one provider config against the public catalog contract."""
    entry = get_catalog_entry(config.name)
    if entry is None:
        raise ProviderUnavailableError(f"unknown provider: {config.name!r}")
    if entry.requires_api_key and not config.api_key:
        raise ProviderUnavailableError(f"{config.name}: api_key is required")
    if entry.requires_base_url and not config.base_url:
        raise ProviderUnavailableError(f"{config.name}: base_url is required")
    if not config.default_model:
        raise ProviderUnavailableError(f"{config.name}: default_model is required")
    if config.max_concurrent <= 0:
        raise ProviderUnavailableError(f"{config.name}: max_concurrent must be greater than zero")
    if config.rate_per_minute <= 0:
        raise ProviderUnavailableError(f"{config.name}: rate_per_minute must be greater than zero")
    if config.cost_per_1k_input_usd < 0 or config.cost_per_1k_output_usd < 0:
        raise ProviderUnavailableError(f"{config.name}: cost fields cannot be negative")
    if config.name == "custom_openai":
        _validate_base_url(config.base_url)


def build_provider(config: ProviderConfig, *, client_factory: Any | None = None) -> LlmProvider:
    """Build any catalog provider from the same resolved value object."""
    validate_provider_config(config)
    common = {
        "default_model": config.default_model,
        "max_concurrent": config.max_concurrent,
        "rate_per_minute": config.rate_per_minute,
    }
    if client_factory is not None:
        common["client_factory"] = client_factory

    if config.name == "anthropic":
        return AnthropicProvider(api_key=config.api_key, **common)
    if config.name == "openai":
        return OpenAiProvider(
            api_key=config.api_key,
            base_url=config.base_url or "https://api.openai.com/v1",
            organization=config.organization or None,
            **common,
        )
    if config.name == "gemini":
        return GeminiProvider(
            api_key=config.api_key,
            tier="free" if config.tier == "free" else "paid",
            **common,
        )
    if config.name == "grok":
        return GrokProvider(
            api_key=config.api_key,
            tier="free" if config.tier == "free" else "paid",
            **common,
        )
    if config.name == "sarvam":
        return SarvamProvider(
            api_key=config.api_key,
            base_url=config.base_url or "https://api.sarvam.ai/v1",
            **common,
        )
    if config.name == "ollama":
        return OllamaProvider(base_url=config.base_url or "http://localhost:11434", **common)
    if config.name == "vllm":
        return VllmProvider(
            base_url=config.base_url,
            api_key=config.api_key or "EMPTY",
            **common,
        )
    if config.name == "custom_openai":
        return CustomOpenAiCompatibleProvider(
            base_url=config.base_url,
            api_key=config.api_key or "EMPTY",
            cost_per_1k_input_usd=config.cost_per_1k_input_usd,
            cost_per_1k_output_usd=config.cost_per_1k_output_usd,
            is_local=config.is_local,
            **common,
        )
    raise ProviderUnavailableError(f"no factory for provider: {config.name!r}")


__all__ = ["build_provider", "validate_provider_config"]
