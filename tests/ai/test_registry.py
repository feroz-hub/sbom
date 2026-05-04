"""ProviderRegistry tests — config loading, lazy instantiation, DB overrides."""

from __future__ import annotations

import pytest
from app.ai.providers.base import (
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ProviderInfo,
    ProviderUnavailableError,
)
from app.ai.registry import ProviderConfig, ProviderRegistry


class _FakeProvider:
    """Hand-rolled stand-in — :class:`LlmProvider` is a Protocol, so any
    object with the right methods satisfies it. Lets us avoid hitting the
    network in registry tests."""

    name = "fake"
    default_model = "fake-1"
    is_local = True
    max_concurrent = 1

    async def generate(self, req: LlmRequest) -> LlmResponse:
        return LlmResponse(
            text="x",
            parsed=None,
            usage=LlmUsage(input_tokens=0, output_tokens=0, cost_usd=0.0),
            provider="fake",
            model="fake-1",
            latency_ms=0,
        )

    async def health_check(self) -> bool:
        return True

    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="fake",
            available=True,
            default_model="fake-1",
            supports_structured_output=False,
            is_local=True,
        )


def _registry_with_one(name: str = "anthropic", *, enabled: bool = True, api_key: str = "k") -> ProviderRegistry:
    return ProviderRegistry(
        configs=[
            ProviderConfig(
                name=name,
                enabled=enabled,
                default_model=f"{name}-default",
                api_key=api_key,
                base_url="",
                max_concurrent=2,
                rate_per_minute=10.0,
            )
        ],
        default_provider=name,
    )


def test_registry_get_unknown_raises():
    reg = _registry_with_one()
    with pytest.raises(ProviderUnavailableError):
        reg.get("does-not-exist")


def test_registry_get_disabled_raises():
    reg = _registry_with_one(enabled=False)
    with pytest.raises(ProviderUnavailableError):
        reg.get("anthropic")


def test_registry_default_resolves():
    reg = _registry_with_one()
    inst = reg.get_default()
    assert inst.name == "anthropic"
    # Cached on second call — same object.
    assert reg.get_default() is inst


def test_registry_lazy_instantiation_per_provider():
    # Build a registry that declares Anthropic + OpenAI but only one has
    # credentials. Asking for the missing one raises; asking for the
    # configured one succeeds — without instantiating the missing one.
    reg = ProviderRegistry(
        configs=[
            ProviderConfig(name="anthropic", enabled=True, default_model="a", api_key="k"),
            ProviderConfig(name="openai", enabled=False, default_model="o", api_key=""),
        ],
        default_provider="anthropic",
    )
    reg.get("anthropic")
    with pytest.raises(ProviderUnavailableError):
        reg.get("openai")


def test_registry_register_instance_overrides_factory():
    reg = ProviderRegistry(configs=[], default_provider="fake")
    fake = _FakeProvider()
    reg.register_instance(fake)
    assert reg.get("fake") is fake


def test_registry_list_available_includes_disabled():
    reg = ProviderRegistry(
        configs=[
            ProviderConfig(name="anthropic", enabled=True, default_model="a", api_key="k"),
            ProviderConfig(name="openai", enabled=False, default_model="o", api_key=""),
        ],
        default_provider="anthropic",
    )
    infos = {info.name: info for info in reg.list_available()}
    assert infos["anthropic"].available is True
    assert infos["openai"].available is False
    assert "no credentials" in (infos["openai"].notes or "").lower()


def test_registry_unknown_provider_factory_raises():
    reg = ProviderRegistry(
        configs=[ProviderConfig(name="bogus", enabled=True, default_model="x", api_key="k")],
        default_provider="bogus",
    )
    with pytest.raises(ProviderUnavailableError):
        reg.get("bogus")
