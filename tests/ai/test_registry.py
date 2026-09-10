"""ProviderRegistry tests — config loading, lazy instantiation, DB overrides."""

from __future__ import annotations

import pytest
from app.ai.providers.base import (
    AiProviderError,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ProviderInfo,
    ProviderUnavailableError,
    UpstreamFailure,
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


class _OutcomeProvider(_FakeProvider):
    def __init__(self, name: str, *, failure_kind: str | None = None) -> None:
        self.name = name
        self.default_model = f"{name}-model"
        self.failure_kind = failure_kind
        self.calls = 0

    async def generate(self, req: LlmRequest) -> LlmResponse:
        self.calls += 1
        if self.failure_kind:
            raise AiProviderError(
                f"{self.name} failed",
                failure=UpstreamFailure(kind=self.failure_kind, provider_name=self.name),
            )
        return LlmResponse(
            text=f"{self.name}-ok",
            parsed=None,
            usage=LlmUsage(input_tokens=1, output_tokens=1, cost_usd=0.0),
            provider=self.name,
            model=self.default_model,
            latency_ms=1,
        )


def _request() -> LlmRequest:
    return LlmRequest(system="system", user="user", request_id="req-1")


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


def test_registry_selects_exact_default_and_fallback_credentials():
    reg = ProviderRegistry(
        configs=[
            ProviderConfig(
                name="openai",
                enabled=True,
                default_model="primary-model",
                api_key="primary-key",
                credential_id=41,
                label="primary",
                is_default=True,
            ),
            ProviderConfig(
                name="openai",
                enabled=True,
                default_model="fallback-model",
                api_key="fallback-key",
                credential_id=42,
                label="fallback",
                is_fallback=True,
            ),
        ],
        default_provider="openai",
    )

    assert reg.get_default_config().credential_id == 41
    assert reg.get_fallback_config() is not None
    assert reg.get_fallback_config().credential_id == 42
    assert reg.get_default().default_model == "primary-model"
    fallback = reg.get_fallback()
    assert fallback is not None
    assert fallback.default_model == "fallback-model"


@pytest.mark.asyncio
async def test_registry_uses_one_controlled_fallback_for_transient_failure():
    configs = [
        ProviderConfig(
            name="openai", enabled=True, default_model="primary", api_key="x", credential_id=41, is_default=True
        ),
        ProviderConfig(
            name="anthropic",
            enabled=True,
            default_model="fallback",
            api_key="y",
            credential_id=42,
            is_fallback=True,
        ),
    ]
    reg = ProviderRegistry(configs=configs, default_provider="openai")
    primary = _OutcomeProvider("openai", failure_kind="provider_down")
    fallback = _OutcomeProvider("anthropic")
    reg.register_instance(primary, selector="credential:41")
    reg.register_instance(fallback, selector="credential:42")

    routed = await reg.generate_with_fallback(_request())

    assert routed.fallback_used is True
    assert routed.response.text == "anthropic-ok"
    assert primary.calls == 1
    assert fallback.calls == 1


@pytest.mark.asyncio
async def test_registry_does_not_fallback_for_deterministic_failure():
    configs = [
        ProviderConfig(
            name="openai", enabled=True, default_model="primary", api_key="x", credential_id=41, is_default=True
        ),
        ProviderConfig(
            name="anthropic",
            enabled=True,
            default_model="fallback",
            api_key="y",
            credential_id=42,
            is_fallback=True,
        ),
    ]
    reg = ProviderRegistry(configs=configs, default_provider="openai")
    primary = _OutcomeProvider("openai", failure_kind="auth_failed")
    fallback = _OutcomeProvider("anthropic")
    reg.register_instance(primary, selector="credential:41")
    reg.register_instance(fallback, selector="credential:42")

    with pytest.raises(AiProviderError):
        await reg.generate_with_fallback(_request())

    assert primary.calls == 1
    assert fallback.calls == 0


@pytest.mark.asyncio
async def test_registry_never_loops_when_fallback_fails():
    configs = [
        ProviderConfig(
            name="openai", enabled=True, default_model="primary", api_key="x", credential_id=41, is_default=True
        ),
        ProviderConfig(
            name="anthropic",
            enabled=True,
            default_model="fallback",
            api_key="y",
            credential_id=42,
            is_fallback=True,
        ),
    ]
    reg = ProviderRegistry(configs=configs, default_provider="openai")
    primary = _OutcomeProvider("openai", failure_kind="provider_down")
    fallback = _OutcomeProvider("anthropic", failure_kind="provider_down")
    reg.register_instance(primary, selector="credential:41")
    reg.register_instance(fallback, selector="credential:42")

    with pytest.raises(AiProviderError):
        await reg.generate_with_fallback(_request())

    assert primary.calls == 1
    assert fallback.calls == 1
