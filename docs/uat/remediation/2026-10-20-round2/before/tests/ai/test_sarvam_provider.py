"""Sarvam AI provider wiring — provider class, catalog, registry factory."""

from __future__ import annotations

import pytest
from app.ai.catalog import get_catalog_entry
from app.ai.providers.base import ProviderUnavailableError
from app.ai.providers.sarvam import SarvamProvider
from app.ai.registry import (
    ProviderConfig,
    ProviderRegistry,
    build_configs_from_settings,
)


def test_sarvam_provider_basics():
    p = SarvamProvider(api_key="test-key")
    assert p.name == "sarvam"
    assert p.default_model == "sarvam-m"
    assert p.is_local is False
    # OpenAI-compatible subclass → reports as sarvam in its public metadata.
    info = p.info()
    assert info.name == "sarvam"
    assert info.default_model == "sarvam-m"


def test_sarvam_requires_api_key():
    with pytest.raises(ProviderUnavailableError):
        SarvamProvider(api_key="")


def test_sarvam_in_catalog():
    entry = get_catalog_entry("sarvam")
    assert entry is not None
    assert entry.requires_api_key is True
    assert entry.requires_base_url is False
    assert any(m.name == "sarvam-m" for m in entry.available_models)


def test_registry_factory_builds_sarvam():
    cfg = ProviderConfig(
        name="sarvam",
        enabled=True,
        default_model="sarvam-m",
        api_key="k",
        base_url="https://api.sarvam.ai/v1",
    )
    reg = ProviderRegistry([cfg], default_provider="sarvam")
    prov = reg.get("sarvam")
    assert isinstance(prov, SarvamProvider)
    assert prov.name == "sarvam"


def test_build_configs_includes_sarvam():
    # The default ai_providers list now declares sarvam, so it must appear
    # (enabled only when SARVAM_API_KEY is set — env-dependent, not asserted).
    configs = build_configs_from_settings()
    assert any(c.name == "sarvam" for c in configs)
