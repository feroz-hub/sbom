"""Canonical, source-aware AI configuration value objects.

These types deliberately separate provider HTTP configuration from routing
metadata.  In particular, ``organization`` is only the real OpenAI
organization value; default/fallback selection never overloads it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EffectiveAiConfig:
    """Effective runtime controls shared by every AI consumer.

    A database row is authoritative when present.  Environment values are a
    migration/startup fallback only when that row does not exist or the
    database itself is unavailable.
    """

    feature_enabled: bool
    kill_switch_active: bool
    budget_per_request_usd: float
    budget_per_scan_usd: float
    budget_daily_usd: float
    source: str  # ``db`` | ``env``


@dataclass(frozen=True)
class ProviderConfig:
    """Resolved configuration for one exact provider credential."""

    name: str
    enabled: bool
    default_model: str
    api_key: str = ""
    base_url: str = ""
    organization: str = ""
    max_concurrent: int = 10
    rate_per_minute: float = 60.0
    tier: str = "paid"
    cost_per_1k_input_usd: float = 0.0
    cost_per_1k_output_usd: float = 0.0
    is_local: bool = False

    # Routing/diagnostic metadata.  These fields never enter provider HTTP
    # headers or payloads.
    credential_id: int | None = None
    label: str = "default"
    is_default: bool = False
    is_fallback: bool = False
    source: str = "env"  # ``db`` | ``env``
    config_error: str | None = None

    @property
    def selection_key(self) -> str:
        if self.credential_id is not None:
            return f"credential:{self.credential_id}"
        return f"env:{self.name}"


__all__ = ["EffectiveAiConfig", "ProviderConfig"]
