"""Static catalog of provider configuration fields and bootstrap models.

Phase 1 §1.4 deliverable. This is the metadata the Settings UI uses to
populate the "Add provider" dropdown — provider name, display label,
which fields the form must collect, the free-tier rate limits, the
"where do I get an API key" link, and a pre-save bootstrap model.

Why a static catalog separate from the runtime registry:

  * The runtime registry (``app/ai/registry.py``) reflects what's
    *configured* — providers with credentials wired up. This catalog
    reflects what's *available* — every provider the platform can
    talk to, regardless of current configuration.
  * The two have different lifecycles. New runtime credentials are
    common; new provider classes are rare.
  * ``available_models`` is retained for the unsaved Add Provider form only.
    Once saved, the provider adapter and ``ai_provider_model`` registry are
    the model source of truth.

Sources (last verified 2026-09-06 — re-check each quarter):
  * Anthropic    https://docs.anthropic.com/en/docs/about-claude/models
  * OpenAI       https://platform.openai.com/docs/models
  * Gemini       https://ai.google.dev/pricing  ·  https://ai.google.dev/gemini-api/docs/rate-limits
  * Grok (xAI)   https://docs.x.ai/docs/models  ·  https://docs.x.ai/docs/usage-tiers-and-rate-limits
  * Ollama       (local — no upstream limits)
  * vLLM         (self-hosted — no upstream limits)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ModelTier = Literal["free", "paid"]


class ModelInfo(BaseModel):
    """One bootstrap model used only before live discovery is possible.

    ``default_tier`` is the *expected* tier for this model. Free-tier
    models on cloud providers (Gemini Flash, Grok 2 Mini) carry rate
    limits the orchestrator honors via the per-provider rate limiter.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="API-side model identifier (e.g. claude-sonnet-4-5)")
    display_name: str = Field(..., description="Human-friendly label for dropdowns")
    default_tier: ModelTier = "paid"
    notes: str = ""


class ProviderCatalogEntry(BaseModel):
    """Catalog metadata for one provider.

    Returned by ``GET /api/v1/ai/providers/available``. The Settings UI
    reads this to drive form rendering — which fields appear, what
    validation to apply, what tier badges to show.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    display_name: str

    requires_api_key: bool
    requires_base_url: bool
    is_local: bool = False

    supports_free_tier: bool = False
    free_tier_rate_limit_rpm: int | None = None
    free_tier_daily_token_limit: int | None = None

    available_models: list[ModelInfo] = Field(default_factory=list)

    docs_url: str = ""
    api_key_url: str = ""

    notes: str = ""


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

ANTHROPIC = ProviderCatalogEntry(
    name="anthropic",
    display_name="Anthropic Claude",
    requires_api_key=True,
    requires_base_url=False,
    available_models=[
        ModelInfo(
            name="claude-sonnet-4-5",
            display_name="Claude Sonnet 4.5 (bootstrap)",
            default_tier="paid",
            notes="Temporary pre-save value; refresh after saving credentials",
        ),
    ],
    docs_url="https://docs.anthropic.com/en/api/messages",
    api_key_url="https://console.anthropic.com/settings/keys",
    notes="Production-grade reasoning. Recommended default for fix generation.",
)


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

OPENAI = ProviderCatalogEntry(
    name="openai",
    display_name="OpenAI",
    requires_api_key=True,
    requires_base_url=False,
    available_models=[
        ModelInfo(
            name="gpt-4o-mini",
            display_name="GPT-4o mini (bootstrap)",
            default_tier="paid",
            notes="Temporary pre-save value; refresh after saving credentials",
        ),
    ],
    docs_url="https://platform.openai.com/docs/api-reference/chat",
    api_key_url="https://platform.openai.com/api-keys",
    notes="Wide model family; gpt-4o-mini is the cost/quality sweet spot.",
)


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------

GEMINI = ProviderCatalogEntry(
    name="gemini",
    display_name="Google Gemini",
    requires_api_key=True,
    requires_base_url=False,
    supports_free_tier=True,
    free_tier_rate_limit_rpm=15,
    free_tier_daily_token_limit=1_000_000,
    available_models=[
        ModelInfo(
            name="gemini-3.6-flash",
            display_name="Gemini 3.6 Flash (bootstrap)",
            default_tier="free",
            notes="Temporary pre-save value; refresh after saving credentials",
        ),
    ],
    docs_url="https://ai.google.dev/gemini-api/docs",
    api_key_url="https://aistudio.google.com/app/apikey",
    notes="Genuine free tier. Best for evaluation and small workloads.",
)


# ---------------------------------------------------------------------------
# xAI Grok
# ---------------------------------------------------------------------------

GROK = ProviderCatalogEntry(
    name="grok",
    display_name="xAI Grok",
    requires_api_key=True,
    requires_base_url=False,
    supports_free_tier=True,
    free_tier_rate_limit_rpm=60,
    free_tier_daily_token_limit=25_000,
    available_models=[
        ModelInfo(
            name="grok-2-mini",
            display_name="Grok 2 Mini (bootstrap)",
            default_tier="free",
            notes="Temporary pre-save value; refresh after saving credentials",
        ),
    ],
    docs_url="https://docs.x.ai/docs",
    api_key_url="https://console.x.ai/",
    notes="Free tier exists but daily token cap is tight — better for one-off CVE clicks than batch.",
)


# ---------------------------------------------------------------------------
# Sarvam AI (OpenAI-compatible)
# ---------------------------------------------------------------------------

SARVAM = ProviderCatalogEntry(
    name="sarvam",
    display_name="Sarvam AI",
    requires_api_key=True,
    requires_base_url=False,
    supports_free_tier=False,
    available_models=[
        ModelInfo(name="sarvam-m", display_name="Sarvam-M", default_tier="paid"),
    ],
    docs_url="https://docs.sarvam.ai/",
    api_key_url="https://dashboard.sarvam.ai/",
    notes="OpenAI-compatible chat completions (base https://api.sarvam.ai/v1). Confirm the model id and pricing for your account.",
)


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

OLLAMA = ProviderCatalogEntry(
    name="ollama",
    display_name="Ollama (local)",
    requires_api_key=False,
    requires_base_url=True,
    is_local=True,
    supports_free_tier=False,
    available_models=[
        ModelInfo(
            name="llama3.3:70b",
            display_name="Llama 3.3 70B (bootstrap)",
            default_tier="free",
            notes="Temporary pre-save value; refresh to list locally installed models",
        ),
    ],
    docs_url="https://github.com/ollama/ollama/blob/main/docs/api.md",
    api_key_url="",
    notes="Self-hosted; no per-token cost. Default URL: http://localhost:11434",
)


# ---------------------------------------------------------------------------
# vLLM
# ---------------------------------------------------------------------------

VLLM = ProviderCatalogEntry(
    name="vllm",
    display_name="vLLM (self-hosted)",
    requires_api_key=False,
    requires_base_url=True,
    is_local=True,
    available_models=[
        ModelInfo(
            name="meta-llama/Meta-Llama-3.1-70B-Instruct",
            display_name="Llama 3.1 70B Instruct",
            default_tier="free",
        ),
    ],
    docs_url="https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html",
    notes="OpenAI-compatible server. Configure base URL to point at your deployment.",
)


# ---------------------------------------------------------------------------
# Custom OpenAI-compatible — the escape hatch
# ---------------------------------------------------------------------------

CUSTOM = ProviderCatalogEntry(
    name="custom_openai",
    display_name="Custom OpenAI-compatible",
    requires_api_key=False,  # most local setups; user can add one if their proxy needs it
    requires_base_url=True,
    is_local=False,  # could be remote; treated as cloud by default for cost reporting
    available_models=[],  # free-text in the UI
    docs_url="https://platform.openai.com/docs/api-reference/chat",
    notes=(
        "For LM Studio, LocalAI, LiteLLM proxies, or any OpenAI-compatible "
        "endpoint not listed above. Cost defaults to $0; configure rates "
        "explicitly if you want to track local-compute equivalents."
    ),
)


# ---------------------------------------------------------------------------
# Public catalog
# ---------------------------------------------------------------------------


PROVIDER_CATALOG: tuple[ProviderCatalogEntry, ...] = (
    ANTHROPIC,
    OPENAI,
    GEMINI,
    GROK,
    SARVAM,
    OLLAMA,
    VLLM,
    CUSTOM,
)


def list_catalog() -> list[ProviderCatalogEntry]:
    """Return the catalog as a list (for API responses)."""
    return list(PROVIDER_CATALOG)


def get_catalog_entry(name: str) -> ProviderCatalogEntry | None:
    """Lookup by provider ``name``. Returns ``None`` for unknown names."""
    key = (name or "").strip().lower()
    for entry in PROVIDER_CATALOG:
        if entry.name == key:
            return entry
    return None


__all__ = [
    "ANTHROPIC",
    "CUSTOM",
    "GEMINI",
    "GROK",
    "ModelInfo",
    "ModelTier",
    "OLLAMA",
    "OPENAI",
    "PROVIDER_CATALOG",
    "ProviderCatalogEntry",
    "SARVAM",
    "VLLM",
    "get_catalog_entry",
    "list_catalog",
]
