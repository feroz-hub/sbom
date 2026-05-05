"""Static catalog of supported AI providers and their model lists.

Phase 1 §1.4 deliverable. This is the metadata the Settings UI uses to
populate the "Add provider" dropdown — provider name, display label,
which fields the form must collect, the free-tier rate limits, the
"where do I get an API key" link, and the per-provider model list.

Why a static catalog separate from the runtime registry:

  * The runtime registry (``app/ai/registry.py``) reflects what's
    *configured* — providers with credentials wired up. This catalog
    reflects what's *available* — every provider the platform can
    talk to, regardless of current configuration.
  * The two have different lifecycles. New runtime credentials are
    common; new provider classes are rare.
  * Storing curated rate-limit and model metadata as code (not config)
    means PR review catches breaking changes — a Gemini free-tier
    bump from 15 to 30 RPM is a code edit, code review, deploy.

Sources (last verified 2026-05-04 — re-check each quarter):
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
    """One model exposed by a provider.

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
        ModelInfo(name="claude-opus-4-7", display_name="Claude Opus 4.7", default_tier="paid"),
        ModelInfo(name="claude-sonnet-4-6", display_name="Claude Sonnet 4.6", default_tier="paid"),
        ModelInfo(name="claude-sonnet-4-5", display_name="Claude Sonnet 4.5", default_tier="paid"),
        ModelInfo(name="claude-haiku-4-5", display_name="Claude Haiku 4.5", default_tier="paid", notes="Cheapest in family"),
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
        ModelInfo(name="gpt-4o", display_name="GPT-4o", default_tier="paid"),
        ModelInfo(name="gpt-4o-mini", display_name="GPT-4o mini", default_tier="paid", notes="Cheapest paid OpenAI tier"),
        ModelInfo(name="gpt-4.1", display_name="GPT-4.1", default_tier="paid"),
        ModelInfo(name="gpt-4.1-mini", display_name="GPT-4.1 mini", default_tier="paid"),
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
            name="gemini-2.5-flash",
            display_name="Gemini 2.5 Flash",
            default_tier="free",
            notes="Free tier: 15 req/min, 1M tokens/day, 1500 req/day",
        ),
        ModelInfo(
            name="gemini-2.5-flash-lite",
            display_name="Gemini 2.5 Flash Lite",
            default_tier="paid",
            notes="Cheapest paid Gemini tier",
        ),
        ModelInfo(
            name="gemini-2.5-pro",
            display_name="Gemini 2.5 Pro",
            default_tier="paid",
            notes="Free tier: 5 req/min — too tight for batch use",
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
            display_name="Grok 2 Mini",
            default_tier="free",
            notes="Free tier: ~1 req/sec, ~25k tokens/day. Tight for batch.",
        ),
        ModelInfo(name="grok-2", display_name="Grok 2", default_tier="paid"),
        ModelInfo(name="grok-3", display_name="Grok 3", default_tier="paid"),
    ],
    docs_url="https://docs.x.ai/docs",
    api_key_url="https://console.x.ai/",
    notes="Free tier exists but daily token cap is tight — better for one-off CVE clicks than batch.",
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
        ModelInfo(name="llama3.3:70b", display_name="Llama 3.3 70B", default_tier="free"),
        ModelInfo(name="llama3.1:70b", display_name="Llama 3.1 70B", default_tier="free"),
        ModelInfo(name="qwen2.5:72b", display_name="Qwen 2.5 72B", default_tier="free"),
        ModelInfo(name="qwen2.5:32b", display_name="Qwen 2.5 32B", default_tier="free", notes="Smaller — fits more GPUs"),
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
    "VLLM",
    "get_catalog_entry",
    "list_catalog",
]
