"""LLM provider protocol and shared request / response / usage types.

This module is the contract every concrete provider implements. The fix
generator orchestrator (Phase 2) and the batch worker (Phase 3) talk to
:class:`LlmProvider` only — never to a concrete subclass, never to a
provider SDK.

Adding a new provider therefore reduces to:
  1. Add a class in this package implementing :class:`LlmProvider`.
  2. Register it in :class:`~app.ai.registry.ProviderRegistry`.
  3. Update env / DB config.

No callers outside this package change.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Request / response value objects
# ---------------------------------------------------------------------------


class LlmRequest(BaseModel):
    """A single LLM call.

    The orchestrator builds one of these per cache miss. ``response_schema``
    is optional in Phase 1 (concrete schemas land in Phase 2); when present,
    the provider uses its native structured-output mechanism (Anthropic tool
    use, OpenAI JSON schema, Ollama format=json) and parses the response.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    system: str = Field(..., description="System prompt — task framing, schema instructions")
    user: str = Field(..., description="User prompt — grounded context as JSON or prose")

    # Stored as a dict so this object stays JSON-serialisable for logging /
    # tracing. Phase 2 builds it from the Pydantic schemas via
    # ``model_json_schema()``.
    response_schema: dict[str, Any] | None = Field(
        default=None,
        description="Optional JSON Schema for structured output. None → free-text.",
    )

    max_output_tokens: int = Field(default=1024, ge=1, le=8192)
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)
    request_id: str = Field(..., description="Trace id; written to ai_usage_log")
    purpose: str = Field(
        default="generic",
        description="Free-form tag (remediation_prose | upgrade_command | decision | health_check | …)",
    )

    # Optional override for the model name. None → provider's default model.
    model: str | None = None


class LlmUsage(BaseModel):
    """Token + cost accounting for a single completed call.

    ``cost_usd`` is provider-specific — each concrete provider plugs its own
    ``cost_per_1k_input`` / ``cost_per_1k_output`` table from
    :mod:`app.ai.cost`.
    """

    input_tokens: int = Field(..., ge=0)
    output_tokens: int = Field(..., ge=0)
    cost_usd: float = Field(..., ge=0.0)


class LlmResponse(BaseModel):
    """Result of a successful LLM call."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    text: str = Field(..., description="Raw text from the model. May be JSON-encoded.")
    parsed: dict[str, Any] | None = Field(
        default=None,
        description="Parsed JSON if ``response_schema`` was provided and parse succeeded.",
    )
    usage: LlmUsage
    provider: str
    model: str
    latency_ms: int = Field(..., ge=0)
    cache_hit: bool = Field(default=False, description="Set by the orchestrator on hit, never by the provider.")


class ProviderInfo(BaseModel):
    """Public-facing description used by the registry and Settings UI."""

    name: str
    available: bool
    default_model: str
    supports_structured_output: bool
    is_local: bool = Field(
        default=False,
        description="True for self-hosted (Ollama / vLLM); used for cost reporting.",
    )
    notes: str = ""


# ---------------------------------------------------------------------------
# Test-connection contract
# ---------------------------------------------------------------------------


from typing import Literal as _Literal

ConnectionErrorKind = _Literal[
    "network",
    "auth",
    "rate_limit",
    "model_not_found",
    "invalid_response",
    "unknown",
]


class ConnectionTestResult(BaseModel):
    """Outcome of a credential's "Test connection" probe.

    Designed for the Settings UI: one structured result that the
    frontend translates into a typed banner (green check / amber
    warning / red error). The ``error_kind`` enum is the discriminator
    — never parse ``error_message`` to decide UX.
    """

    success: bool
    latency_ms: int | None = Field(default=None, ge=0)
    detected_models: list[str] = Field(default_factory=list)
    error_message: str | None = None
    error_kind: ConnectionErrorKind | None = None
    provider: str = ""
    model_tested: str | None = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AiProviderError(RuntimeError):
    """Base class for every error raised by this package.

    Subclasses are caught by the orchestrator (Phase 2) and converted into
    structured failures rather than exceptions in user-facing surfaces.
    """


class ProviderUnavailableError(AiProviderError):
    """Provider is not configured or its remote endpoint is unreachable.

    Distinct from :class:`CircuitBreakerOpenError` — this means the provider
    has no usable credentials / endpoint at all.
    """


class CircuitBreakerOpenError(AiProviderError):
    """Provider is temporarily disabled by the circuit breaker.

    The breaker opens after N consecutive failures (configurable per
    provider) and half-opens after a cool-down. Callers should fall back to
    another provider or fail the request gracefully — never busy-loop.
    """


class BudgetExceededError(AiProviderError):
    """Per-request, per-scan, or per-day budget cap would be exceeded.

    Carries the cap level so the API layer can pick the right CTA
    ("increase per-scan budget" vs "wait until tomorrow").
    """

    def __init__(self, scope: str, cap_usd: float, would_be_usd: float) -> None:
        super().__init__(
            f"AI budget exceeded at scope={scope}: cap=${cap_usd:.4f}, "
            f"would-be=${would_be_usd:.4f}"
        )
        self.scope = scope
        self.cap_usd = cap_usd
        self.would_be_usd = would_be_usd


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


@runtime_checkable
class LlmProvider(Protocol):
    """Every concrete provider implements this Protocol.

    Why a Protocol and not an ABC:
      * Cheap to satisfy (any object with the right methods works in tests)
      * No inheritance chain leaking back into the orchestrator
      * Plays nicely with import-linter — concrete deps stay confined
    """

    name: str
    """Stable identifier ("anthropic", "openai", "ollama", "vllm")."""

    default_model: str
    """Provider's default model when ``LlmRequest.model`` is None."""

    is_local: bool
    """True for self-hosted (no per-token cost). Affects cost reporting."""

    max_concurrent: int
    """Max concurrent in-flight requests this provider tolerates."""

    async def generate(self, req: LlmRequest) -> LlmResponse:
        """Perform a single LLM call. Raises subclasses of AiProviderError on failure."""
        ...

    async def health_check(self) -> bool:
        """Cheap probe — used by the registry's "Test" button on the Settings page."""
        ...

    async def test_connection(self, *, model: str | None = None) -> ConnectionTestResult:
        """Run a structured connectivity probe.

        Returns a :class:`ConnectionTestResult` with a typed
        :attr:`ConnectionTestResult.error_kind` on failure so the UI can
        pick a specific message ("Invalid API key", "Couldn't reach
        provider", "Model not available"). Implementations SHOULD attempt
        a ``/models`` enumeration first when the provider supports it,
        falling back to a tiny chat completion otherwise.
        """
        ...

    def info(self) -> ProviderInfo:
        """Public metadata used by the registry / API."""
        ...
