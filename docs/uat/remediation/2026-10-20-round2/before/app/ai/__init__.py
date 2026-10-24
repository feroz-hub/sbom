"""AI-driven remediation subsystem.

Provider-agnostic LLM layer used by the AI fix generator. The orchestrator
talks to the protocol in :mod:`app.ai.providers.base`, never to a concrete
SDK or HTTP client. Concrete provider implementations live in
:mod:`app.ai.providers` and are the ONLY place provider-specific code may
appear.

Phase 1 surface (foundation):
  * :class:`LlmProvider` protocol + request/response/usage types
  * Concrete providers: Anthropic, OpenAI, Ollama, vLLM
  * Registry + runtime configuration
  * Cost ledger + per-request / per-scan / per-day budget caps
  * Per-provider rate-limiter and circuit breaker

Phase 2+ (schemas, orchestrator, batching, UI) builds on top of these
primitives.
"""

from .providers.base import (
    AiProviderError,
    BudgetExceededError,
    CircuitBreakerOpenError,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    ProviderInfo,
    ProviderUnavailableError,
)

__all__ = [
    "AiProviderError",
    "BudgetExceededError",
    "CircuitBreakerOpenError",
    "LlmProvider",
    "LlmRequest",
    "LlmResponse",
    "LlmUsage",
    "ProviderInfo",
    "ProviderUnavailableError",
]
