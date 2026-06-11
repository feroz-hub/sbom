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

import re
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
# Structured upstream-failure value object
# ---------------------------------------------------------------------------


UpstreamFailureKind = _Literal[
    "quota_exceeded",
    "rate_limited",
    "auth_failed",
    "model_not_found",
    "network_unreachable",
    "provider_down",
    "invalid_request",
    "unknown",
]


class UpstreamFailure(BaseModel):
    """Provider-side failure metadata captured at the HTTP boundary.

    Attached to :class:`AiProviderError` so the orchestrator can build a
    typed :class:`~app.ai.schemas.AiFixError` without parsing strings.

    ``upstream_body`` is truncated; the full body is logged to the
    structured ledger but never returned to the UI.
    """

    model_config = ConfigDict(extra="forbid")

    kind: UpstreamFailureKind
    provider_name: str
    upstream_status: int | None = None
    upstream_body: str | None = None
    upstream_message: str | None = None
    retry_after_seconds: int | None = None


# Pattern matches both Gemini's prose ("Please retry in 35.60207746s.") and
# the structured ``retryDelay: "35s"`` form Google embeds in the JSON body.
_RETRY_AFTER_BODY_RE = re.compile(
    r'(?:please\s+retry\s+in|retrydelay["\']?\s*[:=]?\s*["\']?)\s*([\d.]+)\s*s',
    re.IGNORECASE,
)


def _parse_retry_after_header(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return max(0, int(float(value.strip())))
    except (ValueError, TypeError):
        return None


def _parse_retry_after_body(body: str | None) -> int | None:
    if not body:
        return None
    m = _RETRY_AFTER_BODY_RE.search(body)
    if not m:
        return None
    try:
        return max(0, int(float(m.group(1))))
    except ValueError:
        return None


def _extract_upstream_message(body: str | None) -> str | None:
    """Pull a human-readable error message out of a JSON body when present."""
    if not body:
        return None
    snippet = body.strip()
    if not snippet.startswith("{") and not snippet.startswith("["):
        return snippet[:240] or None
    import json as _json

    try:
        data: Any = _json.loads(snippet)
    except (ValueError, TypeError):
        return snippet[:240] or None
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()[:240]
        msg = data.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()[:240]
    return snippet[:240] or None


def classify_http_failure(
    *,
    provider_name: str,
    status: int,
    body: str | None,
    retry_after_header: str | None = None,
) -> UpstreamFailure:
    """Map an HTTP error response to an :class:`UpstreamFailure`.

    The classification rules:
      * 429 with ``RESOURCE_EXHAUSTED`` / "quota" / "exceeded your" in the
        body → :data:`quota_exceeded` (daily / monthly project cap)
      * other 429 → :data:`rate_limited` (rolling RPS-style throttle)
      * 401 / 403 → :data:`auth_failed`
      * 404 mentioning ``model`` → :data:`model_not_found`
      * 5xx → :data:`provider_down`
      * other 4xx → :data:`invalid_request`
      * everything else → :data:`unknown`
    """
    body_lc = (body or "").lower()
    retry_after = _parse_retry_after_header(retry_after_header) or _parse_retry_after_body(body_lc)
    upstream_msg = _extract_upstream_message(body)

    kind: UpstreamFailureKind
    if status == 429:
        if (
            "resource_exhausted" in body_lc
            or "quota" in body_lc
            or "exceeded your" in body_lc
        ):
            kind = "quota_exceeded"
        else:
            kind = "rate_limited"
    elif status in (401, 403):
        kind = "auth_failed"
    elif status == 404 and "model" in body_lc:
        kind = "model_not_found"
    elif 500 <= status < 600:
        kind = "provider_down"
    elif 400 <= status < 500:
        kind = "invalid_request"
    else:
        kind = "unknown"

    return UpstreamFailure(
        kind=kind,
        provider_name=provider_name,
        upstream_status=status,
        upstream_body=(body or "")[:1000] or None,
        upstream_message=upstream_msg,
        retry_after_seconds=retry_after,
    )


def classify_network_failure(
    *,
    provider_name: str,
    exc: Exception,
) -> UpstreamFailure:
    """Map an :class:`httpx.RequestError` to a network-unreachable failure."""
    return UpstreamFailure(
        kind="network_unreachable",
        provider_name=provider_name,
        upstream_status=None,
        upstream_body=None,
        upstream_message=str(exc)[:240] or None,
        retry_after_seconds=None,
    )


# Substrings that indicate quota exhaustion when a provider returns the
# error in a 2xx response body instead of the conventional 429. Gemini's
# OpenAI-compat endpoint does this — the wrapper returns 200 with the
# quota error embedded in the assistant message text. The URL is the
# strongest signal: it appears nowhere else in normal model output.
_QUOTA_BODY_SIGNALS: tuple[str, ...] = (
    "ai.google.dev/gemini-api/docs/rate-limits",
    "exceeded your current quota",
    "exceeded your quota",
    "resource_exhausted",
    "quotaexceeded",
)


def detect_quota_in_2xx_body(body: str | None, *, provider_name: str, status: int) -> UpstreamFailure | None:
    """Return a :class:`UpstreamFailure` when ``body`` shows quota exhaustion.

    Some providers (Gemini's OpenAI-compat endpoint) embed quota errors
    in successful HTTP responses, so :func:`classify_http_failure` never
    sees them. This is the second line of defence: scan the body text
    for known quota markers even on 2xx, and surface the same typed
    failure the 429 path produces.

    The substring set is intentionally narrow — generic phrases like
    "rate limit" appear too often in legitimate model output about
    security topics to be safe signals.
    """
    if not body:
        return None
    body_lc = body.lower()
    for signal in _QUOTA_BODY_SIGNALS:
        idx = body_lc.find(signal)
        if idx == -1:
            continue
        # Surrounding ±50 chars of original-case context so the modal
        # message and ledger row preserve readable substring.
        start = max(0, idx - 50)
        end = min(len(body), idx + len(signal) + 50)
        context = body[start:end].strip()
        return UpstreamFailure(
            kind="quota_exceeded",
            provider_name=provider_name,
            upstream_status=status,
            upstream_body=body[:1000],
            upstream_message=context[:240] or None,
            retry_after_seconds=_parse_retry_after_body(body_lc),
        )
    return None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AiProviderError(RuntimeError):
    """Base class for every error raised by this package.

    Subclasses are caught by the orchestrator (Phase 2) and converted into
    structured failures rather than exceptions in user-facing surfaces.

    When a concrete provider has structured information about the upstream
    failure (HTTP status, response body, Retry-After), it attaches an
    :class:`UpstreamFailure` via :attr:`failure`. The orchestrator reads
    this directly to populate the typed :class:`~app.ai.schemas.AiFixError`
    instead of regex-ing error strings.
    """

    def __init__(self, message: str, *, failure: UpstreamFailure | None = None) -> None:
        super().__init__(message)
        self.failure = failure


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
