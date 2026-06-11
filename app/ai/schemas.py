"""Structured output schemas for the AI fix generator (Phase 2).

The model never produces free-form text in production. Every call requests
JSON conforming to :class:`AiFixBundle` and we parse / validate before
caching. Failures fall through to a structured error rather than a silent
"the model said something weird" outcome.

Why one bundle instead of three calls: Phase 1 §8 examples model all three
artifacts as a single JSON object with three top-level keys. One LLM call
is roughly a third of the cost of three sequential calls and dramatically
simpler to make atomic. We trade a small amount of prompt size for ~67%
cost reduction at the same cache hit rate.

Phase 5 schema loosening
------------------------
The original Phase 2 schemas were strict (``extra="forbid"``, exact-case
enums, every classification field required). Real-world Gemini /
OpenAI-compat output drifts in three predictable ways that block parsing
without changing the meaning of the answer:

  * Capitalised enum values ("High" instead of "high") — fixed by
    pre-validators that lowercase + normalise separators.
  * Extra context fields the model felt like adding — fixed by
    ``extra="ignore"`` (the post-validator + post-validation in
    :class:`~app.ai.fix_generator.AiFixGenerator` is the actual
    hallucination defence; rejecting unknown keys never was).
  * Omitted classification fields when the model is uncertain — fixed
    with sensible defaults on the *secondary* classification fields
    (``confidence``, ``exploitation_likelihood``, ``priority``,
    ``breaking_change_risk``). Required content fields (``summary``,
    ``recommended_path``, ``command``, ``target_version``,
    ``rationale``) stay required — there's no sensible default for
    those.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _normalize_enum_value(v: object) -> object:
    """Lowercase + normalise separators on string enum candidates.

    Used as a ``mode='before'`` validator. Pydantic's ``Literal[...]``
    matches exact strings, so ``"Actively Exploited"`` from a model
    that ignored the lowercase instruction would otherwise fail.
    Tolerates ``"High"`` → ``"high"``, ``"Major"`` → ``"major"``,
    ``"Actively-Exploited"`` → ``"actively_exploited"``, etc.
    """
    if isinstance(v, str):
        return v.strip().lower().replace("-", "_").replace(" ", "_")
    return v

# Bumping :data:`SCHEMA_VERSION` is a hard cache invalidation — every
# existing ``ai_fix_cache`` row becomes stale on upgrade. Keep stable and
# only bump when the bundle shape changes in a backward-incompatible way.
SCHEMA_VERSION: int = 1


# ---------------------------------------------------------------------------
# RemediationProse
# ---------------------------------------------------------------------------


ExploitationLikelihood = Literal[
    "actively_exploited",
    "high",
    "moderate",
    "low",
    "theoretical",
]

ConfidenceTier = Literal["high", "medium", "low"]


class RemediationProse(BaseModel):
    """2-4 sentence user-facing summary of the finding in context.

    Length is enforced at validator level — trimming a 6-sentence response
    is preferable to surfacing a wall of text. The prompt instructs the
    model on length, but defence in depth lives here too.
    """

    # ``extra="ignore"`` (Phase 5): real-world models occasionally include
    # extra fields like ``"explanation"`` or ``"references"`` we didn't
    # ask for; rejecting the bundle for that is a worse user experience
    # than ignoring them. Hallucination defence lives in
    # :meth:`AiFixGenerator._post_validate`, not in ``extra="forbid"``.
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    summary_in_context: str = Field(..., min_length=20, max_length=1200)
    # Default "moderate" — the safest middle classification when the
    # model omits this (post-validation downgrades anyway if the kev
    # flag isn't set).
    exploitation_likelihood: ExploitationLikelihood = "moderate"
    recommended_path: str = Field(..., min_length=10, max_length=600)
    confidence: ConfidenceTier = "medium"

    @field_validator("exploitation_likelihood", "confidence", mode="before")
    @classmethod
    def _normalize_enum(cls, v: object) -> object:
        # Gemini sometimes returns "High" with a capital H or
        # "Actively Exploited" with a space; lowercase + replace
        # separators so the strict Literal still matches.
        return _normalize_enum_value(v)


# ---------------------------------------------------------------------------
# UpgradeCommand
# ---------------------------------------------------------------------------


BreakingChangeRisk = Literal["none", "minor", "major", "unknown"]


class UpgradeCommand(BaseModel):
    """Concrete, copy-paste-ready remediation command.

    ``tested_against_data`` is the load-bearing field — the
    :class:`AiFixGenerator` post-validation step ensures it can ONLY be
    ``True`` when ``target_version`` actually appears in the upstream
    fix-version list. The model is allowed to *suggest* a version it
    inferred, but the bit gets flipped to ``False`` server-side if the
    suggestion is not in the data. This is the schema-level half of the
    hallucination defence — the prompt-level half is in the prompt files.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    ecosystem: str = Field(..., min_length=1, max_length=64)
    command: str = Field(..., min_length=1, max_length=600)
    target_version: str = Field(..., min_length=1, max_length=64)
    rationale: str = Field(..., min_length=1, max_length=400)
    # Default "unknown" when the model omits the risk classification —
    # surfaces the uncertainty in the UI rather than failing the parse.
    breaking_change_risk: BreakingChangeRisk = "unknown"
    # Default False so an omission is treated as "we have no evidence"
    # — post-validation will only ever flip this to False, never True.
    tested_against_data: bool = False

    @field_validator("breaking_change_risk", mode="before")
    @classmethod
    def _normalize_breaking_change_risk(cls, v: object) -> object:
        return _normalize_enum_value(v)


# ---------------------------------------------------------------------------
# DecisionRecommendation
# ---------------------------------------------------------------------------


PriorityTier = Literal["urgent", "soon", "scheduled", "defer"]
CitationSource = Literal[
    "osv",
    "ghsa",
    "nvd",
    "epss",
    "kev",
    "fix_version_data",
]


class DecisionRecommendation(BaseModel):
    """Structured 'should you act on this now' advice.

    ``citations`` enumerates the data sources the model used. We don't
    require these to map 1:1 with the grounding context's ``sources_used``
    list, but a model that cites ``kev`` when KEV data wasn't provided is
    flagged as a low-confidence hallucination during post-validation.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    # Default "scheduled" when the model omits the priority — least
    # alarming default that still routes the finding into the work queue.
    priority: PriorityTier = "scheduled"
    # Length is enforced inside the validator (truncate over reject) so an
    # over-eager model still produces a usable answer instead of a hard fail.
    reasoning: list[str] = Field(default_factory=list)
    citations: list[CitationSource] = Field(default_factory=list)
    confidence: ConfidenceTier = "medium"
    caveats: list[str] = Field(default_factory=list)

    @field_validator("priority", "confidence", mode="before")
    @classmethod
    def _normalize_enums(cls, v: object) -> object:
        return _normalize_enum_value(v)

    @field_validator("citations", mode="before")
    @classmethod
    def _normalize_citations(cls, v: object) -> object:
        # Lowercase each citation string so "KEV" / "kev" / "kev " all
        # match the Literal enum.
        if isinstance(v, list):
            return [_normalize_enum_value(item) for item in v]
        return v

    @field_validator("reasoning")
    @classmethod
    def _enforce_reasoning_lengths(cls, v: list[str]) -> list[str]:
        # Each bullet has to be useful. 8 chars is the minimum that gets
        # past "ok" / "n/a" type single-word junk responses. An omitted
        # list may default empty, but an explicitly non-empty junk list is
        # rejected so model output cannot silently lose all reasoning.
        out = [b.strip() for b in v if isinstance(b, str) and len(b.strip()) >= 8]
        if v and not out:
            raise ValueError("reasoning must include at least one substantive bullet")
        return out[:5]

    @field_validator("caveats")
    @classmethod
    def _trim_caveats(cls, v: list[str]) -> list[str]:
        out = [c.strip() for c in v if isinstance(c, str) and c.strip()]
        return out[:3]


# ---------------------------------------------------------------------------
# Bundle — what one orchestrator call returns
# ---------------------------------------------------------------------------


class AiFixBundle(BaseModel):
    """The atomic unit of AI fix output.

    Cached as a single row in :class:`~app.models.AiFixCache` keyed on
    ``(vuln_id, component_name, component_version, prompt_version)``.

    ``overall_confidence`` is the model's self-assessed confidence in the
    *entire* response (distinct from the per-section ``confidence`` fields on
    :class:`RemediationProse` and :class:`DecisionRecommendation`, which scope
    only their own recommendation). It is surfaced prominently at the top of
    the AI-fix UI so a reader can calibrate trust before reading the detail.
    Model self-reported, not server-clamped — defaults to ``"medium"`` when
    omitted, matching the neutral default used by the per-section fields.
    """

    model_config = ConfigDict(extra="forbid")

    remediation_prose: RemediationProse
    upgrade_command: UpgradeCommand
    decision_recommendation: DecisionRecommendation
    overall_confidence: ConfidenceTier = "medium"

    @field_validator("overall_confidence", mode="before")
    @classmethod
    def _normalize_overall_confidence(cls, v: object) -> object:
        # Same lenience as the per-section confidence fields: a model that
        # emits "High" / "Medium" still matches the lowercase Literal.
        return _normalize_enum_value(v)


# ---------------------------------------------------------------------------
# Metadata wrapper used by the orchestrator + API layer
# ---------------------------------------------------------------------------


class AiFixMetadata(BaseModel):
    """Per-bundle provenance — what produced it, when, and at what cost."""

    model_config = ConfigDict(extra="forbid")

    cache_key: str
    cache_hit: bool
    provider_used: str
    model_used: str
    prompt_version: str
    schema_version: int = SCHEMA_VERSION
    total_cost_usd: float = Field(..., ge=0.0)
    generated_at: str
    expires_at: str
    age_seconds: int = Field(default=0, ge=0)


class AiFixResult(BaseModel):
    """Generator output — bundle + metadata.

    Returned to the API surface; the orchestrator's batch helper aggregates
    a list of these.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: int | None = None
    vuln_id: str
    component_name: str
    component_version: str
    bundle: AiFixBundle
    metadata: AiFixMetadata


AiFixErrorCode = Literal[
    # Original codes — kept for back-compat with cached events.
    "schema_parse_failed",
    "provider_unavailable",
    "circuit_breaker_open",
    "budget_exceeded",
    "grounding_missing",
    "internal_error",
    # Phase 5 — typed upstream-failure surface (the modal renders distinct
    # copy and disables the Generate button per the rules in the frontend).
    "quota_exceeded",
    "rate_limited",
    "auth_failed",
    "model_not_found",
    "network_unreachable",
    "provider_down",
    "invalid_request",
    "unknown",
]


class AiFixError(BaseModel):
    """Structured error surface for the orchestrator.

    Failed generations are reported, not raised. The batch worker continues
    past per-finding errors so a single bad provider response can't take
    down a 1,000-finding scan.

    The Phase 5 upstream-failure fields (``upstream_status_code``,
    ``upstream_message``, ``retry_after_seconds``, ``retry_after_human``,
    ``provider_name``, ``model_name``) are populated whenever a concrete
    provider attached an :class:`~app.ai.providers.base.UpstreamFailure`
    to the raised :class:`~app.ai.providers.base.AiProviderError`. Older
    code paths leave them ``None``.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: int | None = None
    vuln_id: str
    component_name: str
    component_version: str
    error_code: AiFixErrorCode
    message: str

    # Structured upstream context — see docstring.
    provider_name: str | None = None
    model_name: str | None = None
    upstream_status_code: int | None = None
    upstream_message: str | None = None
    retry_after_seconds: int | None = None
    retry_after_human: str | None = None


def humanize_retry_after(seconds: int | None) -> str | None:
    """Format ``seconds`` as a coarse "in N <unit>" string for the modal.

    Returns ``None`` when ``seconds`` is ``None`` or non-positive. The
    output is intentionally coarse — the user only needs to know whether
    to retry in a moment vs come back tomorrow.
    """
    if seconds is None or seconds <= 0:
        return None
    if seconds < 60:
        return f"in {seconds}s"
    if seconds < 3600:
        return f"in {seconds // 60} min"
    if seconds < 86400:
        hours = seconds // 3600
        return f"in {hours} hour{'s' if hours != 1 else ''}"
    days = seconds // 86400
    return f"in {days} day{'s' if days != 1 else ''}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def bundle_json_schema() -> dict[str, object]:
    """Return the JSON Schema dict for :class:`AiFixBundle`.

    Used by the providers to pin structured output (Anthropic tool-use
    ``input_schema``, OpenAI ``response_format.json_schema.schema``, Ollama
    ``format``).
    """
    return AiFixBundle.model_json_schema()
