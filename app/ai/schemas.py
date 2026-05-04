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
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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

    model_config = ConfigDict(extra="forbid")

    summary_in_context: str = Field(..., min_length=20, max_length=1200)
    exploitation_likelihood: ExploitationLikelihood
    recommended_path: str = Field(..., min_length=10, max_length=600)
    confidence: ConfidenceTier


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

    model_config = ConfigDict(extra="forbid")

    ecosystem: str = Field(..., min_length=1, max_length=64)
    command: str = Field(..., min_length=1, max_length=600)
    target_version: str = Field(..., min_length=1, max_length=64)
    rationale: str = Field(..., min_length=1, max_length=400)
    breaking_change_risk: BreakingChangeRisk
    tested_against_data: bool


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

    model_config = ConfigDict(extra="forbid")

    priority: PriorityTier
    # Length is enforced inside the validator (truncate over reject) so an
    # over-eager model still produces a usable answer instead of a hard fail.
    reasoning: list[str]
    citations: list[CitationSource] = Field(default_factory=list)
    confidence: ConfidenceTier
    caveats: list[str] = Field(default_factory=list)

    @field_validator("reasoning")
    @classmethod
    def _enforce_reasoning_lengths(cls, v: list[str]) -> list[str]:
        # Each bullet has to be useful. 8 chars is the minimum that gets
        # past "ok" / "n/a" type single-word junk responses.
        out = [b.strip() for b in v if isinstance(b, str) and len(b.strip()) >= 8]
        if not out:
            raise ValueError("reasoning must contain at least one substantive bullet")
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
    """

    model_config = ConfigDict(extra="forbid")

    remediation_prose: RemediationProse
    upgrade_command: UpgradeCommand
    decision_recommendation: DecisionRecommendation


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


class AiFixError(BaseModel):
    """Structured error surface for the orchestrator.

    Failed generations are reported, not raised. The batch worker continues
    past per-finding errors so a single bad provider response can't take
    down a 1,000-finding scan.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: int | None = None
    vuln_id: str
    component_name: str
    component_version: str
    error_code: Literal[
        "schema_parse_failed",
        "provider_unavailable",
        "circuit_breaker_open",
        "budget_exceeded",
        "grounding_missing",
        "internal_error",
    ]
    message: str


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
