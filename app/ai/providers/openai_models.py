"""Reviewed OpenAI capabilities; model listing alone never establishes access.

SBO-99. Sources: https://developers.openai.com/api/docs/models and
https://developers.openai.com/api/docs/guides/latest-model (2026-10-30).
Keep exact IDs here, including documented snapshots. Unknown models remain
discoverable but require a reviewed profile and pricing before invocation.
This module has no effect on providers that merely speak OpenAI's protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal


@dataclass(frozen=True)
class OpenAiModelProfile:
    endpoint: Literal["chat/completions", "responses"] = "responses"
    token_parameter: Literal["max_tokens", "max_completion_tokens", "max_output_tokens"] = "max_output_tokens"
    reasoning_efforts: tuple[str, ...] = ()
    default_effort: str | None = None
    temperature: bool = False
    chat: bool | None = True
    structured: bool | None = True
    tools: bool | None = True
    context_window: int | None = None
    max_output_tokens: int | None = None
    # Standard, uncached text USD per 1k tokens. Reasoning is output usage.
    pricing: tuple[float, float] | None = None


_CHAT = dict(
    endpoint="chat/completions",
    token_parameter="max_tokens",
    temperature=True,
    context_window=128000,
    max_output_tokens=16384,
)
PROFILES = {
    "gpt-4o": OpenAiModelProfile(**_CHAT, pricing=(0.0025, 0.01)),
    "gpt-4o-mini": OpenAiModelProfile(**_CHAT, pricing=(0.00015, 0.0006)),
}
for _family, _pricing in {"gpt-4.1": (0.002, 0.008), "gpt-4.1-mini": (0.0004, 0.0016)}.items():
    PROFILES[_family] = OpenAiModelProfile(
        endpoint="chat/completions",
        token_parameter="max_tokens",
        temperature=True,
        context_window=1047576,
        max_output_tokens=32768,
        pricing=_pricing,
    )
    PROFILES[_family + "-2025-04-14"] = PROFILES[_family]


def _reasoning(ids, *, efforts, pricing, context=400000, default="low"):
    for model in ids:
        PROFILES[model] = OpenAiModelProfile(
            reasoning_efforts=efforts,
            default_effort=default,
            context_window=context,
            max_output_tokens=128000,
            pricing=pricing,
        )


_reasoning(("gpt-5", "gpt-5-2025-08-07"), efforts=("minimal", "low", "medium", "high"), pricing=(0.00125, 0.01))
_reasoning(
    ("gpt-5-mini", "gpt-5-mini-2025-08-07"), efforts=("minimal", "low", "medium", "high"), pricing=(0.00025, 0.002)
)
_reasoning(
    ("gpt-5-nano", "gpt-5-nano-2025-08-07"), efforts=("minimal", "low", "medium", "high"), pricing=(0.00005, 0.0004)
)
_reasoning(("gpt-5.1", "gpt-5.1-2025-11-13"), efforts=("none", "low", "medium", "high"), pricing=(0.00125, 0.01))
_reasoning(
    ("gpt-5.2", "gpt-5.2-2025-12-11"), efforts=("none", "low", "medium", "high", "xhigh"), pricing=(0.00175, 0.014)
)
_reasoning(
    ("gpt-5.4", "gpt-5.4-2026-03-05"),
    efforts=("none", "low", "medium", "high", "xhigh"),
    pricing=(0.0025, 0.015),
    context=1050000,
)
_EFFORTS = ("none", "low", "medium", "high", "xhigh", "max")
_reasoning(("gpt-5.4-mini", "gpt-5.4-mini-2026-03-17"), efforts=_EFFORTS[:-1], pricing=(0.00075, 0.0045))
_reasoning(("gpt-5.5", "gpt-5.5-2026-04-23"), efforts=_EFFORTS[:-1], pricing=(0.005, 0.03), context=1050000)
_reasoning(("gpt-5.6-luna",), efforts=_EFFORTS, pricing=(0.0002, 0.0012), context=1050000)
_reasoning(("gpt-5.6-terra",), efforts=_EFFORTS, pricing=(0.002, 0.012), context=1050000)
_reasoning(("gpt-5.6-sol",), efforts=_EFFORTS, pricing=(0.004, 0.02), context=1050000)
_reasoning(("gpt-6-luna",), efforts=_EFFORTS, pricing=(0.0001, 0.0005), context=1050000)
_reasoning(("gpt-6.1-terra",), efforts=_EFFORTS, pricing=(0.001, 0.005), context=1050000)
_reasoning(("gpt-6-sol", "gpt-6.1-sol"), efforts=_EFFORTS[1:], pricing=(0.002, 0.01), context=1050000)
# GPT-6 Sol, unlike GPT-6.1 Sol, also supports none.
PROFILES["gpt-6-sol"] = replace(PROFILES["gpt-6-sol"], reasoning_efforts=_EFFORTS)

# Existing documented snapshots retain exact runtime identifiers.
for _snapshot, _family in {
    "gpt-4o-2024-08-06": "gpt-4o",
    "gpt-4o-2024-11-20": "gpt-4o",
    "gpt-4o-mini-2024-07-18": "gpt-4o-mini",
}.items():
    PROFILES[_snapshot] = PROFILES[_family]

UNKNOWN = OpenAiModelProfile(chat=None, structured=None, tools=None)
NON_GENERATIVE = OpenAiModelProfile(chat=False, structured=False, tools=False)


def profile_for(model: str) -> OpenAiModelProfile:
    if model in PROFILES:
        return PROFILES[model]
    if any(
        part in model.lower()
        for part in ("embedding", "transcribe", "tts", "realtime", "audio", "image", "moderation", "whisper")
    ):
        return NON_GENERATIVE
    return UNKNOWN
