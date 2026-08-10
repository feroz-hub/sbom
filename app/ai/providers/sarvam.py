"""Sarvam AI provider — OpenAI-compatible Chat Completions.

Sarvam (https://sarvam.ai) exposes an OpenAI-compatible ``/chat/completions``
endpoint, so this is a thin specialisation of :class:`OpenAiProvider`: same
request/response shape, with a Sarvam base URL + default model and a
conservative structured-output mode.

``json_object`` (rather than ``json_schema_strict``) is the default because
the OpenAI-compat endpoint enforces *valid JSON* but not full JSON-Schema —
the strict prompt + ``AiFixGenerator`` post-validation carry the schema shape,
matching how the Gemini OpenAI-compat path is wired. Cost is looked up under
the ``"sarvam"`` key in ``app.ai.cost`` (unknown models bill at $0 with a
logged warning until pricing is filled in).
"""

from __future__ import annotations

from typing import Any

from .openai import OpenAiProvider, StructuredOutputMode

_DEFAULT_BASE_URL = "https://api.sarvam.ai/v1"
_DEFAULT_MODEL = "sarvam-m"


class SarvamProvider(OpenAiProvider):
    """Implements :class:`LlmProvider` against Sarvam's OpenAI-compatible API."""

    name: str = "sarvam"

    def __init__(
        self,
        *,
        api_key: str,
        default_model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        max_concurrent: int = 10,
        rate_per_minute: float = 60.0,
        structured_output_mode: StructuredOutputMode = "json_object",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            api_key=api_key,
            default_model=default_model,
            base_url=base_url or _DEFAULT_BASE_URL,
            max_concurrent=max_concurrent,
            rate_per_minute=rate_per_minute,
            structured_output_mode=structured_output_mode,
            **kwargs,
        )


__all__ = ["SarvamProvider"]
