"""Lenient LLM-output JSON parsing.

LLMs sometimes wrap structured output in cosmetic noise — markdown
fences, a leading "Sure, here's the JSON:" preamble, trailing
commentary. Strict ``model_validate(json.loads(text))`` rejects these,
forcing a (quota-burning) retry that the model is no more likely to
get right than the first attempt.

This module is the layer between "what the model emitted" and "what
strict Pydantic validates". It tries a small ordered list of
candidate strings (each handles one specific quirk), parses each as
JSON, and returns the first one Pydantic accepts. The strict schema
is unchanged — we add tolerance for *valid output that's superficially
malformed*, not for *invalid output*. If every candidate fails we
raise a single :class:`ParseError` carrying the last validation
error and the raw response (truncated to 500 chars) so callers can
log the offending text.

What this module does NOT do:

  * It does not recover truncated JSON — if the model ran out of
    tokens mid-object there are no closing braces to invent.
    Truncation is a token-budget problem, not a parsing problem.
  * It does not silently substitute defaults. Loosening the schemas
    to accept missing fields belongs in the schema definitions.
  * It does not invent fields the model didn't produce.
"""

from __future__ import annotations

import json
import re
from typing import Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

# Match a fenced JSON block: optional ```json or ```javascript marker,
# any content, closing ```. ``re.DOTALL`` lets ``.`` cross newlines.
_FENCE_PATTERN = re.compile(
    r"^\s*```(?:json|javascript)?\s*(.+?)\s*```\s*$",
    re.DOTALL | re.IGNORECASE,
)

# Hard upper bound on the raw text we surface in errors. The full body
# still goes to ai_usage_log; this is the user-facing-modal slice.
_RAW_PREVIEW_LIMIT = 500


class ParseError(Exception):
    """Raised by :func:`parse_llm_json` when no candidate parses cleanly.

    Carries:

    * :attr:`raw`: the model's full response text.
    * :attr:`raw_preview`: the first 500 chars (modal-safe).
    * :attr:`last_validation_error`: the deepest Pydantic
      :class:`ValidationError` from the strictest candidate that at
      least produced a JSON object (``None`` if no candidate even
      json.loaded).
    """

    def __init__(
        self,
        message: str,
        *,
        raw: str,
        last_validation_error: ValidationError | None = None,
    ) -> None:
        super().__init__(message)
        self.raw = raw
        self.raw_preview = (raw or "")[:_RAW_PREVIEW_LIMIT]
        self.last_validation_error = last_validation_error


def parse_llm_json(raw: str, schema: Type[T]) -> T:
    """Parse LLM-generated JSON into a strict Pydantic ``schema``.

    Tries, in order:

    1. The text as-is (fast path for well-behaved models).
    2. Stripped markdown fence — handles `````json {...} `````.
    3. First complete JSON object via brace counting — handles
       ``"Sure, here's the result: {...} hope this helps!"``.

    Raises :class:`ParseError` with the offending response if every
    candidate fails. The schema layer is responsible for
    case-insensitive enum normalisation; this module never mutates
    the JSON contents, only the wrapping.
    """
    if not raw or not raw.strip():
        raise ParseError("empty response", raw=raw or "")

    last_validation_error: ValidationError | None = None
    for candidate in _generate_candidates(raw):
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        try:
            return schema.model_validate(data)
        except ValidationError as exc:
            last_validation_error = exc
            continue

    raise ParseError(
        f"could not parse response as {schema.__name__}",
        raw=raw,
        last_validation_error=last_validation_error,
    )


def _generate_candidates(raw: str) -> list[str]:
    """Yield candidate JSON strings to try parsing, in priority order.

    Each strategy targets one specific real-world quirk. Order
    matters — the as-is candidate is tried first because it's the
    common case for well-behaved providers (Anthropic tool-use,
    OpenAI ``json_schema`` mode); the fence and brace-extraction
    strategies handle the messier providers.
    """
    candidates: list[str] = []

    stripped = raw.strip()
    if stripped:
        candidates.append(stripped)

    fenced = _FENCE_PATTERN.match(stripped)
    if fenced:
        body = fenced.group(1).strip()
        if body and body not in candidates:
            candidates.append(body)

    extracted = _extract_first_json_object(stripped)
    if extracted and extracted not in candidates:
        candidates.append(extracted)

    return candidates


def _extract_first_json_object(text: str) -> str | None:
    """Return the first complete ``{...}`` substring via brace counting.

    Handles cases like::

        Sure, here you go:

        {
          "remediation_prose": {…}
        }

        Hope this helps!

    Skips braces inside string literals so JSON values containing
    ``{`` or ``}`` don't throw the depth counter off. Returns
    ``None`` when no complete object is present (e.g. truncated
    output where the closing brace never arrives).
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


__all__ = ["ParseError", "parse_llm_json"]
