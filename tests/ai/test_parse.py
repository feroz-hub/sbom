"""Tests for ``app.ai.parse.parse_llm_json``.

Each test pins one parsing strategy against one real-world LLM-output
quirk. The helper is lossless — it never mutates the JSON contents,
only the wrapping. Schema-layer tolerance (case-insensitive enums,
ignored extras, defaults) is tested in ``test_schemas_lenient`` below.
"""

from __future__ import annotations

import pytest
from app.ai.parse import ParseError, parse_llm_json
from pydantic import BaseModel, ConfigDict


class _Payload(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    count: int


# ============================================================ Happy paths


def test_parse_plain_json_passes_through() -> None:
    out = parse_llm_json('{"name": "ok", "count": 1}', _Payload)
    assert out == _Payload(name="ok", count=1)


def test_parse_with_surrounding_whitespace() -> None:
    out = parse_llm_json('   \n\n  {"name": "ok", "count": 1}   \n', _Payload)
    assert out == _Payload(name="ok", count=1)


# ============================================================ Markdown fences


def test_parse_strips_json_fence() -> None:
    raw = '```json\n{"name": "fenced", "count": 2}\n```'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="fenced", count=2)


def test_parse_strips_bare_fence() -> None:
    raw = '```\n{"name": "bare", "count": 3}\n```'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="bare", count=3)


def test_parse_strips_javascript_fence() -> None:
    raw = '```javascript\n{"name": "js", "count": 4}\n```'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="js", count=4)


# ============================================================ Preamble / trailing


def test_parse_extracts_object_with_leading_preamble() -> None:
    raw = 'Sure, here\'s your result:\n\n{"name": "preamble", "count": 5}'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="preamble", count=5)


def test_parse_extracts_object_with_trailing_text() -> None:
    raw = '{"name": "trail", "count": 6}\n\nLet me know if you need anything else!'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="trail", count=6)


def test_parse_extracts_object_with_both_preamble_and_trailing() -> None:
    raw = 'Sure, here you go:\n{"name": "both", "count": 7}\n\nHope that helps.'
    out = parse_llm_json(raw, _Payload)
    assert out == _Payload(name="both", count=7)


# ============================================================ Brace-counting edge cases


def test_brace_counter_skips_braces_inside_strings() -> None:
    """A `{` or `}` inside a JSON string literal must not affect depth."""
    raw = '{"name": "has } and { in value", "count": 8}'
    out = parse_llm_json(raw, _Payload)
    assert out.name == "has } and { in value"
    assert out.count == 8


def test_brace_counter_handles_escaped_quote_in_string() -> None:
    raw = '{"name": "with \\" quote", "count": 9}'
    out = parse_llm_json(raw, _Payload)
    assert out.name == 'with " quote'


def test_nested_object_value() -> None:
    """Brace counting must close at the OUTER object, not the first inner }."""
    raw = 'Here you go: {"name": "nested", "count": 10, "extra": {"a": 1, "b": 2}} thanks!'
    out = parse_llm_json(raw, _Payload)
    assert out.count == 10


# ============================================================ Failure paths


def test_parse_raises_on_empty_input() -> None:
    with pytest.raises(ParseError) as ei:
        parse_llm_json("", _Payload)
    assert ei.value.raw == ""


def test_parse_raises_on_whitespace_only() -> None:
    with pytest.raises(ParseError):
        parse_llm_json("   \n\n   ", _Payload)


def test_parse_raises_on_truncated_json_with_raw_preview() -> None:
    """Truncated JSON cannot be recovered — the helper raises and
    surfaces the offending text via ``raw_preview`` for logging."""
    raw = '{"name": "trunc", "count": 1, "extra": {"deep": "value never closes'
    with pytest.raises(ParseError) as ei:
        parse_llm_json(raw, _Payload)
    assert ei.value.raw == raw
    assert ei.value.raw_preview == raw  # under the 500-char limit


def test_parse_raises_when_no_json_object_present() -> None:
    with pytest.raises(ParseError):
        parse_llm_json("just plain text, no JSON here", _Payload)


def test_parse_carries_validation_error_when_json_parses_but_schema_fails() -> None:
    """If the JSON is valid but doesn't match the schema, the
    ValidationError is preserved on ``last_validation_error`` so
    callers can debug the schema mismatch."""
    raw = '{"name": "ok", "count": "not-an-int"}'
    with pytest.raises(ParseError) as ei:
        parse_llm_json(raw, _Payload)
    assert ei.value.last_validation_error is not None


def test_parse_truncates_raw_preview_to_500_chars() -> None:
    big = "x" * 800
    raw = f"prefix {big} {{not-json"
    with pytest.raises(ParseError) as ei:
        parse_llm_json(raw, _Payload)
    assert len(ei.value.raw_preview) == 500
    assert ei.value.raw == raw  # full body still available
