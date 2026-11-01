"""OpenAI-only payloads, output validation and sanitized diagnostics (SBO-99)."""

from __future__ import annotations

import copy
import json
from typing import Any

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from .base import AiProviderError, LlmRequest, LlmUsage, UpstreamFailure
from .openai_models import OpenAiModelProfile

MESSAGES = {
    "auth": "OpenAI rejected the API key. Check the saved credential.",
    "permission": "The credential lacks permission to invoke this model. Check project model access.",
    "model_not_found": "The exact model ID is unavailable or not accessible to this project.",
    "unsupported_model": "This model has no reviewed text-generation profile and pricing. Configure its capabilities before use.",
    "unsupported_parameter": "The model rejected a request parameter. Review its capability profile.",
    "configuration": "OpenAI rejected the request. Check the model capability profile and output schema.",
    "rate_limit": "OpenAI rate limit reached. Retry after the provider's retry interval.",
    "quota": "OpenAI quota is exhausted. Check project billing and spending limits.",
    "network": "OpenAI could not be reached. Check network connectivity.",
    "timeout": "OpenAI timed out. Retry later or select a faster model.",
    "provider_unavailable": "OpenAI is temporarily unavailable. Retry later.",
    "invalid_response": "OpenAI returned an invalid response.",
    "invalid_json": "The model output did not match the required JSON schema.",
    "incomplete": "Generation was incomplete. The output limit includes reasoning tokens; review the bounded token budget.",
    "refusal": "The model declined this request. Review the task and supplied evidence.",
    "budget_exceeded": "Model test exceeds the configured AI budget. Review spending limits.",
    "unknown": "OpenAI verification failed. Check model access and configuration.",
}


def http_kind(status: int, body: str = "") -> str:
    try:
        error = json.loads(body).get("error", {})
        code = error.get("code") or error.get("type") or ""
        if not isinstance(code, str):
            code = ""
    except (ValueError, AttributeError, TypeError):
        code = ""
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if status == 404:
        return "model_not_found"
    if status == 429:
        return (
            "quota" if code in {"insufficient_quota", "billing_hard_limit_reached", "quota_exceeded"} else "rate_limit"
        )
    if status in (400, 422):
        return "unsupported_parameter" if code in {"unsupported_parameter", "unsupported_value"} else "configuration"
    if status == 408:
        return "timeout"
    return "provider_unavailable" if status >= 500 else "unknown"


class OpenAiError(AiProviderError):
    def __init__(
        self,
        kind: str,
        *,
        status: int | None = None,
        usage: LlmUsage | None = None,
        accessible: bool | None = None,
        generated: bool | None = None,
    ):
        failure_kind = {
            "auth": "auth_failed",
            "permission": "auth_failed",
            "model_not_found": "model_not_found",
            "unsupported_model": "model_not_found",
            "rate_limit": "rate_limited",
            "quota": "quota_exceeded",
            "network": "network_unreachable",
            "timeout": "network_unreachable",
            "provider_unavailable": "provider_down",
        }.get(kind, "invalid_request")
        super().__init__(
            "openai: " + MESSAGES[kind],
            failure=UpstreamFailure(
                kind=failure_kind,
                provider_name="openai",
                upstream_status=status,
            ),
        )
        self.kind = kind
        self.usage = usage
        self.accessible = False if kind in {"auth", "permission", "model_not_found"} else accessible
        self.generated = generated


def _strict_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Close object schemas without mutating the caller. Maps use JSON mode.

    OpenAI's strict subset requires all declared properties to be required and
    disallows additional properties. Arbitrary dictionaries cannot be encoded
    faithfully, so those schemas retain local validation with JSON mode.
    """
    result = copy.deepcopy(schema)
    compatible = True

    def visit(node):
        nonlocal compatible
        if not isinstance(node, dict):
            compatible = False
            return
        node.pop("default", None)
        # An unconstrained schema (Pydantic Any), dictionary, or unsupported
        # composition must retain its semantics through JSON mode.
        if not any(key in node for key in ("type", "$ref", "anyOf")):
            compatible = False
        if any(
            key in node
            for key in (
                "allOf",
                "oneOf",
                "not",
                "if",
                "then",
                "else",
                "patternProperties",
                "dependentSchemas",
                "dependentRequired",
            )
        ):
            compatible = False
        if node.get("type") == "object" or "properties" in node:
            if "properties" not in node and node.get("additionalProperties") is not False:
                compatible = False
            else:
                node["additionalProperties"] = False
                node["required"] = list(node.get("properties", {}))
        for key in ("properties", "$defs", "definitions"):
            for child in node.get(key, {}).values():
                visit(child)
        for key in ("items", "additionalProperties"):
            if isinstance(node.get(key), dict):
                visit(node[key])
        for key in ("anyOf", "oneOf", "allOf"):
            for child in node.get(key, []):
                visit(child)

    visit(result)
    return result if compatible else None


def build_body(
    req: LlmRequest, model: str, profile: OpenAiModelProfile, *, effort: str | None, temperature: float | None
) -> dict[str, Any]:
    if profile.chat is not True or profile.pricing is None:
        raise OpenAiError("unsupported_model")
    if profile.max_output_tokens and req.max_output_tokens > profile.max_output_tokens:
        raise OpenAiError("configuration")
    selected_effort = effort or profile.default_effort
    if selected_effort and selected_effort not in profile.reasoning_efforts:
        raise OpenAiError("unsupported_parameter")
    body: dict[str, Any] = {"model": model, profile.token_parameter: req.max_output_tokens}
    messages = [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}]
    responses = profile.endpoint == "responses"
    body["input" if responses else "messages"] = messages
    if responses:
        body["store"] = False
    if selected_effort:
        body["reasoning" if responses else "reasoning_effort"] = (
            {"effort": selected_effort} if responses else selected_effort
        )
    if profile.temperature and selected_effort in (None, "none"):
        body["temperature"] = req.temperature if temperature is None else temperature
    if req.response_schema is not None:
        try:
            Draft202012Validator.check_schema(req.response_schema)
        except SchemaError:
            raise OpenAiError("configuration") from None
        if profile.structured is not True:
            raise OpenAiError("unsupported_model")
        schema = _strict_schema(req.response_schema)
        if schema is None:
            messages[0]["content"] += "\nReturn only JSON matching this schema: " + json.dumps(req.response_schema)
        fmt = (
            {"type": "json_schema", "name": "structured_output", "strict": True, "schema": schema}
            if schema
            else {"type": "json_object"}
        )
        if responses:
            body["text"] = {"format": fmt}
        else:
            body["response_format"] = (
                {"type": "json_schema", "json_schema": {k: v for k, v in fmt.items() if k != "type"}} if schema else fmt
            )
    return body


def extract(data: dict[str, Any], *, responses: bool) -> tuple[str, str | None]:
    """Return visible text and a controlled failure; never expose reasoning."""
    if responses:
        output = data.get("output", [])
        if not isinstance(output, list):
            return "", "invalid_response"
        parts = []
        for item in output:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            content = item.get("content") or []
            if not isinstance(content, list):
                return "", "invalid_response"
            parts.extend(part for part in content if isinstance(part, dict))
        if any(part.get("type") == "refusal" for part in parts):
            return "", "refusal"
        text = "".join(
            part["text"] for part in parts if part.get("type") == "output_text" and isinstance(part.get("text"), str)
        ).strip()
        status = data.get("status")
        if status == "failed":
            error = data.get("error") or {}
            code = error.get("code") if isinstance(error, dict) else None
            if not isinstance(code, str):
                code = None
            return text, {
                "rate_limit_exceeded": "rate_limit",
                "insufficient_quota": "quota",
                "server_error": "provider_unavailable",
            }.get(code, "invalid_response")
        details = data.get("incomplete_details") or {}
        if not isinstance(details, dict):
            return text, "invalid_response"
        if status == "incomplete" and details.get("reason") == "content_filter":
            return "", "refusal"
        return text, None if status == "completed" else "incomplete" if status in {
            "incomplete",
            "in_progress",
            "queued",
        } else "invalid_response"
    try:
        choice = data["choices"][0]
        message = choice["message"]
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            return "", "refusal"
        content = message.get("content") or ""
        if not isinstance(content, str):
            return "", "invalid_response"
        return content.strip(), "incomplete" if choice.get("finish_reason") == "length" else None
    except (KeyError, IndexError, TypeError, AttributeError):
        return "", "invalid_response"


def validate_output(text: str, schema: dict[str, Any] | None) -> dict[str, Any] | None:
    if not text:
        raise OpenAiError("invalid_response", accessible=True, generated=False)
    if schema is None:
        return None
    try:
        parsed = json.loads(text)
        Draft202012Validator(schema).validate(parsed)
        if not isinstance(parsed, dict):
            raise ValueError()
        return parsed
    except (ValueError, SchemaError, ValidationError, TypeError):
        raise OpenAiError("invalid_json", accessible=True, generated=True) from None
