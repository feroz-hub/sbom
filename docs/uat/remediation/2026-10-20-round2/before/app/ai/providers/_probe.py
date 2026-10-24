"""Shared probe helpers for ``test_connection``.

Phase 1 §1.6: every provider classifies connection failures into typed
:class:`ConnectionErrorKind` values so the Settings UI can pick a
specific message instead of parsing strings. This module owns the
shared classifier so each provider stays focused on its own request
shape.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from .base import ConnectionErrorKind, ConnectionTestResult


def classify_http_error(status_code: int, body_text: str = "") -> ConnectionErrorKind:
    """HTTP status → typed connection error kind.

    Used by every cloud provider's probe path. Local providers (Ollama)
    skip auth-class buckets since they typically don't authenticate.
    """
    if status_code in (401, 403):
        return "auth"
    if status_code == 408:
        return "network"
    if status_code >= 500:
        return "provider_unavailable"
    if status_code == 400:
        # Google can reject an invalid key with HTTP 400. Only explicit
        # machine-readable reasons qualify; arbitrary 400s are not auth failures.
        try:
            error = json.loads(body_text).get("error", {})
            details = error.get("details", []) if isinstance(error, dict) else []
            if any(isinstance(item, dict) and item.get("reason") in {"API_KEY_INVALID", "API_KEY_EXPIRED"} for item in details):
                return "auth"
        except (ValueError, AttributeError, TypeError):
            pass
        return "configuration"
    if status_code == 404:
        return "model_not_found"
    if status_code == 429:
        return "rate_limit"
    return "unknown"


def classify_request_error(exc: Exception) -> ConnectionErrorKind:
    """Network-layer exception → typed kind."""
    if isinstance(exc, httpx.RequestError):
        return "network"
    return "unknown"


async def probe_openai_compatible_models(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    headers: dict[str, str],
    timeout_s: float = 8.0,
) -> tuple[list[str], int | None, str] | None:
    """Hit ``GET {base_url}/models``. Return (models, status_code, error_body) or None on failure.

    None indicates the endpoint doesn't exist (404) — caller should
    fall back to a chat-completion probe. Other failures bubble up via
    a separate exception (caller should catch ``httpx.HTTPError``).
    """
    url = base_url.rstrip("/") + "/models"
    resp = await client.get(url, headers=headers, timeout=timeout_s)
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        return [], resp.status_code, resp.text
    body = resp.json()
    items = body.get("data") or body.get("models") or []
    names: list[str] = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("id") or item.get("name") or item.get("model")
            if isinstance(name, str):
                names.append(name)
        elif isinstance(item, str):
            names.append(item)
    return names, resp.status_code, ""


def measure(start_perf: float) -> int:
    return int((time.perf_counter() - start_perf) * 1000)


def network_failure(*, provider: str, model: str | None, exc: Exception) -> ConnectionTestResult:
    """Build a network-failure result without re-stringifying messages."""
    return ConnectionTestResult(
        success=False,
        latency_ms=None,
        detected_models=[],
        error_message="The provider could not be reached. Verification can be retried later.",
        error_kind=classify_request_error(exc),
        provider=provider,
        model_tested=model,
    )


def http_failure(
    *,
    provider: str,
    model: str | None,
    status: int,
    body_text: str,
    latency_ms: int,
    detected_models: list[str] | None = None,
) -> ConnectionTestResult:
    return ConnectionTestResult(
        success=False,
        latency_ms=latency_ms,
        detected_models=detected_models or [],
        error_message=f"HTTP {status}: {classify_http_error(status, body_text)}",
        error_kind=classify_http_error(status, body_text),
        http_status=status,
        provider=provider,
        model_tested=model,
    )


def success(
    *,
    provider: str,
    model: str | None,
    detected_models: list[str],
    latency_ms: int,
) -> ConnectionTestResult:
    return ConnectionTestResult(
        success=True,
        latency_ms=latency_ms,
        detected_models=detected_models,
        error_message=None,
        error_kind=None,
        provider=provider,
        model_tested=model,
    )


def parse_chat_completion_response(data: dict[str, Any]) -> str:
    """Extract the assistant text from an OpenAI-compatible chat response."""
    choices = data.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") or {}
    return (msg.get("content") or "").strip()


__all__ = [
    "classify_http_error",
    "classify_request_error",
    "http_failure",
    "measure",
    "network_failure",
    "parse_chat_completion_response",
    "probe_openai_compatible_models",
    "success",
]


def sanitized_result(result: ConnectionTestResult) -> ConnectionTestResult:
    """Never return/store arbitrary adapter error text, even for older adapters."""
    if result.success:
        return result.model_copy(update={"error_message": None, "error_kind": None})
    kind = result.error_kind or "unknown"
    detail = f"{kind}" + (f" (HTTP {result.http_status})" if result.http_status else "")
    return result.model_copy(update={"error_message": detail})
