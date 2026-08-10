"""Deprecation metadata and lightweight telemetry for compatibility APIs."""

from __future__ import annotations

import logging
from collections import Counter
from threading import Lock

from fastapi import Response

log = logging.getLogger("sbom.api.deprecation")

LEGACY_ANALYSIS_SUNSET = "Sun, 31 Jan 2027 23:59:59 GMT"
LEGACY_JSON_SBOM_SUNSET = "Sun, 31 Jan 2027 23:59:59 GMT"

_calls: Counter[str] = Counter()
_lock = Lock()


def mark_deprecated(
    response: Response,
    *,
    endpoint: str,
    successor: str,
    sunset: str,
) -> None:
    """Attach standard headers and record one compatibility-path call."""
    with _lock:
        _calls[endpoint] += 1
        total = _calls[endpoint]
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = sunset
    response.headers["Link"] = f'<{successor}>; rel="successor-version"'
    response.headers["X-Deprecated-Endpoint"] = endpoint
    log.warning(
        "deprecated_endpoint_call endpoint=%s successor=%s sunset=%s total_calls=%d",
        endpoint,
        successor,
        sunset,
        total,
    )


def deprecated_call_count(endpoint: str) -> int:
    """Return the process-local counter used by tests and operations hooks."""
    with _lock:
        return int(_calls[endpoint])
