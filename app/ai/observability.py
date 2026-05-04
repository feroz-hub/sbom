"""AI subsystem observability — counters, histograms, gauges, OTel shim, structured logger.

Mirrors the in-process pattern in :mod:`app.nvd_mirror.observability` so we
don't introduce ``prometheus_client`` for a single feature. The registry is
process-local, thread-safe, and serialises to both JSON (for the dashboard
endpoint) and Prometheus text format (for ``/metrics`` scraping).

When the ``opentelemetry`` package is present, :func:`generate_span` produces
real OTel spans; otherwise it returns a no-op context manager so call sites
stay unchanged regardless of whether the operator chose to install the OTel
SDK.

The structured logger (:func:`log_ai_call`) emits one ``ai.call`` log entry
per LLM invocation. It NEVER logs the response body — instead it emits a
SHA-256 of the response text plus a ``response_bytes`` count so debugging
can join with provider audit logs without leaking content (Phase 5 §5.2).
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import threading
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Literal

log = logging.getLogger("sbom.ai.metrics")
audit_log = logging.getLogger("sbom.ai.audit")


# ---------------------------------------------------------------------------
# Histogram primitive
# ---------------------------------------------------------------------------


# Latency buckets (seconds) chosen to span LLM call distributions:
#   sub-100ms cache hits, 1-3s warm small models, 5-15s large models, 30s+ batches.
_DEFAULT_BUCKETS: tuple[float, ...] = (
    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0,
)


@dataclass
class Histogram:
    """Cumulative-bucket histogram, Prometheus-compatible.

    ``observe(v)`` increments every bucket whose upper bound is >= v plus
    the ``+Inf`` bucket. Mean falls out of (sum / count); we don't track
    quantiles because those need either a streaming summary or all observations.
    """

    buckets: tuple[float, ...] = _DEFAULT_BUCKETS
    counts: list[int] = field(default_factory=list)
    sum_total: float = 0.0
    count_total: int = 0

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = [0] * (len(self.buckets) + 1)  # +1 for +Inf

    def observe(self, value: float) -> None:
        v = max(float(value), 0.0)
        self.sum_total += v
        self.count_total += 1
        for i, upper in enumerate(self.buckets):
            if v <= upper:
                self.counts[i] += 1
        # +Inf bucket always increments
        self.counts[-1] += 1


# ---------------------------------------------------------------------------
# Telemetry registry
# ---------------------------------------------------------------------------


_LabelKey = tuple[tuple[str, str], ...]  # frozen sorted-tuple of (label, value)


def _label_key(labels: dict[str, str]) -> _LabelKey:
    return tuple(sorted(labels.items()))


def _format_labels(labels: _LabelKey) -> str:
    if not labels:
        return ""
    inside = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
    return "{" + inside + "}"


def _escape(value: str) -> str:
    return value.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


class AiTelemetry:
    """Thread-safe registry of AI metrics.

    Kept tiny on purpose. When the org introduces an actual metrics
    library (prometheus_client, statsd, opentelemetry-metrics), one
    re-implementation of :class:`AiTelemetry` swaps the backend without
    touching call sites.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # counter[metric_name][label_key] = float
        self._counters: dict[str, dict[_LabelKey, float]] = defaultdict(dict)
        # histogram[metric_name][label_key] = Histogram
        self._histograms: dict[str, dict[_LabelKey, Histogram]] = defaultdict(dict)
        # gauge[metric_name][label_key] = float
        self._gauges: dict[str, dict[_LabelKey, float]] = defaultdict(dict)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def inc(self, metric: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        if value < 0:
            return
        key = _label_key(labels or {})
        with self._lock:
            self._counters[metric][key] = self._counters[metric].get(key, 0.0) + float(value)

    def observe(self, metric: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = _label_key(labels or {})
        with self._lock:
            h = self._histograms[metric].get(key)
            if h is None:
                h = Histogram()
                self._histograms[metric][key] = h
            h.observe(value)

    def set_gauge(self, metric: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = _label_key(labels or {})
        with self._lock:
            self._gauges[metric][key] = float(value)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """JSON-friendly snapshot. Used by :get-route /api/v1/ai/metrics."""
        with self._lock:
            return {
                "counters": {
                    metric: [
                        {"labels": dict(k), "value": v} for k, v in series.items()
                    ]
                    for metric, series in self._counters.items()
                },
                "histograms": {
                    metric: [
                        {
                            "labels": dict(k),
                            "count": h.count_total,
                            "sum": h.sum_total,
                            "buckets": [
                                {"le": str(b), "count": h.counts[i]}
                                for i, b in enumerate(h.buckets)
                            ]
                            + [{"le": "+Inf", "count": h.counts[-1]}],
                        }
                        for k, h in series.items()
                    ]
                    for metric, series in self._histograms.items()
                },
                "gauges": {
                    metric: [
                        {"labels": dict(k), "value": v} for k, v in series.items()
                    ]
                    for metric, series in self._gauges.items()
                },
            }

    def render_prometheus(self) -> str:
        """Render the current state in Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            for metric, series in sorted(self._counters.items()):
                lines.append(f"# TYPE {metric} counter")
                for k, v in series.items():
                    lines.append(f"{metric}{_format_labels(k)} {v}")
            for metric, series in sorted(self._histograms.items()):
                lines.append(f"# TYPE {metric} histogram")
                for k, h in series.items():
                    base_labels = list(k)
                    for i, upper in enumerate(h.buckets):
                        bl = tuple(base_labels + [("le", str(upper))])
                        lines.append(f"{metric}_bucket{_format_labels(bl)} {h.counts[i]}")
                    bl = tuple(base_labels + [("le", "+Inf")])
                    lines.append(f"{metric}_bucket{_format_labels(bl)} {h.counts[-1]}")
                    lines.append(f"{metric}_sum{_format_labels(k)} {h.sum_total}")
                    lines.append(f"{metric}_count{_format_labels(k)} {h.count_total}")
            for metric, series in sorted(self._gauges.items()):
                lines.append(f"# TYPE {metric} gauge")
                for k, v in series.items():
                    lines.append(f"{metric}{_format_labels(k)} {v}")
        return "\n".join(lines) + ("\n" if lines else "")

    def reset(self) -> None:
        """Test helper — drops every series."""
        with self._lock:
            self._counters.clear()
            self._histograms.clear()
            self._gauges.clear()


# Process-global registry.
ai_telemetry = AiTelemetry()


# ---------------------------------------------------------------------------
# OpenTelemetry shim (soft dependency)
# ---------------------------------------------------------------------------


_otel_tracer: Any | None = None
try:  # pragma: no cover — optional dep
    from opentelemetry import trace as _otel_trace

    _otel_tracer = _otel_trace.get_tracer("sbom.ai")
except Exception:  # noqa: BLE001
    _otel_tracer = None


@contextlib.contextmanager
def generate_span(
    *,
    provider: str,
    model: str,
    purpose: str,
    request_id: str,
    cache_hit: bool = False,
) -> Iterator[Any]:
    """Open a span for an AI generation.

    Yields a span object when OTel is installed, ``None`` otherwise. Call
    sites use the context manager unconditionally — the absence of OTel is
    invisible to them.
    """
    if _otel_tracer is None:
        yield None
        return
    with _otel_tracer.start_as_current_span(  # pragma: no cover — exercised only when OTel is installed
        "ai.generate",
        attributes={
            "ai.provider": provider,
            "ai.model": model,
            "ai.purpose": purpose,
            "ai.request_id": request_id,
            "ai.cache_hit": cache_hit,
        },
    ) as span:
        yield span


# ---------------------------------------------------------------------------
# Structured logger (Phase 5 §5.2)
# ---------------------------------------------------------------------------


def hash_response(text: str | None) -> str:
    """SHA-256 of the response body. Zero-length response → empty string.

    Hashing (not logging) the body lets us correlate with provider audit
    logs without leaking the raw content. Joining is cheap: log greps
    return the hash, the operator hashes the suspect text, the match is
    instant.
    """
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def log_ai_call(
    *,
    request_id: str,
    provider: str,
    model: str,
    purpose: str,
    finding_cache_key: str | None,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    latency_ms: int,
    cache_hit: bool,
    outcome: Literal["ok", "schema_parse_failed", "provider_error", "budget_exceeded", "circuit_open", "cache_hit"],
    response_text: str | None = None,
    error: str | None = None,
) -> None:
    """Emit one structured audit log line for an AI call.

    Hard rule from prompt §5.2: NEVER log the full response body. We log
    a hash + byte count so debugging stays possible without exfiltrating
    user data.
    """
    audit_log.info(
        "ai.call",
        extra={
            "ai_event": "ai.call",
            "request_id": request_id,
            "provider": provider,
            "model": model,
            "purpose": purpose,
            "finding_cache_key": finding_cache_key,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": float(cost_usd),
            "latency_ms": int(latency_ms),
            "cache_hit": bool(cache_hit),
            "outcome": outcome,
            "response_sha256": hash_response(response_text),
            "response_bytes": len(response_text or ""),
            "error": error[:240] if error else None,
        },
    )


# ---------------------------------------------------------------------------
# High-level recorders the orchestrator uses
# ---------------------------------------------------------------------------


def record_call(
    *,
    provider: str,
    model: str,
    purpose: str,
    outcome: str,
    latency_seconds: float,
    cost_usd: float,
    cache_hit: bool,
) -> None:
    """One call site for every metric the orchestrator emits per AI call."""
    base = {"provider": provider, "purpose": purpose}
    ai_telemetry.inc("ai_request_total", {**base, "outcome": outcome})
    if cache_hit:
        ai_telemetry.inc("ai_request_total", {**base, "outcome": "cache_hit"})
    ai_telemetry.observe("ai_request_latency_seconds", latency_seconds, {**base, "model": model})
    if cost_usd > 0:
        ai_telemetry.inc("ai_cost_usd_total", base, value=cost_usd)


def update_cache_hit_ratio(*, hits: int, total: int) -> None:
    if total <= 0:
        ai_telemetry.set_gauge("ai_cache_hit_ratio", 0.0)
        return
    ai_telemetry.set_gauge("ai_cache_hit_ratio", round(hits / total, 4))


def update_budget_remaining(*, remaining_usd: float | None) -> None:
    if remaining_usd is None:
        return
    ai_telemetry.set_gauge("ai_budget_remaining_daily_usd", max(remaining_usd, 0.0))


def record_throughput(*, latency_ms: int) -> None:
    ai_telemetry.observe("ai_batch_finding_latency_seconds", max(latency_ms, 0) / 1000.0)


__all__ = [
    "AiTelemetry",
    "ai_telemetry",
    "generate_span",
    "hash_response",
    "log_ai_call",
    "record_call",
    "record_throughput",
    "update_budget_remaining",
    "update_cache_hit_ratio",
]
