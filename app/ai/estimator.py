"""Free-tier-aware batch duration estimator.

Phase 1 §1.5: before a batch run on a free-tier provider, the user
should see an honest estimate of how long it will take. The frontend
calls :func:`estimate_batch_duration` (via the API), and surfaces a
warning when the estimate crosses the configured threshold.

The estimate composes:

  * **Cache hit ratio** — from the existing ledger telemetry. A 70%
    hit ratio means only 30% of findings actually call the LLM.
  * **Concurrency** — bounded by the provider's max_concurrent.
  * **Rate limit** — provider-level RPM. For free tiers this is the
    binding constraint; for paid tiers concurrency usually wins.
  * **Per-call latency** — fixed estimate based on tier
    (cloud-paid ~ 4s, cloud-free ~ 6s, local ~ 8s).

This is rough on purpose. The goal is "is this 90 seconds or 12
minutes?", not "exactly 8 minutes 23 seconds". The frontend rounds the
output to the nearest 30 seconds.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import get_catalog_entry


@dataclass(frozen=True)
class BatchDurationEstimate:
    """Output of :func:`estimate_batch_duration`.

    ``estimated_seconds`` is the wall-clock time. ``estimated_cost_usd``
    is the projected spend (zero on free tier). ``warning_recommended``
    is the trip-wire the UI uses to decide whether to surface the
    "this will take a while" modal.
    """

    findings_total: int
    findings_to_generate: int          # total - cached
    cached_count: int
    concurrency: int
    requests_per_minute: float
    estimated_seconds: int
    estimated_cost_usd: float
    bottleneck: str                    # "rate_limit", "concurrency", or "cache"
    warning_recommended: bool


# Phase 1 §1.5 — surface a warning above this threshold.
_WARNING_THRESHOLD_SECONDS = 5 * 60  # 5 minutes


def _per_call_latency_seconds(provider_name: str, tier: str, is_local: bool) -> float:
    """Heuristic average latency. Hand-tuned from staging telemetry."""
    if is_local:
        return 8.0
    if tier == "free":
        return 6.0
    return 4.0


def estimate_batch_duration(
    *,
    findings_total: int,
    cached_count: int,
    provider_name: str,
    tier: str = "paid",
    max_concurrent: int = 10,
    rate_per_minute: float | None = None,
    is_local: bool = False,
    avg_cost_per_finding_usd: float = 0.005,
) -> BatchDurationEstimate:
    """Compute the projected wall-clock duration for a batch run.

    The model: throughput is the *minimum* of (concurrency × per-call
    rate) and (rate-limit × 60 / 60), then total time is
    ``findings_to_generate / throughput_per_second``. The bottleneck
    is whichever side won the min().
    """
    if findings_total < 0:
        findings_total = 0
    cached_count = max(min(cached_count, findings_total), 0)
    to_generate = findings_total - cached_count

    if to_generate == 0:
        return BatchDurationEstimate(
            findings_total=findings_total,
            findings_to_generate=0,
            cached_count=cached_count,
            concurrency=max_concurrent,
            requests_per_minute=rate_per_minute or 0.0,
            estimated_seconds=0,
            estimated_cost_usd=0.0,
            bottleneck="cache",
            warning_recommended=False,
        )

    # Resolve the rate limit: explicit value wins; otherwise pull from
    # the static catalog entry (free-tier RPM); otherwise no limit.
    effective_rpm: float
    if rate_per_minute is not None and rate_per_minute > 0:
        effective_rpm = float(rate_per_minute)
    else:
        entry = get_catalog_entry(provider_name)
        if entry and entry.free_tier_rate_limit_rpm and tier == "free":
            effective_rpm = float(entry.free_tier_rate_limit_rpm)
        else:
            # Conservative default — no observed RPM, paid tier.
            effective_rpm = 1000.0

    per_call_s = _per_call_latency_seconds(provider_name, tier, is_local)
    # Concurrency-bound throughput (req/sec).
    concurrency_throughput = max_concurrent / per_call_s
    # Rate-limit throughput (req/sec).
    rate_throughput = effective_rpm / 60.0

    bottleneck = "concurrency" if concurrency_throughput <= rate_throughput else "rate_limit"
    throughput = min(concurrency_throughput, rate_throughput)
    if throughput <= 0:
        throughput = 1.0  # avoid division by zero on misconfiguration

    estimated_seconds = int(to_generate / throughput)
    cost = (
        0.0
        if (is_local or tier == "free")
        else round(to_generate * float(avg_cost_per_finding_usd), 4)
    )

    return BatchDurationEstimate(
        findings_total=findings_total,
        findings_to_generate=to_generate,
        cached_count=cached_count,
        concurrency=max_concurrent,
        requests_per_minute=effective_rpm,
        estimated_seconds=estimated_seconds,
        estimated_cost_usd=cost,
        bottleneck=bottleneck,
        warning_recommended=estimated_seconds > _WARNING_THRESHOLD_SECONDS,
    )


__all__ = ["BatchDurationEstimate", "estimate_batch_duration"]
