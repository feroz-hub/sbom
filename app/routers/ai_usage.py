"""AI usage telemetry endpoints — read-only.

Backs the cost dashboard introduced in Phase 1. Aggregations come from
``ai_usage_log``; the endpoints expose them as small, cacheable JSON
payloads.

Path note: the prompt asked for ``app/api/v1/ai_usage.py``; the existing
codebase keeps routers under ``app/routers/`` and uses a router-level
``/api/v1`` prefix. Following that convention here means the route URL
matches the spec (``/api/v1/ai/usage``) without diverging from the wider
project layout.

Auth is applied at app level via ``require_auth`` (see
``app/main.py``), so these handlers stay focused on data shaping.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import Integer as sa_Integer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..ai.catalog import ProviderCatalogEntry, get_catalog_entry, list_catalog
from ..ai.cost import PRICING
from ..ai.observability import ai_telemetry
from ..ai.providers.base import ProviderInfo
from ..ai.registry import get_registry, reset_registry
from ..db import get_db
from ..models import AiFixCache, AiUsageLog
from ..settings import get_settings

log = logging.getLogger("sbom.routers.ai_usage")

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


# ---------------------------------------------------------------------------
# Response shapes
# ---------------------------------------------------------------------------


class AiUsageTotals(BaseModel):
    """Aggregate cost / call counts for a window."""

    window_days: int = Field(..., description="Window size used for the aggregation.")
    total_calls: int
    total_cache_hits: int
    cache_hit_ratio: float = Field(..., description="0.0-1.0; 0.0 when there are no calls.")
    total_cost_usd: float
    total_input_tokens: int
    total_output_tokens: int


class AiUsageBucket(BaseModel):
    """One row of a per-purpose / per-provider breakdown."""

    label: str
    calls: int
    cost_usd: float


class AiUsageSummary(BaseModel):
    """Top-level payload for the cost dashboard."""

    today: AiUsageTotals
    last_30_days: AiUsageTotals
    by_purpose: list[AiUsageBucket]
    by_provider: list[AiUsageBucket]
    budget_caps_usd: dict[str, float | None]
    spent_today_usd: float
    daily_remaining_usd: float | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _totals_for_window(db: Session, *, since_iso: str, window_days: int) -> AiUsageTotals:
    # Boolean SUM is dialect-portable — Postgres accepts SUM(bool::int) via
    # implicit cast and SQLite stores the column as INTEGER 0/1 already.
    base = select(
        func.count(AiUsageLog.id),
        func.coalesce(func.sum(AiUsageLog.cost_usd), 0.0),
        func.coalesce(func.sum(AiUsageLog.input_tokens), 0),
        func.coalesce(func.sum(AiUsageLog.output_tokens), 0),
        func.coalesce(func.sum(func.cast(AiUsageLog.cache_hit, sa_Integer())), 0),
    ).where(AiUsageLog.created_at >= since_iso)
    row = db.execute(base).one_or_none()
    calls = int(row[0] or 0) if row else 0
    cost = float(row[1] or 0.0) if row else 0.0
    in_tok = int(row[2] or 0) if row else 0
    out_tok = int(row[3] or 0) if row else 0
    hits = int(row[4] or 0) if row else 0
    ratio = (hits / calls) if calls else 0.0
    return AiUsageTotals(
        window_days=window_days,
        total_calls=calls,
        total_cache_hits=hits,
        cache_hit_ratio=round(ratio, 4),
        total_cost_usd=round(cost, 6),
        total_input_tokens=in_tok,
        total_output_tokens=out_tok,
    )


def _bucket_by(db: Session, *, since_iso: str, column) -> list[AiUsageBucket]:
    stmt = (
        select(
            column,
            func.count(AiUsageLog.id),
            func.coalesce(func.sum(AiUsageLog.cost_usd), 0.0),
        )
        .where(AiUsageLog.created_at >= since_iso)
        .group_by(column)
        .order_by(func.coalesce(func.sum(AiUsageLog.cost_usd), 0.0).desc())
    )
    return [
        AiUsageBucket(label=str(label or "unknown"), calls=int(calls or 0), cost_usd=round(float(cost or 0.0), 6))
        for (label, calls, cost) in db.execute(stmt).all()
    ]


def _today_iso() -> str:
    return datetime.now(UTC).date().isoformat()


def _days_ago_iso(days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).date().isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/usage", response_model=AiUsageSummary)
def get_ai_usage(db: Session = Depends(get_db)) -> AiUsageSummary:
    """Aggregate spend, call counts, cache-hit ratio, and budget headroom."""
    today_iso = _today_iso()
    last30_iso = _days_ago_iso(30)

    today = _totals_for_window(db, since_iso=today_iso, window_days=1)
    last30 = _totals_for_window(db, since_iso=last30_iso, window_days=30)
    by_purpose = _bucket_by(db, since_iso=last30_iso, column=AiUsageLog.purpose)
    by_provider = _bucket_by(db, since_iso=last30_iso, column=AiUsageLog.provider)

    s = get_settings()
    caps = {
        "per_request_usd": float(s.ai_budget_per_request_usd),
        "per_scan_usd": float(s.ai_budget_per_scan_usd),
        "per_day_org_usd": float(s.ai_budget_per_day_org_usd),
    }
    spent_today = today.total_cost_usd
    daily_remaining = (
        max(caps["per_day_org_usd"] - spent_today, 0.0) if caps["per_day_org_usd"] is not None else None
    )

    return AiUsageSummary(
        today=today,
        last_30_days=last30,
        by_purpose=by_purpose,
        by_provider=by_provider,
        budget_caps_usd=caps,
        spent_today_usd=round(spent_today, 6),
        daily_remaining_usd=daily_remaining,
    )


@router.get("/providers", response_model=list[ProviderInfo])
def list_providers(db: Session = Depends(get_db)) -> list[ProviderInfo]:
    """Public metadata for the Settings page provider selector."""
    return get_registry(db).list_available()


class PricingEntry(BaseModel):
    provider: str
    model: str
    input_per_1k_usd: float
    output_per_1k_usd: float


@router.get("/pricing", response_model=list[PricingEntry])
def list_pricing() -> list[PricingEntry]:
    """Static pricing table (sourced from each provider's docs).

    Useful for the cost-estimate UI ("~$0.005 · 3-8 seconds") on the
    "Generate AI remediation" CTA, before any LLM call has been made.
    """
    out: list[PricingEntry] = []
    for provider, models in PRICING.items():
        for model, (in_rate, out_rate) in models.items():
            out.append(
                PricingEntry(
                    provider=provider,
                    model=model,
                    input_per_1k_usd=in_rate,
                    output_per_1k_usd=out_rate,
                )
            )
    return out


@router.post("/registry/reset", status_code=204)
def reset_provider_registry() -> None:
    """Drop the cached provider registry. Picks up env / DB config changes.

    Phase 1 admin convenience — Phase 4 wires this behind the Settings UI's
    "Test connection" button.
    """
    reset_registry()


# ---------------------------------------------------------------------------
# Phase 5 telemetry surface
# ---------------------------------------------------------------------------


class TrendPoint(BaseModel):
    """One day in the cost trend sparkline."""

    day: str = Field(..., description="UTC date in YYYY-MM-DD")
    calls: int
    cost_usd: float
    cache_hits: int


class TrendResponse(BaseModel):
    days: int
    points: list[TrendPoint]


@router.get("/usage/trend", response_model=TrendResponse)
def get_usage_trend(
    days: int = Query(default=30, ge=1, le=180, description="Window length."),
    db: Session = Depends(get_db),
) -> TrendResponse:
    """Per-day cost / call / cache-hit series for the cost dashboard sparkline.

    Server aggregates by ``substr(created_at, 1, 10)`` (the YYYY-MM-DD prefix
    of the ISO-8601 timestamp). Portable across SQLite + Postgres, fast on
    the ``ix_ai_usage_log_created_at`` index.
    """
    since_iso = _days_ago_iso(days)
    day_expr = func.substr(AiUsageLog.created_at, 1, 10)
    rows = db.execute(
        select(
            day_expr.label("day"),
            func.count(AiUsageLog.id),
            func.coalesce(func.sum(AiUsageLog.cost_usd), 0.0),
            func.coalesce(func.sum(func.cast(AiUsageLog.cache_hit, sa_Integer())), 0),
        )
        .where(AiUsageLog.created_at >= since_iso)
        .group_by(day_expr)
        .order_by(day_expr)
    ).all()
    return TrendResponse(
        days=days,
        points=[
            TrendPoint(
                day=str(day),
                calls=int(calls or 0),
                cost_usd=round(float(cost or 0.0), 6),
                cache_hits=int(hits or 0),
            )
            for (day, calls, cost, hits) in rows
        ],
    )


class TopCachedItem(BaseModel):
    """One row of the "most expensive cached fixes" leaderboard."""

    cache_key: str
    vuln_id: str
    component_name: str
    component_version: str
    provider_used: str
    model_used: str
    total_cost_usd: float
    generated_at: str


@router.get("/usage/top-cached", response_model=list[TopCachedItem])
def get_top_cached_fixes(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[TopCachedItem]:
    """The N most expensive cache entries, sorted by ``total_cost_usd`` desc.

    Surfaces "most-expensive log4j (cached, $0.012)" style highlights on
    the dashboard. Cache entries are tenant-shared (Phase 2 §2.4), so this
    is org-wide.
    """
    rows = (
        db.execute(
            select(AiFixCache)
            .order_by(AiFixCache.total_cost_usd.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        TopCachedItem(
            cache_key=r.cache_key,
            vuln_id=r.vuln_id,
            component_name=r.component_name,
            component_version=r.component_version,
            provider_used=r.provider_used,
            model_used=r.model_used,
            total_cost_usd=float(r.total_cost_usd or 0.0),
            generated_at=r.generated_at,
        )
        for r in rows
    ]


@router.get("/metrics", response_model=None)
def get_metrics_json() -> dict:
    """JSON snapshot of every counter / histogram / gauge.

    Lighter than the Prometheus text format — suitable for the in-app
    dashboard which doesn't speak the exposition format.
    """
    return ai_telemetry.snapshot()


@router.get("/metrics/prometheus", response_class=PlainTextResponse)
def get_metrics_prometheus() -> str:
    """Prometheus text exposition format.

    Operators can point a Prometheus scraper at this endpoint without
    pulling in ``prometheus_client`` as a hard dep.
    """
    return ai_telemetry.render_prometheus()


# ---------------------------------------------------------------------------
# Phase 1 §1.4 — provider catalog (drives the Settings UI dropdown)
# ---------------------------------------------------------------------------


@router.get("/providers/available", response_model=list[ProviderCatalogEntry])
def get_provider_catalog() -> list[ProviderCatalogEntry]:
    """Static catalog of every provider the platform supports.

    The Settings page reads this to populate the "Add provider"
    dropdown, render provider-specific form fields (API key vs base
    URL), and surface free-tier rate limits.

    Distinct from ``/providers`` which reflects runtime *configured*
    providers — this endpoint reflects what's *available* regardless
    of current configuration.
    """
    return list_catalog()


@router.get("/providers/available/{name}", response_model=ProviderCatalogEntry)
def get_provider_catalog_entry(name: str) -> ProviderCatalogEntry:
    """Lookup one provider's catalog entry by name."""
    from fastapi import HTTPException

    entry = get_catalog_entry(name)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {name!r}")
    return entry
