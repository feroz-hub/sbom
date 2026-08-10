"""AI Security Copilot — portfolio-grounded executive briefing + Q&A.

Two capabilities, both grounded in a compact JSON snapshot assembled
EXCLUSIVELY from ``app.metrics`` functions (no direct ``analysis_finding``
/ ``analysis_run`` queries here — CLAUDE.md rule, enforced by the
metric-consistency test):

* **briefing** — a ≤250-word markdown executive summary of the current
  security posture. Cached in-process keyed on the metrics invalidation
  tuple (max run id, run count, sbom count) with a 6h TTL — a new run
  landing busts it immediately, otherwise the LLM is not re-billed.
* **ask** — one-shot natural-language Q&A over the same snapshot. Never
  cached (questions vary), always budget-guarded.

Cost discipline mirrors the AI-fix path: pre-flight
``BudgetGuard.check_request`` with a worst-case estimate, post-call
``record`` + ``write_usage_log_row`` (purposes ``copilot_briefing`` /
``copilot_ask``) so the admin usage dashboard sees every call. Provider
errors bubble as ``AiProviderError`` subclasses for the router to map.

The model is instructed to use ONLY the snapshot numbers. The snapshot is
small (≈1–2k tokens) and contains no SBOM file contents, no component
inventory dumps, and no credentials — the same privacy posture as the
fix-generation grounding context.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .. import metrics
from ..db import SessionLocal
from ..metrics.cache import invalidation_key
from .cost import BudgetGuard, estimate_cost_usd, estimate_tokens, write_usage_log_row
from .fix_generator import _budget_caps_from_settings
from .providers.base import LlmRequest
from .registry import get_registry

# Briefing cache: {invalidation_key: (monotonic_ts, payload)}.
_BRIEFING_TTL_SECONDS = 6 * 3600
_briefing_cache: dict[tuple, tuple[float, dict]] = {}
_briefing_lock = threading.Lock()

_MAX_QUESTION_CHARS = 500
_BRIEFING_MAX_TOKENS = 700
_ASK_MAX_TOKENS = 500

_BRIEFING_SYSTEM = """You are the AI Security Copilot embedded in an SBOM vulnerability-analysis dashboard.
You receive a JSON snapshot of the organisation's current security posture. Every number you state MUST come from that snapshot — never invent CVE ids, counts, or trends.

Write an executive briefing in markdown, 250 words maximum:
1. One bold opening line: the posture verdict (calm, factual, no alarmism).
2. 3-5 short bullets: the most decision-relevant insights, each citing concrete snapshot numbers (KEV first if non-zero, then exploitation outlook, SLA breaches, trajectory).
3. A "**Do next:**" line with the top 1-3 actions, most urgent first.

If `forecast.insufficient_history` is true, do not discuss trajectory. If `exploitation.coverage` is low (<0.5), caveat the probability. Plain language; no headers other than bold; no preamble."""

_ASK_SYSTEM = """You are the AI Security Copilot embedded in an SBOM vulnerability-analysis dashboard.
Answer the analyst's question using ONLY the JSON snapshot provided. Cite concrete numbers. If the snapshot cannot answer the question, say so in one line and name the dashboard view or filter that can (e.g. run detail, compare, schedules). Maximum 180 words. Markdown allowed, no headers."""


def build_portfolio_snapshot(db: Session) -> dict:
    """Compact, metrics-only state-of-the-world the LLM is grounded in."""
    severity = metrics.findings_latest_per_sbom_severity_distribution(db)
    net = metrics.findings_net_change(db, days=7)
    forecast = metrics.findings_forecast(db)
    outlook = metrics.portfolio_exploitation_outlook(db)
    remediation = metrics.remediation_summary(db)
    risk_map = metrics.portfolio_risk_map(db)

    return {
        "as_of": datetime.now(UTC).isoformat(timespec="seconds"),
        "portfolio": {
            "total_sboms": int(metrics.sboms_total(db)),
            "sboms_analysed": int(metrics.sboms_analysed_total(db)),
            "active_projects": int(metrics.projects_active_total(db)),
            "total_findings_latest": int(metrics.findings_latest_per_sbom_total(db)),
            "distinct_vulnerabilities": int(metrics.findings_latest_per_sbom_distinct_vulnerabilities(db)),
            "severity": severity,
            "kev_findings": int(metrics.findings_kev_in_scope(db, scope="latest_per_sbom")),
            "high_epss_findings": int(metrics.findings_high_epss_in_scope(db, scope="latest_per_sbom")),
            "fix_available": int(metrics.findings_latest_per_sbom_fix_available(db)),
            "needs_review": int(metrics.findings_needs_review_in_scope(db, scope="latest_per_sbom")),
        },
        "net_7day": {
            "added": net.added,
            "resolved": net.resolved,
            "is_first_period": net.is_first_period,
        },
        "forecast": {
            "insufficient_history": forecast["insufficient_history"],
            "current_total": forecast["current_total"],
            "projected_total_in_14d": forecast["projected_total"],
            "slope_per_day": forecast["slope_per_day"],
            "r_squared": forecast["r_squared"],
            "days_to_zero": forecast["days_to_zero"],
            "anomaly": forecast["anomaly"],
        },
        "exploitation": {
            "probability_30d": outlook["probability_30d"],
            "coverage": outlook["coverage"],
            "kev_cves": outlook["kev_cves"],
            "top_drivers": outlook["top_drivers"][:3],
        },
        "remediation": {
            "mttr_days": remediation["mttr_days"],
            "sla_overdue": remediation["sla"]["overdue"],
            "sla_due_soon": remediation["sla"]["due_soon"],
            "worst_offenders": remediation["sla"]["worst_offenders"][:3],
            "velocity_30d": remediation["velocity"],
        },
        "top_risk_sboms": [
            {
                "name": i["name"],
                "findings": i["findings_total"],
                "dominant_severity": i["dominant"],
            }
            for i in risk_map["items"][:5]
        ],
    }


async def generate_briefing(db: Session, *, force: bool = False) -> dict:
    """Executive briefing, cached on the metrics invalidation tuple."""
    inv = invalidation_key(db)
    now = time.time()
    if not force:
        with _briefing_lock:
            hit = _briefing_cache.get(inv)
            if hit is not None and (now - hit[0]) < _BRIEFING_TTL_SECONDS:
                return {**hit[1], "cached": True}

    snapshot = build_portfolio_snapshot(db)
    db.close()  # Close session early before external provider call!

    result = await _call_llm(
        system=_BRIEFING_SYSTEM,
        user=json.dumps(snapshot, separators=(",", ":")),
        purpose="copilot_briefing",
        max_output_tokens=_BRIEFING_MAX_TOKENS,
    )
    payload = {
        "briefing": result["text"],
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "provider": result["provider"],
        "model": result["model"],
        "cost_usd": result["cost_usd"],
        "cached": False,
        "schema_version": 1,
    }
    with _briefing_lock:
        _briefing_cache[inv] = (now, payload)
        # Bounded: drop oldest entries beyond a handful of snapshots.
        while len(_briefing_cache) > 8:
            oldest = min(_briefing_cache, key=lambda k: _briefing_cache[k][0])
            _briefing_cache.pop(oldest, None)
    return payload


async def answer_question(db: Session, question: str) -> dict:
    """One-shot grounded Q&A. Never cached; always budget-guarded."""
    q = (question or "").strip()[:_MAX_QUESTION_CHARS]
    if not q:
        raise ValueError("question must not be empty")
    snapshot = build_portfolio_snapshot(db)
    db.close()  # Close session early before external provider call!

    user = "SNAPSHOT:\n" + json.dumps(snapshot, separators=(",", ":")) + "\n\nQUESTION: " + q
    result = await _call_llm(
        system=_ASK_SYSTEM,
        user=user,
        purpose="copilot_ask",
        max_output_tokens=_ASK_MAX_TOKENS,
    )
    return {
        "answer": result["text"],
        "question": q,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "provider": result["provider"],
        "model": result["model"],
        "cost_usd": result["cost_usd"],
        "schema_version": 1,
    }


async def _call_llm(*, system: str, user: str, purpose: str, max_output_tokens: int) -> dict:
    """Shared provider call: pre-flight budget, generate, record, ledger."""
    with SessionLocal() as db:
        registry = get_registry(db)
        provider = registry.get_default()
        model = provider.default_model

        guard = BudgetGuard(_budget_caps_from_settings(), db)
        estimated = estimate_cost_usd(
            provider=provider.name,
            model=model,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=max_output_tokens,
        )
        guard.check_request(estimated_usd=estimated)

    request_id = uuid.uuid4().hex
    started = time.monotonic()
    response = await provider.generate(
        LlmRequest(
            system=system,
            user=user,
            max_output_tokens=max_output_tokens,
            temperature=0.2,
            request_id=request_id,
            purpose=purpose,
        )
    )
    latency_ms = int((time.monotonic() - started) * 1000)

    actual_cost = float(response.usage.cost_usd or 0.0)
    with SessionLocal() as db:
        guard = BudgetGuard(_budget_caps_from_settings(), db)
        guard.record(actual_usd=actual_cost)
        write_usage_log_row(
            db,
            request_id=request_id,
            provider=response.provider,
            model=response.model,
            purpose=purpose,
            finding_cache_key=None,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cost_usd=actual_cost,
            latency_ms=latency_ms,
            cache_hit=False,
        )
        db.commit()

    return {
        "text": response.text.strip(),
        "provider": response.provider,
        "model": response.model,
        "cost_usd": actual_cost,
    }


def reset_briefing_cache() -> None:
    """Test seam."""
    with _briefing_lock:
        _briefing_cache.clear()


__all__ = [
    "build_portfolio_snapshot",
    "generate_briefing",
    "answer_question",
    "reset_briefing_cache",
]
