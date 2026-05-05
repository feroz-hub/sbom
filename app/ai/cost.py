"""Token counting, cost calculation, and budget enforcement.

Two responsibilities:

1. **Pricing** — per-provider, per-model dollars-per-1k-token tables. These
   are hardcoded constants because (a) they change quarterly and (b) we
   want them visible in code review when they do. Each entry carries the
   source URL and the date it was last verified — when in doubt, follow
   the link and update.
2. **BudgetGuard** — enforces the three-level cap (per-request,
   per-scan, per-day) BEFORE the call lands at the provider, so no token
   is ever consumed past the cap.

Token counting is a heuristic, not exact: real tokenisers (``tiktoken``,
``anthropic.tokenizers``) live behind optional imports because we don't
want to hard-pin them to the runtime. The fallback is the well-known
"4 characters ≈ 1 token" approximation, which is correct enough for cost
*estimation* (the actual ``input_tokens`` returned by the provider is what
gets logged to the ledger).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime
from threading import Lock
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .providers.base import BudgetExceededError

log = logging.getLogger("sbom.ai.cost")


# ---------------------------------------------------------------------------
# Pricing table
# ---------------------------------------------------------------------------
# Sources (last verified 2026-04-30 — re-check each quarter):
#   * Anthropic: https://www.anthropic.com/pricing#api
#   * OpenAI:    https://openai.com/api/pricing/
#   * Ollama:    self-hosted, $0
#   * vLLM:      self-hosted, $0
# Prices are in USD per 1,000 tokens. ``None`` for either side means "we
# don't have a price for this model — bill it as zero and log a warning".
# Local providers list every model at $0 explicitly to make the intent
# unmistakable in code review.

ModelPricing = dict[str, tuple[float, float]]  # model_name -> (input_per_1k, output_per_1k)

PRICING: dict[str, ModelPricing] = {
    "anthropic": {
        "claude-opus-4-7": (0.015, 0.075),
        "claude-opus-4-6": (0.015, 0.075),
        "claude-sonnet-4-6": (0.003, 0.015),
        "claude-sonnet-4-5": (0.003, 0.015),
        "claude-haiku-4-5": (0.0008, 0.004),
        "claude-haiku-4-5-20251001": (0.0008, 0.004),
    },
    "openai": {
        "gpt-4o": (0.0025, 0.010),
        "gpt-4o-mini": (0.00015, 0.00060),
        "gpt-4.1": (0.0025, 0.010),
        "gpt-4.1-mini": (0.00015, 0.00060),
    },
    # Gemini — paid-tier pricing per 1k tokens (Flash / Pro / Lite).
    # Source: https://ai.google.dev/pricing (verified 2026-05-04).
    # Free-tier usage is reported as $0.00 — the registry passes
    # ``is_local=False`` but the actual call's ``cost_usd`` lands at the
    # paid-tier rate; operators on free tier should treat the recorded
    # cost as a "what this would have cost on paid" projection.
    "gemini": {
        "gemini-2.5-flash": (0.000075, 0.0003),
        "gemini-2.5-flash-lite": (0.0000375, 0.00015),
        "gemini-2.5-pro": (0.00125, 0.005),
    },
    # Grok — xAI public pricing (verified 2026-05-04).
    "grok": {
        "grok-2-mini": (0.0002, 0.001),
        "grok-2": (0.002, 0.010),
        "grok-3": (0.005, 0.015),
    },
    "ollama": {},  # priced at zero by ``estimate_cost`` when provider.is_local
    "vllm": {},
    # Custom OpenAI-compatible endpoints carry no built-in pricing —
    # CustomOpenAiCompatibleProvider does its own cost math via the
    # caller-supplied per-1k rates.
    "custom_openai": {},
}


def estimate_cost_usd(
    *,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    is_local: bool = False,
) -> float:
    """Compute USD cost from the pricing table.

    Local providers (``is_local=True``) always cost $0. Unknown models on
    cloud providers cost $0 as well, but emit a warning so the operator
    notices the gap and updates the table.
    """
    if is_local:
        return 0.0
    table = PRICING.get(provider, {})
    pair = table.get(model)
    if pair is None:
        log.warning(
            "ai.cost.unknown_model: provider=%s model=%s — billed at $0; "
            "update PRICING in app/ai/cost.py",
            provider,
            model,
        )
        return 0.0
    in_rate, out_rate = pair
    return round((input_tokens / 1000.0) * in_rate + (output_tokens / 1000.0) * out_rate, 6)


# ---------------------------------------------------------------------------
# Token counting (heuristic)
# ---------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    """Cheap heuristic: ``ceil(len / 4)``.

    Used only for *pre-call* cost estimation (budget enforcement). The
    actual token count comes from the provider response and is what gets
    written to the ledger. Tightening this with a real BPE tokeniser is a
    Phase 5 follow-up — buys us better budget accuracy, costs us a
    dependency.
    """
    if not text:
        return 0
    # Round up — better to over-estimate budget impact than under-.
    return (len(text) + 3) // 4


# ---------------------------------------------------------------------------
# Budget guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BudgetCaps:
    """Three-level budget configuration.

    All values are USD. Set any of them to ``None`` (caller's responsibility)
    to disable that level — the guard treats ``None`` as "no cap".
    """

    per_request_usd: float | None = 0.10
    per_scan_usd: float | None = 5.00
    per_day_org_usd: float | None = 50.00


class _DayCounter:
    """In-memory counter with daily roll-over.

    Backed by Redis would be the production answer; for Phase 1 we keep
    state in-process and re-hydrate from ``ai_usage_log`` on demand. The
    SSE / Celery worker share the same DB ledger so a missed in-memory
    increment never lets the cap be silently bypassed — see
    :meth:`BudgetGuard._spent_today_db`.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._date: date | None = None
        self._spent: float = 0.0

    def _maybe_roll(self) -> None:
        today = datetime.now(UTC).date()
        if self._date != today:
            self._date = today
            self._spent = 0.0

    def add(self, usd: float) -> float:
        with self._lock:
            self._maybe_roll()
            self._spent += float(usd)
            return self._spent

    def reset(self) -> None:
        with self._lock:
            self._date = None
            self._spent = 0.0

    def get(self) -> float:
        with self._lock:
            self._maybe_roll()
            return self._spent


class BudgetGuard:
    """Enforce per-request / per-scan / per-day caps before the LLM call.

    Usage::

        guard = BudgetGuard(caps, db)
        guard.check_request(estimated_usd=0.0042, scan_id=run_id)
        # … call LLM …
        guard.record(actual_usd=0.0041, scan_id=run_id)

    The guard is process-local. In a multi-worker deployment (Celery +
    Uvicorn) the day cap is best-effort: each worker tracks its own slice
    and reconciles via ``ai_usage_log`` once per ``recheck_seconds``. This
    is acceptable because the cap is a guardrail, not a billing system —
    the ledger remains authoritative.
    """

    def __init__(
        self,
        caps: BudgetCaps,
        db_session_factory: Any | None = None,
        *,
        recheck_seconds: float = 30.0,
    ) -> None:
        self._caps = caps
        self._db_session_factory = db_session_factory
        self._recheck_seconds = recheck_seconds
        self._counter = _DayCounter()
        self._scan_spend: dict[int, float] = {}
        self._lock = Lock()
        self._last_db_recheck: float = 0.0

    @property
    def caps(self) -> BudgetCaps:
        return self._caps

    def reset(self) -> None:
        """Test helper — clears in-memory state. Does not touch the DB."""
        self._counter.reset()
        with self._lock:
            self._scan_spend.clear()
            self._last_db_recheck = 0.0

    # ------------------------------------------------------------------
    # Pre-call check
    # ------------------------------------------------------------------

    def check_request(
        self,
        *,
        estimated_usd: float,
        scan_id: int | None = None,
    ) -> None:
        """Raise :class:`BudgetExceededError` if the estimated cost would breach a cap.

        ``estimated_usd`` is what :func:`estimate_cost_usd` returned given the
        prompt size and provider model. We use it as a worst-case upper
        bound — actual cost recorded by :meth:`record` is usually a touch
        lower.
        """
        if estimated_usd < 0:
            raise ValueError("estimated_usd cannot be negative")

        per_req = self._caps.per_request_usd
        if per_req is not None and estimated_usd > per_req:
            raise BudgetExceededError("per_request", per_req, estimated_usd)

        if scan_id is not None and self._caps.per_scan_usd is not None:
            current = self._scan_spend.get(scan_id, 0.0)
            if current + estimated_usd > self._caps.per_scan_usd:
                raise BudgetExceededError(
                    "per_scan",
                    self._caps.per_scan_usd,
                    current + estimated_usd,
                )

        day_cap = self._caps.per_day_org_usd
        if day_cap is not None:
            spent = self._spent_today()
            if spent + estimated_usd > day_cap:
                raise BudgetExceededError("per_day_org", day_cap, spent + estimated_usd)

    # ------------------------------------------------------------------
    # Post-call recording
    # ------------------------------------------------------------------

    def record(self, *, actual_usd: float, scan_id: int | None = None) -> None:
        """Apply the realised cost to in-memory counters.

        The DB ledger is the durable record — see :func:`write_usage_log_row`.
        This method only updates the fast-path counters used by future
        :meth:`check_request` calls in the same process.
        """
        if actual_usd < 0:
            return
        self._counter.add(actual_usd)
        if scan_id is not None:
            with self._lock:
                self._scan_spend[scan_id] = self._scan_spend.get(scan_id, 0.0) + float(actual_usd)
        # Update the daily-budget-remaining gauge so the Prometheus scrape
        # reflects the new headroom without waiting for the next ledger query.
        if self._caps.per_day_org_usd is not None:
            try:
                from .observability import update_budget_remaining

                update_budget_remaining(
                    remaining_usd=max(self._caps.per_day_org_usd - self._counter.get(), 0.0)
                )
            except Exception:  # noqa: BLE001 — telemetry failure must not break a successful call
                pass

    def spent_today(self) -> float:
        return self._spent_today()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _spent_today(self) -> float:
        """Return today's spend, periodically reconciling with the DB ledger."""
        now = datetime.now(UTC).timestamp()
        if (now - self._last_db_recheck) > self._recheck_seconds and self._db_session_factory is not None:
            try:
                db_total = self._spent_today_db()
                # Use whichever is larger — being conservative protects the cap.
                if db_total > self._counter.get():
                    self._counter._spent = db_total  # type: ignore[attr-defined]
                self._last_db_recheck = now
            except Exception as exc:
                log.debug("ai.cost.db_recheck_failed: %s", exc)
        return self._counter.get()

    def _spent_today_db(self) -> float:
        """Sum cost_usd from ai_usage_log for today (UTC). Returns 0.0 on any failure."""
        if self._db_session_factory is None:
            return 0.0
        try:
            from ..models import AiUsageLog
        except Exception:
            return 0.0
        today_iso = datetime.now(UTC).date().isoformat()
        with self._db_session_factory() as session:  # type: Session
            stmt = select(func.coalesce(func.sum(AiUsageLog.cost_usd), 0.0)).where(
                AiUsageLog.created_at >= today_iso
            )
            return float(session.execute(stmt).scalar() or 0.0)


# ---------------------------------------------------------------------------
# Ledger write
# ---------------------------------------------------------------------------


def write_usage_log_row(
    db: Session,
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
    cache_hit: bool = False,
    error: str | None = None,
) -> None:
    """Write a single row to ``ai_usage_log``.

    Errors here are swallowed (logged but never re-raised) — losing a row
    on a transient DB hiccup is preferable to failing a user-facing
    generate call after the LLM has already been billed.
    """
    try:
        from ..models import AiUsageLog

        row = AiUsageLog(
            request_id=request_id,
            provider=provider,
            model=model,
            purpose=purpose,
            finding_cache_key=finding_cache_key,
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            cost_usd=float(cost_usd),
            latency_ms=int(latency_ms),
            cache_hit=bool(cache_hit),
            error=error,
            created_at=datetime.now(UTC).isoformat(),
        )
        db.add(row)
        db.commit()
    except Exception as exc:  # noqa: BLE001 — see docstring
        log.warning(
            "ai.cost.ledger_write_failed: provider=%s model=%s cost=%s err=%s",
            provider,
            model,
            cost_usd,
            exc,
        )
        try:
            db.rollback()
        except Exception:
            pass
