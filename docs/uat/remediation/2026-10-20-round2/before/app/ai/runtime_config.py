"""Canonical runtime access to effective AI controls.

Every external LLM consumer uses this module for feature state and budget
caps.  Database-backed Settings values are authoritative when the singleton
row exists; environment values are retained only as the migration/startup
fallback implemented by :mod:`app.ai.config_loader`.
"""

from __future__ import annotations

from .config_loader import get_loader
from .config_types import EffectiveAiConfig
from .cost import BudgetCaps, BudgetGuard


def get_effective_ai_config() -> EffectiveAiConfig:
    """Return the exact feature/kill-switch/budget snapshot runtime enforces."""
    return get_loader().resolve_settings()


def get_effective_budget_caps(*, per_scan_override_usd: float | None = None) -> BudgetCaps:
    config = get_effective_ai_config()
    return BudgetCaps(
        per_request_usd=config.budget_per_request_usd,
        per_scan_usd=(
            float(per_scan_override_usd)
            if per_scan_override_usd is not None
            else config.budget_per_scan_usd
        ),
        per_day_org_usd=config.budget_daily_usd,
    )


def build_budget_guard(*, per_scan_override_usd: float | None = None) -> BudgetGuard:
    """Build a durable-ledger guard with the canonical SQLAlchemy factory."""
    from ..db import SessionLocal

    return BudgetGuard(
        get_effective_budget_caps(per_scan_override_usd=per_scan_override_usd),
        db_session_factory=SessionLocal,
        # Always reconcile the durable tenant-scoped ledger before an
        # external call.  This keeps independently running API/worker
        # processes on the same daily cap snapshot.
        recheck_seconds=0.0,
    )


__all__ = [
    "build_budget_guard",
    "get_effective_ai_config",
    "get_effective_budget_caps",
]
