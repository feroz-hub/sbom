"""Phased-rollout gating for the AI fix generator.

Single decision point used by every endpoint that would trigger an AI
call. Composes the three layers in order:

  1. **Kill switch** (DB-first effective AI settings) — operator panic button.
     Reasons returned: ``kill_switch``.
  2. **Master flag** (DB-first effective setting, env migration fallback) — feature gate. Reasons:
     ``not_enabled``.
  3. **Canary sampling** (``AI_CANARY_PERCENTAGE`` ∈ [0, 100]) —
     deterministic hash of the rollout key (run / finding / user) decides
     whether this request is in the canary cohort. A given key produces
     the same decision for every call until the percentage changes, so
     users don't see flickering "AI available now / now it's not"
     behaviour as their requests are routed.

A request that passes returns :data:`AiAccess(allowed=True)`. A request
that's blocked carries the reason and a structured message the API layer
can echo into a 409 response.

Why not random sampling: random would route the same user to AI on one
click and not the next. Hash-based sampling is stable per-key and
trivially correct — bumping the percentage from 10 → 50 keeps the
already-included 10% in the cohort and adds the next 40%.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from ..settings import get_settings
from .providers.base import AiProviderError
from .runtime_config import get_effective_ai_config

AccessReason = Literal[
    "ok",
    "kill_switch",
    "not_enabled",
    "canary_excluded",
]


@dataclass(frozen=True)
class AiAccess:
    """Outcome of the rollout decision.

    ``allowed=False`` carries the reason so the API can pick an HTTP code
    and a CTA (e.g. "operator paused" vs "feature off" vs "you're in the
    canary control group").
    """

    allowed: bool
    reason: AccessReason
    message: str = ""

    @property
    def http_status(self) -> int:
        """HTTP status the API should return for this outcome."""
        return 200 if self.allowed else 409


class AiAccessDeniedError(AiProviderError):
    """Raised when runtime state changes after an API-level gate check."""

    def __init__(self, access: AiAccess) -> None:
        super().__init__(access.message)
        self.reason = access.reason
        self.http_status = access.http_status


def _canary_bucket(key: str) -> int:
    """Deterministic 0-99 bucket from the rollout key.

    SHA-256 (not Python's ``hash``) so the bucket is stable across
    process restarts and across deployments. The first 8 hex chars give
    32 bits of entropy — plenty for a 0-99 split.
    """
    if not key:
        return 0
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def evaluate_access(*, rollout_key: str | None = None, apply_canary: bool = True) -> AiAccess:
    """Apply every gate in order. ``rollout_key`` keys the canary hash.

    Operators always pass through the master + kill-switch gates. The
    canary sampling only runs when both upper gates pass.
    """
    effective = get_effective_ai_config()

    if effective.kill_switch_active:
        return AiAccess(
            allowed=False,
            reason="kill_switch",
            message="AI fixes are temporarily disabled by an operator.",
        )

    if not effective.feature_enabled:
        return AiAccess(
            allowed=False,
            reason="not_enabled",
            message="AI fix generation is not enabled for this deployment.",
        )

    # Canary rollout is intentionally infrastructure-controlled and applies
    # only to AI Fix generation. Copilot and validation repair call this
    # policy with ``apply_canary=False`` while still honoring the same master
    # enable and kill switch.
    if not apply_canary:
        return AiAccess(allowed=True, reason="ok")

    pct = max(0, min(100, int(get_settings().ai_canary_percentage)))
    if pct >= 100:
        return AiAccess(allowed=True, reason="ok")
    if pct <= 0:
        return AiAccess(
            allowed=False,
            reason="canary_excluded",
            message="AI fixes are in canary mode and not yet available for this deployment.",
        )

    # 0 < pct < 100 — sample by key.
    if not rollout_key:
        # No stable key supplied → fall back to "always allowed" once
        # past the master flag. This keeps internal admin tools working
        # while the percentage is still being ramped.
        return AiAccess(allowed=True, reason="ok")

    bucket = _canary_bucket(rollout_key)
    if bucket < pct:
        return AiAccess(allowed=True, reason="ok")
    return AiAccess(
        allowed=False,
        reason="canary_excluded",
        message=(
            f"AI fixes are currently rolled out to {pct}% of deployments. "
            "This request was not selected for the canary cohort."
        ),
    )


__all__ = ["AccessReason", "AiAccess", "AiAccessDeniedError", "evaluate_access"]
