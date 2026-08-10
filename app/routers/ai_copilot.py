"""AI Security Copilot endpoints.

Routes:
  GET  /api/ai/copilot/briefing   cached executive briefing (?force=true regenerates)
  POST /api/ai/copilot/ask        one-shot grounded Q&A {"question": "..."}

Gating mirrors the AI-fixes rollout gate (kill switch → master flag →
canary) so the Copilot never outlives an AI shutdown. Costs flow through
the same BudgetGuard + ai_usage_log ledger as fix generation (purposes
``copilot_briefing`` / ``copilot_ask``) — visible on /admin/ai-usage.

Error contract (matches the FE's typed AI error handling):
  402-ish budget breach   → 429 {error_code: "AI_BUDGET_EXCEEDED"}
  provider failure        → 502 {error_code: "AI_PROVIDER_ERROR"}
  feature disabled        → 403/404 via the rollout gate
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..ai.copilot import answer_question, generate_briefing
from ..ai.providers.base import AiProviderError, BudgetExceededError
from ..ai.rollout import evaluate_access
from ..db import get_db

log = logging.getLogger("sbom.api.ai_copilot")

router = APIRouter(prefix="/api/ai/copilot", tags=["ai-copilot"])


class AskBody(BaseModel):
    question: str = Field(..., min_length=1, max_length=500)


def _require_copilot_enabled() -> None:
    """Same rollout gate as AI fixes — Copilot is part of the AI surface."""
    access = evaluate_access(rollout_key=None)
    if access.allowed:
        return
    raise HTTPException(
        status_code=access.http_status,
        detail={"error_code": "AI_FIXES_DISABLED", "message": access.message},
    )


@router.get("/briefing")
async def copilot_briefing(
    force: bool = Query(False, description="Bypass the cached briefing."),
    db: Session = Depends(get_db),
):
    """Executive briefing over the portfolio snapshot (cached ≤6h per data state)."""
    _require_copilot_enabled()
    try:
        return await generate_briefing(db, force=force)
    except BudgetExceededError as exc:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "AI_BUDGET_EXCEEDED", "message": str(exc)},
        ) from exc
    except AiProviderError as exc:
        log.warning("copilot.briefing provider failure: %s", exc)
        raise HTTPException(
            status_code=502,
            detail={"error_code": "AI_PROVIDER_ERROR", "message": str(exc)},
        ) from exc


@router.post("/ask")
async def copilot_ask(body: AskBody, db: Session = Depends(get_db)):
    """Grounded one-shot Q&A. No cache; every call is budget-guarded."""
    _require_copilot_enabled()
    try:
        return await answer_question(db, body.question)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "AI_BUDGET_EXCEEDED", "message": str(exc)},
        ) from exc
    except AiProviderError as exc:
        log.warning("copilot.ask provider failure: %s", exc)
        raise HTTPException(
            status_code=502,
            detail={"error_code": "AI_PROVIDER_ERROR", "message": str(exc)},
        ) from exc
