"""Celery task: evaluate a Secure Component Advisor recommendation (NFR-SCA-004).

The API evaluates inline after creation, so a user sees candidates at once;
this task is the background path for re-evaluation and future automatic
triggers. It wraps the same idempotent service function:

* Idempotent / retry-safe — an item that is not OPEN or REVIEW_REQUIRED is
  returned unchanged, so a retried or duplicated message cannot create a
  second evaluation or a duplicate work item.
* Tenant-bound — runs under ``minimal_background_context(tenant_id)`` so the
  ORM tenant guards apply exactly as in a request.
* Correlated — the originating request's correlation id is carried through
  log context and stored on the work item.
"""

from __future__ import annotations

from celery import shared_task
from sqlalchemy.exc import OperationalError

from ..core.context import minimal_background_context, tenant_scope
from ..db import SessionLocal
from ..logger import get_logger, log_context, log_event
from ..services.component_advisor.recommendations.service import RecommendationNotFound, evaluate_recommendation

log = get_logger("sbom.component_advisor.tasks")


@shared_task(
    name="component_advisor.evaluate_recommendation",
    bind=True,
    acks_late=True,
    autoretry_for=(OperationalError,),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=3,
    ignore_result=True,
)
def evaluate_recommendation_task(self, recommendation_id: int, tenant_id: int, correlation_id: str | None = None) -> str:
    with tenant_scope(minimal_background_context(tenant_id)), log_context(tenant_id=tenant_id, request_id=correlation_id):
        with SessionLocal() as db:
            try:
                item = evaluate_recommendation(
                    db, tenant_id=tenant_id, recommendation_id=recommendation_id, correlation_id=correlation_id
                )
            except RecommendationNotFound:
                log_event(log, "recommendation.evaluation.skipped", recommendation_id=recommendation_id, reason="not_found")
                return "NOT_FOUND"
            db.commit()
            return item.status
