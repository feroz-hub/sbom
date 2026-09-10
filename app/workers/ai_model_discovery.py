"""Daily refresh of the persistent AI model registry."""

from __future__ import annotations

import asyncio
import logging

from celery import shared_task
from sqlalchemy import select

from ..ai.model_registry import refresh_models
from ..ai.providers.base import ModelDiscoveryError
from ..db import SessionLocal
from ..models import AiProviderCredential

log = logging.getLogger("sbom.workers.ai_model_discovery")


async def _refresh_enabled() -> dict[str, int]:
    counts = {"credentials": 0, "succeeded": 0, "failed": 0, "models": 0}
    with SessionLocal() as session:
        credentials = session.execute(
            select(AiProviderCredential)
            .where(AiProviderCredential.enabled.is_(True))
            .order_by(AiProviderCredential.id)
        ).scalars().all()
        counts["credentials"] = len(credentials)
        for credential in credentials:
            try:
                result = await refresh_models(session, credential)
            except ModelDiscoveryError as exc:
                session.rollback()
                counts["failed"] += 1
                log.warning(
                    "ai.model_refresh.failed provider=%s credential_id=%s kind=%s",
                    credential.provider_name,
                    credential.id,
                    exc.kind,
                )
            except Exception as exc:  # noqa: BLE001
                session.rollback()
                counts["failed"] += 1
                log.warning(
                    "ai.model_refresh.failed provider=%s credential_id=%s error_type=%s",
                    credential.provider_name,
                    credential.id,
                    type(exc).__name__,
                )
            else:
                counts["succeeded"] += 1
                counts["models"] += result.discovered
    return counts


@shared_task(name="ai_models.refresh_all")
def refresh_all_provider_models() -> dict[str, int]:
    """Refresh enabled provider credentials; one failure never stops others."""
    return asyncio.run(_refresh_enabled())


__all__ = ["refresh_all_provider_models"]
