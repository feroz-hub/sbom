"""Celery tasks — background SBOM analysis."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .celery_app import celery_app

log = logging.getLogger(__name__)


@celery_app.task(name="sbom_analyzer.run_sbom_analysis", bind=False)
def run_sbom_analysis(
    sbom_json: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run multi-source analysis in a worker process.

    Uses asyncio.run around the existing async pipeline entrypoint.
    """
    from app.pipeline.multi_source import run_multi_source_analysis_async

    log.info("Celery task run_sbom_analysis starting sources=%s", sources)
    result = asyncio.run(run_multi_source_analysis_async(sbom_json, sources=sources))
    log.info("Celery task run_sbom_analysis complete findings=%s", result.get("total_findings"))
    return result
