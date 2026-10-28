"""Shared event boundary for report generation from stored analysis data."""

import logging
import time
from contextlib import contextmanager

from app.logger import log_context, log_event


@contextmanager
def report_generation(logger, *, report_type, **ids):
    """Keep exception behavior intact and emit only caller-selected aggregates."""
    started_at = time.perf_counter()
    summary = {}
    with log_context(**ids):
        log_event(logger, "report_generation_started", report_type=report_type, **ids)
        try:
            yield summary
        except Exception:
            log_event(
                logger,
                "report_generation_failed",
                level=logging.ERROR,
                exc_info=True,
                report_type=report_type,
                duration_ms=int((time.perf_counter() - started_at) * 1000),
                **ids,
            )
            raise
        else:
            log_event(
                logger,
                "report_generation_completed",
                report_type=report_type,
                duration_ms=int((time.perf_counter() - started_at) * 1000),
                **ids,
                **summary,
            )
