"""Logging boundaries for SBOM and VEX workflows; never serialize input bodies.

Keep exception handling and transactions in the wrapped workflow. Outcomes are
emitted only after it returns, including validation failures returned with HTTP
200 and permanent deletions awaiting a caller-owned transaction commit.
"""

from __future__ import annotations

import inspect
import logging
from contextlib import contextmanager
from functools import wraps
from time import perf_counter

from fastapi import HTTPException

from app.core.context import CurrentContext, get_bound_context
from app.logger import log_context, log_event


def _result_summary(result, kind):
    # Reading __dict__ avoids lazy ORM loads merely to enrich a log record.
    values = result if isinstance(result, dict) else getattr(result, "__dict__", {})
    fields = {}
    for key in ("tenant_id", "project_id", "product_id", "sbom_id"):
        if isinstance(values.get(key), int):
            fields[key] = values[key]
    if kind == "sbom":
        if isinstance(values.get("id"), int):
            fields["sbom_id"] = values["id"]
        if isinstance(values.get("projectid"), int):
            fields["project_id"] = values["projectid"]
    if kind == "validation":
        if isinstance(values.get("imported_sbom_id"), int):
            fields["sbom_id"] = values["imported_sbom_id"]
        report = values.get("latest_error_report") or values.get("latest_error_report_json") or {}
        for key in ("error_count", "warning_count"):
            if isinstance(report.get(key), int):
                fields[key] = report[key]
    for key in (
        "error_count", "warning_count", "components", "file_size_bytes",
        "statements_imported", "matched_statements", "unmatched_statements",
        "discovered_documents", "cascaded_count",
    ):
        if isinstance(values.get(key), int):
            fields[key] = values[key]
    outcome = "completed"
    if kind == "validation" and (
        fields.get("error_count", 0) > 0
        or values.get("validation_status") in {"failed", "security_blocked", "unsupported_format"}
    ):
        outcome = "failed"
    elif kind == "discovery" and values.get("errors"):
        fields["error_count"] = len(values["errors"])
        outcome = "partial"
    elif kind == "delete":
        if values.get("status") == "pending_confirmation":
            outcome = "pending_confirmation"
        if isinstance(values.get("permanent"), bool):
            fields["permanent"] = values["permanent"]
        if isinstance(values.get("deleted_sbom_ids"), list):
            fields["deleted_sbom_count"] = len(values["deleted_sbom_ids"])
    elif kind == "activation" and values.get("status") == "already_active":
        outcome = "unchanged"
    return outcome, fields


def workflow_event(event: str, *, result_kind: str = "", completed_event: str | None = None, expected_errors: tuple = ()):
    """Observe sync/async workflow results without changing their contracts.

    Only trusted context IDs and explicitly selected numeric aggregates are
    logged. Actor labels, exception detail, filenames, URLs and payloads are
    intentionally excluded. Framework dependency failures occur before this
    boundary and remain owned by request logging.
    """
    def decorate(func):
        signature = inspect.signature(func, eval_str=True)
        logger = logging.getLogger(func.__module__)

        @contextmanager
        def observe(args, kwargs):
            arguments = signature.bind(*args, **kwargs).arguments
            context = arguments.get("context")
            if not isinstance(context, CurrentContext):
                context = get_bound_context()
            ids = {}
            if context is not None:
                ids.update(tenant_id=context.tenant_id, user_id=context.user_id)
            owner = arguments.get("self")
            tenant_id = getattr(owner, "_tenant_id", None) or getattr(owner, "tenant_id", None)
            if isinstance(tenant_id, int):
                ids["tenant_id"] = tenant_id
            for key in ("sbom_id", "project_id", "product_id"):
                if isinstance(arguments.get(key), int):
                    ids[key] = arguments[key]
            started = perf_counter()
            with log_context(**{key: value for key, value in ids.items() if value is not None}):
                log_event(logger, f"{event}_started")
                try:
                    yield arguments, started
                except Exception as exc:
                    status = exc.status_code if isinstance(exc, HTTPException) else None
                    expected = (status is not None and status < 500) or isinstance(exc, expected_errors)
                    log_event(
                        logger, f"{event}_failed",
                        level=logging.WARNING if expected else logging.ERROR,
                        exc_info=True,
                        error_type=type(exc).__name__,
                        **({"status_code": status} if status is not None else {}),
                        duration_ms=round((perf_counter() - started) * 1000, 2),
                    )
                    raise

        def completed(result, arguments, started):
            outcome, fields = _result_summary(result, result_kind)
            if arguments.get("commit") is False and outcome == "completed":
                outcome = "prepared"
            log_event(
                logger, completed_event if outcome == "completed" and completed_event else f"{event}_{outcome}",
                level=logging.WARNING if outcome in {"failed", "partial"} else logging.INFO,
                operation=event,
                duration_ms=round((perf_counter() - started) * 1000, 2),
                **fields,
            )

        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def wrapped(*args, **kwargs):
                with observe(args, kwargs) as (arguments, started):
                    result = await func(*args, **kwargs)
                    completed(result, arguments, started)
                    return result
        else:
            @wraps(func)
            def wrapped(*args, **kwargs):
                with observe(args, kwargs) as (arguments, started):
                    result = func(*args, **kwargs)
                    completed(result, arguments, started)
                    return result

        # Resolve postponed annotations in the original module for FastAPI.
        wrapped.__signature__ = signature
        return wrapped
    return decorate
