"""ASGI request logging, including streaming, early rejection and failures."""

from __future__ import annotations

import logging
import re
import secrets
import time

from starlette.datastructures import Headers, MutableHeaders

from app.logger import CONTEXT_FIELDS, get_logger, log_context, log_event

log = get_logger("access")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        supplied = headers.get("x-request-id") or headers.get("x-correlation-id") or ""
        request_id = supplied if _REQUEST_ID.fullmatch(supplied) else secrets.token_hex(6)
        state = scope.setdefault("state", {})
        state["request_id"] = state["correlation_id"] = request_id
        started = time.perf_counter()
        status_code = 500
        completed = False

        def emit(exc_info=False):
            nonlocal completed
            if completed:
                return
            completed = True
            ids = {k: v for k, v in scope.get("path_params", {}).items() if k in CONTEXT_FIELDS and k != "request_id"}
            context = state.get("current_context")
            if context is not None:
                ids.update({k: getattr(context, k, None) for k in ("tenant_id", "user_id")})
            log_event(
                log,
                "http_request_completed",
                level=logging.ERROR
                if exc_info or status_code >= 500
                else logging.WARNING
                if status_code >= 400
                else logging.INFO,
                exc_info=exc_info,
                request_id=request_id,
                method=scope["method"],
                path=scope.get("path", ""),
                status_code=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                **ids,
            )

        async def send_logged(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request_id
                response_headers["X-Correlation-ID"] = request_id
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                emit()

        with log_context(request_id=request_id):
            try:
                await self.app(scope, receive, send_logged)
            except Exception:
                if completed:
                    log_event(log, "http_background_task_failed", level=logging.ERROR, exc_info=True)
                else:
                    emit(exc_info=True)
                raise
            finally:
                # Also record a disconnected/cancelled request; never consume
                # or buffer request/response bodies for logging.
                if not completed:
                    emit()
