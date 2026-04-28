"""Global exception handlers — convert unhandled exceptions into a
canonical, non-leaky 500 envelope while preserving full server-side logs.

Existing FastAPI ``HTTPException`` handling (which carries intentional
client-facing detail for 4xx) is preserved by *not* registering a
handler for ``HTTPException`` itself. Pydantic's ``RequestValidationError``
is likewise left to FastAPI's default 422 handler. Only unhandled
``Exception`` is intercepted.

Each rejection emits a short hex correlation ID in BOTH the response
body and the server log, so an operator who receives a user-reported
``correlation_id`` can grep the logs for the matching exception and
stack trace without having ever exposed that information to the
client.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)


def install(app: FastAPI) -> None:
    """Register the unhandled-Exception → canonical 500 handler."""

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = uuid.uuid4().hex[:12]
        log.exception(
            "unhandled error: method=%s path=%s correlation_id=%s",
            request.method,
            request.url.path,
            correlation_id,
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": {
                    "code": "internal_error",
                    "message": "Internal server error.",
                    "correlation_id": correlation_id,
                }
            },
        )
