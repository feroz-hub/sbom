"""Reject requests whose body exceeds ``Settings.MAX_UPLOAD_BYTES``.

Defends two attack shapes:

  1. Honest oversize — client honestly declares ``Content-Length`` greater
     than the limit. Reject before any body bytes are read.

  2. Lying / chunked oversize — client omits or lies about
     ``Content-Length`` (typically ``Transfer-Encoding: chunked``). Body
     bytes are counted incrementally and the request is cut off as soon
     as the running total exceeds the limit.

Implementation notes
--------------------
* Pure-ASGI; no FastAPI / Starlette imports. Composes cleanly with the
  existing middleware stack in ``app/main.py``.
* ``GET`` / ``HEAD`` / ``OPTIONS`` / ``DELETE`` are pass-through. The
  project's DELETE routes carry no body — see Phase A discovery.
* When the limit is exceeded mid-stream, ``guarded_receive`` returns an
  ``http.disconnect`` to the inner app. Starlette's request reader
  raises ``ClientDisconnect`` in response. ``guarded_send`` swallows any
  partial response the inner app may emit, and the middleware then
  emits a 413 itself.
* The 413 envelope shape matches the project's existing structured
  error pattern: ``{"detail": {"code": "...", "message": "..."}}``.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)

ASGIApp = Callable[..., Awaitable[None]]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
Scope = dict[str, Any]


_BODY_TOO_LARGE_PAYLOAD = (
    b'{"detail":{"code":"payload_too_large",'
    b'"message":"Request body exceeds maximum allowed size."}}'
)

_METHODS_WITHOUT_BODY = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})


class MaxBodySizeMiddleware:
    """ASGI middleware that rejects oversize request bodies with 413."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._app = app
        self._max = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        if method in _METHODS_WITHOUT_BODY:
            await self._app(scope, receive, send)
            return

        # Shape 1: honest Content-Length oversize.
        for header_name, header_value in scope.get("headers", ()):
            if header_name == b"content-length":
                try:
                    declared = int(header_value)
                except (TypeError, ValueError):
                    declared = -1
                if declared > self._max:
                    log.warning(
                        "max_body: rejecting %s %s — declared Content-Length=%d > limit=%d",
                        method,
                        scope.get("path", "?"),
                        declared,
                        self._max,
                    )
                    await self._reject_413(send)
                    return
                break

        # Shape 2: streaming guard.
        state = {"total": 0, "rejected": False, "response_started": False}

        async def guarded_receive() -> dict[str, Any]:
            if state["rejected"]:
                # Tell the inner app the client gave up so its body
                # reader stops asking for more bytes.
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["total"] += len(message.get("body", b""))
                if state["total"] > self._max:
                    state["rejected"] = True
                    log.warning(
                        "max_body: rejecting %s %s — streamed %d bytes > limit=%d",
                        method,
                        scope.get("path", "?"),
                        state["total"],
                        self._max,
                    )
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: dict[str, Any]) -> None:
            if state["rejected"]:
                # Drop whatever the inner app tries to emit — we'll send
                # our own 413 once it has unwound.
                return
            if message["type"] == "http.response.start":
                state["response_started"] = True
            await send(message)

        try:
            await self._app(scope, guarded_receive, guarded_send)
        except Exception:
            if state["rejected"] and not state["response_started"]:
                await self._reject_413(send)
                return
            raise

        if state["rejected"] and not state["response_started"]:
            await self._reject_413(send)

    @staticmethod
    async def _reject_413(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_BODY_TOO_LARGE_PAYLOAD)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _BODY_TOO_LARGE_PAYLOAD})
