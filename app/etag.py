"""Small helpers for conditional GET (ETag) on JSON responses."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import Request, Response


def maybe_not_modified(request: Request, response: Response, payload: dict[str, Any], max_age: int = 5):
    """
    If If-None-Match matches the payload ETag, return a 304 Response.
    Otherwise attach ETag + Cache-Control and return None so the caller
    returns the payload normally.
    """
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    etag = hashlib.sha256(body).hexdigest()[:24]
    tag = f'"{etag}"'
    inm = (request.headers.get("if-none-match") or "").strip()
    if inm == tag:
        return Response(status_code=304)
    response.headers["ETag"] = tag
    response.headers["Cache-Control"] = f"private, max-age={max_age}"
    return None
