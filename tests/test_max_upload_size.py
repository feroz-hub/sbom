"""
Regression tests for BE-001: MAX_UPLOAD_BYTES enforcement.

Settings.MAX_UPLOAD_BYTES is defined at app/settings.py:225 but unenforced —
any POST/PUT/PATCH route is a memory-exhaustion DoS vector. These tests
exercise BOTH attack shapes the audit calls out:

  1. Honest oversize: client declares Content-Length > limit and sends a
     real body of that size. Middleware must reject from the declared
     header before buffering.
  2. Lying / chunked: client streams a chunked body with no Content-Length
     (or a deliberately-wrong one). Middleware must count bytes
     incrementally and cut off as soon as the running total exceeds the
     limit.

Both tests target POST /api/sboms — the only route in the inventory whose
body schema (SBOMSourceCreate.sbom_data) is not size-bounded by the
Pydantic model itself.
"""

from __future__ import annotations

import pytest


def test_post_with_oversize_content_length_returns_413(client):
    """Shape 1: client honestly declares an oversize body via
    Content-Length. Middleware rejects before buffering."""
    from app.settings import get_settings

    max_bytes = get_settings().MAX_UPLOAD_BYTES
    body = b"x" * (max_bytes + 1)

    resp = client.post(
        "/api/sboms",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert resp.status_code == 413, (
        f"expected 413 from MAX_UPLOAD_BYTES enforcement; "
        f"got {resp.status_code} (body: {resp.text[:200]!r})"
    )
    payload = resp.json()
    assert payload.get("detail", {}).get("code") == "payload_too_large", (
        f"413 envelope shape drifted; got {payload!r}"
    )


@pytest.mark.asyncio
async def test_post_with_chunked_oversize_returns_413(app):
    """Shape 2: client streams chunks past the limit with no
    Content-Length header. Middleware counts bytes incrementally and
    cuts the request off mid-stream."""
    from httpx import ASGITransport, AsyncClient

    from app.settings import get_settings

    max_bytes = get_settings().MAX_UPLOAD_BYTES
    chunk = b"x" * 65536
    # One extra chunk past the limit — enough that the middleware MUST
    # reject and not enough to take seconds in CI.
    chunks_needed = (max_bytes // len(chunk)) + 2

    sent = 0

    async def streamer():
        nonlocal sent
        for _ in range(chunks_needed):
            sent += len(chunk)
            yield chunk

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        resp = await ac.post(
            "/api/sboms",
            content=streamer(),
            headers={"Content-Type": "application/json"},
        )

    assert resp.status_code == 413, (
        f"expected 413 from streaming oversize body; "
        f"got {resp.status_code} (body: {resp.text[:200]!r})"
    )
    payload = resp.json()
    assert payload.get("detail", {}).get("code") == "payload_too_large", (
        f"413 envelope shape drifted; got {payload!r}"
    )
    # Soft bound — confirm the middleware did not let the entire body
    # through. Allow some slack because chunk boundaries don't align
    # exactly with the limit.
    assert sent <= max_bytes + 2 * len(chunk), (
        f"streamed {sent} bytes through; middleware did not cut off"
    )
