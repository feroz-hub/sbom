"""
Bearer-token authentication dependency.

Finding A from the Project Lens audit closed the largest unmitigated risk
in the codebase: every backend route was reachable unauthenticated. This
module adds an opt-in bearer-token allowlist that ops enables in
production by setting two env vars:

    API_AUTH_MODE=bearer
    API_AUTH_TOKENS=tok-abc,tok-def

Default mode is ``none`` so existing dev environments are not broken.

Design notes
------------
* The dependency is applied at router-include time in ``app/main.py`` via
  ``dependencies=[Depends(require_auth)]``. One diff = the whole posture
  changes. ``health.py`` is intentionally excluded so liveness probes
  and the FastAPI ``/docs`` page remain reachable.
* Token comparison uses ``hmac.compare_digest`` to avoid timing-attack
  leaks on the equality check. The set membership lookup also goes
  through ``compare_digest`` rather than a plain ``in`` operator.
* When ``API_AUTH_MODE=bearer`` is set but ``API_AUTH_TOKENS`` is empty,
  ``validate_auth_setup()`` raises at startup. Better to refuse to start
  than silently let every request through.
* The dependency does not look at the ``user_id`` query param — that's a
  ``created_by`` filter for soft ownership, an orthogonal concern.
* We read ``os.environ`` directly (not via ``app.settings.get_settings``)
  because the project does not currently install ``pydantic-settings``,
  so ``BaseSettings`` silently falls back to plain ``BaseModel`` and
  Field defaults — no env loading happens. The Settings fields for
  ``api_auth_mode`` / ``api_auth_tokens`` exist as documentation only.
  Future work: install ``pydantic-settings`` and route every settings
  read through one place.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Optional

from fastapi import Header, HTTPException, status

log = logging.getLogger(__name__)


_BEARER_PREFIX = "bearer "  # case-insensitive prefix per RFC 6750


def _read_mode() -> str:
    """Read ``API_AUTH_MODE`` from the live process env, normalised."""
    return (os.getenv("API_AUTH_MODE") or "none").strip().lower() or "none"


def _read_tokens() -> set[str]:
    """Parse ``API_AUTH_TOKENS`` from the live process env into a set."""
    raw = os.getenv("API_AUTH_TOKENS") or ""
    return {t.strip() for t in raw.split(",") if t.strip()}


class AuthConfigError(RuntimeError):
    """Raised at startup if API_AUTH_MODE='bearer' but no tokens are configured."""


def validate_auth_setup() -> None:
    """
    Called from the FastAPI startup hook. Refuses to let the app come up
    in a state where ``API_AUTH_MODE=bearer`` is set but no tokens are
    configured — that combination would otherwise silently let every
    request through, which is the worst possible failure mode.
    """
    mode = _read_mode()
    if mode == "none":
        log.warning(
            "API_AUTH_MODE=none — every /api/*, /analyze-*, /dashboard/* "
            "endpoint is reachable without authentication. This is fine "
            "for local development but MUST be set to 'bearer' in any "
            "shared environment.",
        )
        return
    if mode != "bearer":
        raise AuthConfigError(
            f"Unsupported API_AUTH_MODE='{os.getenv('API_AUTH_MODE')}'. "
            "Expected 'none' or 'bearer'."
        )
    tokens = _read_tokens()
    if not tokens:
        raise AuthConfigError(
            "API_AUTH_MODE='bearer' is set but API_AUTH_TOKENS is empty. "
            "Configure at least one token (comma-separated) before starting "
            "the server, or set API_AUTH_MODE='none' for unauthenticated mode."
        )
    log.info(
        "Bearer authentication enabled (%d token%s configured).",
        len(tokens),
        "s" if len(tokens) != 1 else "",
    )


def _token_in_allowlist(presented: str, allowlist: set[str]) -> bool:
    """
    Constant-time membership check.

    A plain ``presented in allowlist`` would short-circuit on the first
    matching prefix and leak timing information. Iterating with
    ``hmac.compare_digest`` against every entry costs O(N) per request,
    but N is tiny (a handful of tokens) and the safety wins.
    """
    presented_bytes = presented.encode("utf-8")
    matched = False
    for candidate in allowlist:
        if hmac.compare_digest(presented_bytes, candidate.encode("utf-8")):
            matched = True
            # Don't early-exit — keep the comparison work constant.
    return matched


def require_auth(authorization: Optional[str] = Header(default=None)) -> None:
    """
    FastAPI dependency that enforces the configured auth mode.

    Mode ``none``: this is a no-op. The dependency still runs (FastAPI
    needs *something* to plumb in via ``Depends``) but it always passes,
    so the routes are wide open and the per-request cost is a single
    settings lookup.

    Mode ``bearer``: requires a valid ``Authorization: Bearer <token>``
    header. Missing header → 401 with ``WWW-Authenticate: Bearer``.
    Malformed header → 401 with the same challenge. Unknown token →
    401 with the same challenge. We deliberately do NOT distinguish
    between "no header" / "wrong format" / "unknown token" in the
    response body to avoid handing an attacker a discriminator.
    """
    mode = _read_mode()
    if mode == "none":
        return
    if mode != "bearer":
        # validate_auth_setup() catches this at startup, but defend in
        # depth in case someone calls require_auth in isolation (e.g. tests).
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server auth misconfigured",
        )

    challenge = {"WWW-Authenticate": 'Bearer realm="sbom-analyzer"'}

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers=challenge,
        )

    if not authorization.lower().startswith(_BEARER_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers=challenge,
        )

    presented = authorization[len(_BEARER_PREFIX):].strip()
    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers=challenge,
        )

    if not _token_in_allowlist(presented, _read_tokens()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers=challenge,
        )
    # Authenticated — fall through.
