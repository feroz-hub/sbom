"""
Authentication dependency: none | bearer allowlist | JWT (HS256).

Reads ``API_AUTH_MODE`` from the environment each request so tests can
monkeypatch without cache issues. JWT parameters also come from
``get_settings()`` (pydantic-settings / .env).
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

import jwt
from fastapi import Header, HTTPException, status
from jwt import InvalidTokenError

log = logging.getLogger(__name__)

_BEARER_PREFIX = "bearer "


def _read_mode() -> str:
    return (os.getenv("API_AUTH_MODE") or "none").strip().lower() or "none"


def _read_tokens() -> set[str]:
    raw = os.getenv("API_AUTH_TOKENS") or ""
    return {t.strip() for t in raw.split(",") if t.strip()}


class AuthConfigError(RuntimeError):
    """Raised at startup if auth env is inconsistent."""


def _jwt_settings() -> tuple[str, str, str | None, str | None]:
    from .settings import get_settings

    s = get_settings()
    secret = (s.jwt_secret_key or os.getenv("JWT_SECRET_KEY") or "").strip()
    alg = (s.jwt_algorithm or "HS256").strip()
    aud = (s.jwt_audience or "").strip() or None
    iss = (s.jwt_issuer or "").strip() or None
    return secret, alg, aud, iss


def validate_auth_setup() -> None:
    mode = _read_mode()
    if mode == "none":
        log.warning(
            "API_AUTH_MODE=none — protected routes are open. Use bearer or jwt in production.",
        )
        return
    if mode == "bearer":
        tokens = _read_tokens()
        if not tokens:
            raise AuthConfigError(
                "API_AUTH_MODE='bearer' is set but API_AUTH_TOKENS is empty. "
                "Configure at least one token or set API_AUTH_MODE='none'."
            )
        log.info("Bearer authentication enabled (%d token(s)).", len(tokens))
        return
    if mode == "jwt":
        secret, _, _, _ = _jwt_settings()
        if not secret:
            raise AuthConfigError("API_AUTH_MODE='jwt' but jwt_secret_key / JWT_SECRET_KEY is empty.")
        log.info("JWT authentication enabled (algorithm from settings).")
        return
    raise AuthConfigError(
        f"Unsupported API_AUTH_MODE='{os.getenv('API_AUTH_MODE')}'. Expected 'none', 'bearer', or 'jwt'."
    )


def _token_in_allowlist(presented: str, allowlist: set[str]) -> bool:
    presented_bytes = presented.encode("utf-8")
    matched = False
    for candidate in allowlist:
        if hmac.compare_digest(presented_bytes, candidate.encode("utf-8")):
            matched = True
    return matched


def _decode_jwt(token: str) -> dict[str, Any]:
    secret, alg, aud, iss = _jwt_settings()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server auth misconfigured",
        )
    options = {"verify_signature": True, "verify_exp": True}
    kwargs: dict[str, Any] = {
        "algorithms": [alg],
        "options": options,
    }
    if aud:
        kwargs["audience"] = aud
    if iss:
        kwargs["issuer"] = iss
    try:
        return jwt.decode(token, secret, **kwargs)
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Bearer realm="sbom-analyzer"'},
        ) from None


def require_auth(authorization: str | None = Header(default=None)) -> None:
    mode = _read_mode()
    if mode == "none":
        return

    challenge_bearer = {"WWW-Authenticate": 'Bearer realm="sbom-analyzer"'}

    if mode == "bearer":
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers=challenge_bearer,
            )
        if not authorization.lower().startswith(_BEARER_PREFIX):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers=challenge_bearer,
            )
        presented = authorization[len(_BEARER_PREFIX) :].strip()
        if not presented or not _token_in_allowlist(presented, _read_tokens()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers=challenge_bearer,
            )
        return

    if mode == "jwt":
        if not authorization or not authorization.lower().startswith(_BEARER_PREFIX):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers=challenge_bearer,
            )
        token = authorization[len(_BEARER_PREFIX) :].strip()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers=challenge_bearer,
            )
        _decode_jwt(token)
        return

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Server auth misconfigured",
    )
