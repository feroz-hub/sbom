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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, status
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


@dataclass(frozen=True)
class Principal:
    """Authenticated caller identity used for narrow role checks.

    The project historically had binary auth only. This principal is a
    lightweight bridge: JWT deployments can carry roles in claims, bearer
    deployments can pass trusted gateway role headers, and local
    ``API_AUTH_MODE=none`` remains permissive for developer/test parity.
    """

    user_id: str | None
    roles: frozenset[str]

    def has_any_role(self, allowed: set[str]) -> bool:
        return bool({role.lower() for role in self.roles} & {role.lower() for role in allowed})


def _jwt_settings() -> tuple[str, str, str | None, str | None]:
    from .settings import get_settings

    s = get_settings()
    secret = (s.jwt_secret_key or os.getenv("JWT_SECRET_KEY") or "").strip()
    alg = (s.jwt_algorithm or "HS256").strip()
    aud = (s.jwt_audience or "").strip() or None
    iss = (s.jwt_issuer or "").strip() or None
    return secret, alg, aud, iss


def validate_auth_setup() -> None:
    from .settings import get_settings

    if get_settings().auth_enabled:
        from .core.security import validate_hcl_auth_setup

        validate_hcl_auth_setup()
        log.info("HCL IAM JWT/JWKS authentication enabled.")
        return
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


def _roles_from_value(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        parts = value.replace(";", ",").replace(" ", ",").split(",")
        return frozenset(part.strip().lower() for part in parts if part.strip())
    if isinstance(value, (list, tuple, set)):
        roles: set[str] = set()
        for item in value:
            roles.update(_roles_from_value(item))
        return frozenset(roles)
    return frozenset()


def get_current_principal(
    authorization: str | None = Header(default=None),
    x_sbom_user: str | None = Header(default=None, alias="X-SBOM-User"),
    x_sbom_roles: str | None = Header(default=None, alias="X-SBOM-Roles"),
) -> Principal:
    """Return the current caller with best-effort role information.

    ``require_auth`` remains the global guard. This helper is intentionally
    additive and is only wired to sensitive routes that need role semantics.
    """

    mode = _read_mode()
    header_roles = _roles_from_value(x_sbom_roles)

    if mode == "none":
        return Principal(
            user_id=x_sbom_user or "local-dev",
            roles=header_roles or frozenset({"admin", "security"}),
        )

    if mode == "bearer":
        if not authorization or not authorization.lower().startswith(_BEARER_PREFIX):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        presented = authorization[len(_BEARER_PREFIX) :].strip()
        if not presented or not _token_in_allowlist(presented, _read_tokens()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        return Principal(user_id=x_sbom_user or "bearer", roles=header_roles or frozenset({"viewer"}))

    if mode == "jwt":
        if not authorization or not authorization.lower().startswith(_BEARER_PREFIX):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        claims = _decode_jwt(authorization[len(_BEARER_PREFIX) :].strip())
        claim_roles = (
            _roles_from_value(claims.get("roles"))
            or _roles_from_value(claims.get("role"))
            or _roles_from_value(claims.get("scope"))
        )
        return Principal(
            user_id=str(claims.get("sub") or claims.get("email") or x_sbom_user or "jwt"),
            roles=claim_roles or header_roles or frozenset({"viewer"}),
        )

    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server auth misconfigured")


def require_roles(*allowed_roles: str) -> Callable[[Principal], Principal]:
    allowed = {role.lower() for role in allowed_roles}

    def _dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if principal.has_any_role(allowed):
            return principal
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for this action")

    return _dependency
