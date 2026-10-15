"""Compatibility authentication adapters backed by the main security context.

Legacy binary configuration validation remains for explicit local development;
protected operations use database-authorized HCL, Native, or Entra identities.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from jwt import InvalidTokenError

from .core.context import CurrentContext
from .core.security import get_current_tenant_context

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

    Identity and canonical role names are supplied by the main authenticated
    database context. Client identity and role headers are never trusted.
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
    from .core.security import validate_auth_mode
    from .services.entra_auth_service import validate_configuration
    from .settings import get_settings
    validate_auth_mode()
    validate_configuration()
    if get_settings().native_auth_enabled:
        from .services.native_jwt_service import signing_key
        signing_key()
    if get_settings().auth_enabled:
        from .core.security import validate_hcl_auth_setup

        validate_hcl_auth_setup()
        log.info("Database-authorized authentication enabled.")
        return
    mode = _read_mode()
    if mode == "none":
        log.warning(
            "AUTH_ENABLED=false — explicit local development identity enabled; production requires AUTH_ENABLED=true.",
        )
        return
    if mode == "bearer":
        tokens = _read_tokens()
        if not tokens:
            raise AuthConfigError(
                "API_AUTH_MODE='bearer' is set but API_AUTH_TOKENS is empty. "
                "Configure at least one token or set API_AUTH_MODE='none'."
            )
        log.info("Legacy bearer configuration validated (%d token(s)); main context governs protected routes.", len(tokens))
        return
    if mode == "jwt":
        secret, _, _, _ = _jwt_settings()
        if not secret:
            raise AuthConfigError("API_AUTH_MODE='jwt' but jwt_secret_key / JWT_SECRET_KEY is empty.")
        log.info("Legacy JWT configuration validated; main context governs protected routes.")
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
    options = {"verify_signature": True, "verify_exp": True, "require": ["sub", "exp"]}
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


def require_auth(
    context: CurrentContext = Depends(get_current_tenant_context),
) -> None:
    """Compatibility dependency: always use the main authenticated database context."""
    return None


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
    context: CurrentContext = Depends(get_current_tenant_context),
) -> Principal:
    """Legacy principal adapter; identity and roles come only from trusted context."""
    return Principal(user_id=context.actor_label(), roles=frozenset(role.lower() for role in context.roles))


def require_roles(*allowed_roles: str) -> Callable[[Principal], Principal]:
    allowed = {role.lower() for role in allowed_roles}

    def _dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if principal.has_any_role(allowed):
            return principal
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for this action")

    return _dependency
