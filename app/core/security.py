from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..models import IAMUser

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from jwt import InvalidTokenError, PyJWKClient
from sqlalchemy.orm import Session

from ..db import get_db
from ..settings import get_settings
from .context import CurrentContext, bind_context, reset_context
from .permissions import normalize_role

AUTH_CHALLENGE = {"WWW-Authenticate": 'Bearer realm="sbom-analyzer"'}


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers=AUTH_CHALLENGE,
    )


def _claim(claims: dict[str, Any], path: str) -> Any:
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _roles(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        values = value.replace(";", ",").split(",")
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = []
    return frozenset(normalize_role(str(item)) for item in values if str(item).strip())


@lru_cache(maxsize=8)
def _cached_jwks_client(url: str, lifespan: int) -> PyJWKClient:
    return PyJWKClient(
        url,
        cache_keys=True,
        cache_jwk_set=True,
        lifespan=lifespan,
    )


def get_jwks_client() -> PyJWKClient:
    settings = get_settings()
    url = settings.hcl_iam_jwks_url.strip()
    if not url:
        raise RuntimeError("HCL_IAM_JWKS_URL is required when AUTH_ENABLED=true")
    return _cached_jwks_client(url, settings.hcl_iam_jwks_cache_seconds)


def validate_hcl_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    algorithms = [value.strip() for value in settings.hcl_iam_allowed_algorithms.split(",") if value.strip()]
    if not algorithms or any(value.upper().startswith("HS") for value in algorithms):
        raise RuntimeError("HCL IAM must use configured asymmetric JWT algorithms")
    try:
        signing_key = get_jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=algorithms,
            issuer=settings.hcl_iam_issuer,
            audience=settings.hcl_iam_audience,
            options={
                "require": ["exp", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except (InvalidTokenError, ValueError):
        raise _unauthorized() from None
    if not isinstance(claims.get("sub"), str) or not claims["sub"].strip():
        raise _unauthorized()
    for optional in ("email", "name"):
        if claims.get(optional) is not None and not isinstance(claims[optional], str):
            raise _unauthorized()
    return claims


def get_current_claims(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.auth_enabled:
        return {
            "sub": "dev-user",
            "email": "dev@local",
            "name": "Dev User",
            settings.hcl_iam_role_claim: ["TENANT_ADMIN"],
            settings.hcl_iam_tenant_claim: "default",
        }
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _unauthorized()
    token = authorization[7:].strip()
    if not token:
        raise _unauthorized()
    return validate_hcl_token(token)


get_current_user = get_current_claims


_CONTEXT_CACHE = {}
_CACHE_LOCK = threading.Lock()


def _get_cached_context(claims: dict[str, Any], x_tenant_id: str | None) -> CurrentContext | None:
    sub = claims.get("sub")
    if not sub:
        return None
    iat = claims.get("iat")
    key = (sub, x_tenant_id, iat)
    now = time.time()
    with _CACHE_LOCK:
        cached = _CONTEXT_CACHE.get(key)
        if cached:
            expires_at, context = cached
            if now < expires_at:
                return context
            else:
                _CONTEXT_CACHE.pop(key, None)
    return None


def _set_cached_context(claims: dict[str, Any], x_tenant_id: str | None, context: CurrentContext) -> None:
    sub = claims.get("sub")
    if not sub:
        return
    iat = claims.get("iat")
    key = (sub, x_tenant_id, iat)
    now = time.time()
    settings = get_settings()
    expires_at = now + float(settings.auth_context_cache_seconds)
    exp = claims.get("exp")
    if exp:
        try:
            expires_at = min(expires_at, float(exp))
        except (ValueError, TypeError):
            pass
    with _CACHE_LOCK:
        _CONTEXT_CACHE[key] = (expires_at, context)


def _upsert_user(db: Session, claims: dict[str, Any]) -> tuple[IAMUser, bool]:
    from ..services import tenant_service

    return tenant_service.get_or_create_user_from_claims(db, claims)


def _resolve_context(
    db: Session,
    claims: dict[str, Any],
    selected_tenant: str | None,
) -> CurrentContext:
    from ..services import tenant_service

    settings = get_settings()
    user, needs_commit = _upsert_user(db, claims)
    token_roles = _roles(_claim(claims, settings.hcl_iam_role_claim))
    memberships = tenant_service.get_user_memberships(db, user.id)
    tenant_claim = _claim(claims, settings.hcl_iam_tenant_claim)

    selected, membership, roles, permissions, is_platform_admin = tenant_service.resolve_active_tenant(
        db,
        user,
        memberships,
        selected_tenant=selected_tenant,
        tenant_claim=tenant_claim,
        token_roles=token_roles,
        auth_enabled=settings.auth_enabled,
    )

    if needs_commit:
        db.commit()
    return CurrentContext(
        user_id=user.id,
        external_user_id=user.external_iam_user_id,
        email=user.email,
        display_name=user.display_name,
        tenant_id=selected.id,
        external_tenant_id=selected.external_iam_tenant_id,
        roles=roles,
        permissions=permissions,
        is_platform_admin=is_platform_admin,
    )


def get_current_tenant_context(
    request: Request = None,
    claims: dict[str, Any] = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> Iterator[CurrentContext]:
    cached = _get_cached_context(claims, x_tenant_id)
    if cached is not None:
        db.close()
        token = bind_context(cached)
        try:
            yield cached
        finally:
            reset_context(token)
        return

    context = _resolve_context(db, claims, x_tenant_id)
    _set_cached_context(claims, x_tenant_id, context)

    if request is not None and "/stream" in request.url.path:
        db.close()
    token = bind_context(context)
    try:
        yield context
    finally:
        reset_context(token)


def require_permission(permission: str) -> Callable:
    def dependency(
        context: CurrentContext = Depends(get_current_tenant_context),
    ) -> CurrentContext:
        if context.has_permission(permission):
            return context
        raise HTTPException(status_code=403, detail="Insufficient permission")

    return dependency


def require_role(*roles: str) -> Callable:
    expected = {normalize_role(role) for role in roles}

    def dependency(
        context: CurrentContext = Depends(get_current_tenant_context),
    ) -> CurrentContext:
        if context.roles & expected:
            return context
        raise HTTPException(status_code=403, detail="Insufficient role")

    return dependency


def permission_for_request(request: Request) -> str:
    path = request.url.path
    method = request.method.upper()
    if path.startswith("/api/nvd-mirror"):
        return "platform:admin"
    if path.startswith("/dashboard"):
        return "dashboard:read"
    if "/vex" in path:
        return "vex:read" if method == "GET" else "vex:write"
    if path.startswith("/api/remediation"):
        return "remediation:read" if method == "GET" else "remediation:write"
    if "lifecycle" in path:
        return "lifecycle:read" if method == "GET" else "lifecycle:override"
    if "schedule" in path:
        return "schedule:read" if method == "GET" else "schedule:write"
    if path.startswith("/api/projects"):
        return {
            "GET": "project:read",
            "POST": "project:create",
            "PATCH": "project:update",
            "PUT": "project:update",
            "DELETE": "project:delete",
        }.get(method, "project:read")
    if (
        path.startswith("/api/sbom-validation-sessions")
        or path.startswith("/api/validation-sessions")
        or path.startswith("/api/sbom-workspaces")
    ):
        if method == "GET":
            if path.endswith("/download-original") or path.endswith("/download-repair-draft"):
                return "sbom:repair:download"
            if path.endswith("/search"):
                return "sbom:repair:search"
            return "sbom:repair:read"
        if path.endswith("/validate") or path.endswith("/revalidate") or path.endswith("/import"):
            return "sbom:repair:revalidate"
        return "sbom:repair:update"
    if path.startswith("/api/sboms"):
        if method == "GET":
            return "sbom:export" if any(part in path for part in ("/export", "/reports/")) else "sbom:read"
        if method == "DELETE":
            return "sbom:delete"
        if path.endswith("/workspace"):
            return "sbom:repair:update"
        if method == "POST" and (path.endswith("/upload") or path == "/api/sboms"):
            return "sbom:upload"
        if "/analyze" in path:
            return "analysis:run"
        return "sbom:update"
    if path.startswith("/api/runs") or path.startswith("/api/analysis"):
        return "analysis:read" if method == "GET" else "analysis:run"
    if path == "/api/auth/me" or path == "/api/tenants":
        return "dashboard:read" if method == "GET" else "tenant:settings:update"
    if path.startswith("/api/tenants"):
        return "tenant:user:read" if method == "GET" else "tenant:user:update"
    return "dashboard:read" if method == "GET" else "tenant:settings:update"


def enforce_request_access(
    request: Request,
    context: CurrentContext = Depends(get_current_tenant_context),
) -> CurrentContext:
    permission = permission_for_request(request)
    if not context.has_permission(permission):
        raise HTTPException(status_code=403, detail="Insufficient permission")
    request.state.current_context = context
    return context


def validate_hcl_auth_setup() -> None:
    settings = get_settings()
    if not settings.auth_enabled:
        return
    required = {
        "HCL_IAM_ISSUER": settings.hcl_iam_issuer,
        "HCL_IAM_AUDIENCE": settings.hcl_iam_audience,
        "HCL_IAM_JWKS_URL": settings.hcl_iam_jwks_url,
        "HCL_IAM_CLIENT_ID": settings.hcl_iam_client_id,
    }
    missing = [name for name, value in required.items() if not value.strip()]
    if missing:
        raise RuntimeError(f"HCL IAM configuration missing: {', '.join(missing)}")
    if not settings.hcl_iam_jwks_url.lower().startswith("https://") and not os.getenv("PYTEST_CURRENT_TEST"):
        raise RuntimeError("HCL_IAM_JWKS_URL must use HTTPS")
