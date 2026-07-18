from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request
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
log = logging.getLogger("sbom.auth")


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
    normalized = [normalize_role(str(item)) for item in values if str(item).strip()]
    try:
        configured = json.loads(get_settings().hcl_iam_role_mapping)
        mapping = {normalize_role(str(key)): normalize_role(str(result)) for key, result in configured.items()}
    except (ValueError, TypeError, AttributeError):
        mapping = {}
    return frozenset(mapping.get(role, role) for role in normalized)


def _ssl_context(ca_bundle: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_bundle or None)


@lru_cache(maxsize=8)
def _discovery(issuer: str, discovery_url: str, timeout: float, ca_bundle: str) -> dict[str, Any]:
    url = discovery_url or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context(ca_bundle)) as response:
        metadata = json.loads(response.read(1024 * 1024))
    if metadata.get("issuer") != issuer:
        raise RuntimeError("HCL IAM discovery issuer mismatch")
    jwks_url = str(metadata.get("jwks_uri") or "")
    issuer_url = urllib.parse.urlparse(issuer)
    jwks = urllib.parse.urlparse(jwks_url)
    if jwks.scheme != "https" or jwks.netloc != issuer_url.netloc:
        raise RuntimeError("HCL IAM discovery returned an untrusted JWKS endpoint")
    return metadata


@lru_cache(maxsize=8)
def _cached_jwks_client(url: str, lifespan: int, timeout: float, ca_bundle: str) -> PyJWKClient:
    return PyJWKClient(
        url,
        cache_keys=True,
        cache_jwk_set=True,
        lifespan=lifespan,
        timeout=timeout,
        ssl_context=_ssl_context(ca_bundle),
    )


def get_jwks_client() -> PyJWKClient:
    settings = get_settings()
    metadata = _discovery(
        settings.hcl_iam_issuer,
        settings.hcl_iam_discovery_url.strip(),
        settings.hcl_iam_http_timeout_seconds,
        settings.hcl_iam_ca_bundle.strip(),
    )
    discovered_url = str(metadata["jwks_uri"])
    configured_url = settings.hcl_iam_jwks_url.strip()
    if configured_url and configured_url != discovered_url:
        raise RuntimeError("HCL_IAM_JWKS_URL does not match discovery metadata")
    return _cached_jwks_client(
        discovered_url,
        settings.hcl_iam_jwks_cache_seconds,
        settings.hcl_iam_http_timeout_seconds,
        settings.hcl_iam_ca_bundle.strip(),
    )


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
                "require": ["iss", "sub", "aud", "exp"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_iat": True,
            },
            leeway=settings.hcl_iam_clock_skew_seconds,
        )
    except (InvalidTokenError, ValueError):
        raise _unauthorized() from None
    except Exception as exc:  # discovery/JWKS network and key-selection failures fail closed
        log.warning("hcl_iam_validation_unavailable: %s", type(exc).__name__)
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


def clear_authorization_cache() -> None:
    """Compatibility invalidator; authorization decisions no longer use this cache."""
    with _CACHE_LOCK:
        _CONTEXT_CACHE.clear()


def invalidate_user_contexts(user_id: int) -> None:
    """Remove any legacy cached contexts for one local IAM user."""
    with _CACHE_LOCK:
        keys = [key for key, (_expires, context) in _CONTEXT_CACHE.items() if context.user_id == user_id]
        for key in keys:
            _CONTEXT_CACHE.pop(key, None)


def _upsert_user(db: Session, claims: dict[str, Any]) -> tuple[IAMUser, bool]:
    from ..services import tenant_service

    return tenant_service.get_or_create_user_from_claims(db, claims)


def _resolve_context(
    db: Session,
    claims: dict[str, Any],
    selected_tenant: str | None,
    *,
    allow_platform_context: bool = False,
    request: Request | None = None,
) -> CurrentContext:
    from ..services import audit_service, platform_service, tenant_service

    settings = get_settings()
    user, needs_commit = _upsert_user(db, claims)
    identity_roles = _roles(_claim(claims, settings.hcl_iam_role_claim))
    if user.status != "ACTIVE":
        if needs_commit and user.status == "PENDING":
            audit_service.write_authorization_audit(
                db,
                action="iam.user.discovered",
                outcome="SUCCESS",
                target_user_id=user.id,
                request=request,
                new_value={"external_identity_linked": True},
            )
            audit_service.write_authorization_audit(
                db,
                action="iam.user.created_pending",
                outcome="SUCCESS",
                target_user_id=user.id,
                request=request,
                new_value={"status": "PENDING"},
            )
        audit_service.write_authorization_audit(
            db,
            action="authorization.denied.inactive_user",
            outcome="DENIED",
            target_user_id=user.id,
            request=request,
            detail="SBOM IAM user is not active",
        )
        db.commit()
        message = "SBOM access is pending administrator approval" if user.status == "PENDING" else "Access denied"
        raise HTTPException(status_code=403, detail=message)

    platform_grant = platform_service.get_active_platform_grant(db, user.id)
    is_platform_admin = platform_grant is not None
    memberships = tenant_service.get_user_memberships(db, user.id)
    tenant_claim = _claim(claims, settings.hcl_iam_tenant_claim)

    selected, membership, roles, permissions, is_platform_admin = tenant_service.resolve_active_tenant(
        db,
        user,
        memberships,
        selected_tenant=selected_tenant,
        tenant_claim=tenant_claim,
        is_platform_admin=is_platform_admin,
        auth_enabled=settings.auth_enabled,
        allow_platform_context=allow_platform_context,
    )

    if is_platform_admin and membership is None and selected is not None:
        audit_service.write_authorization_audit(
            db,
            action="platform.cross_tenant_access",
            outcome="SUCCESS",
            actor_user_id=user.id,
            target_user_id=user.id,
            tenant_id=selected.id,
            request=request,
            detail="Explicit platform administrator selected a tenant without local membership",
        )
        needs_commit = True

    if needs_commit:
        db.commit()
    return CurrentContext(
        user_id=user.id,
        external_user_id=user.external_iam_user_id,
        email=user.email,
        display_name=user.display_name,
        tenant_id=selected.id if selected is not None else None,
        external_tenant_id=selected.external_iam_tenant_id if selected is not None else None,
        roles=roles,
        permissions=permissions,
        is_platform_admin=is_platform_admin,
        identity_roles=identity_roles,
    )


def get_current_tenant_context(
    request: Request = None,
    claims: dict[str, Any] = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> Iterator[CurrentContext]:
    path = request.url.path if request is not None else ""
    method = request.method.upper() if request is not None else "GET"
    allow_platform_context = (
        path.startswith("/api/platform/")
        or path in {"/api/auth/me", "/api/v1/auth/me", "/api/tenants"}
        or (path == "/api/tenants" and method == "POST")
    )
    # Authorization is deliberately resolved from the database on every
    # request so revocations take effect immediately across all instances.
    context = _resolve_context(
        db,
        claims,
        x_tenant_id,
        allow_platform_context=allow_platform_context,
        request=request,
    )

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
    if path.startswith("/api/platform/administrators"):
        return "platform:user:read" if method == "GET" else "platform:user:write"
    if path.startswith("/api/platform/users"):
        return "platform:user:write"
    if path.startswith("/api/platform/tenants"):
        return "platform:admin"
    if path == "/api/tenants" and method == "POST":
        return "platform:tenant:create"
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
    if path.startswith("/api/products"):
        return {
            "GET": "product:read",
            "POST": "product:create",
            "PATCH": "product:update",
            "PUT": "product:update",
            "DELETE": "product:delete",
        }.get(method, "product:read")
    if path.startswith("/api/components"):
        return "component:read" if method == "GET" else "component:update"
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
    if path in {"/api/auth/me", "/api/v1/auth/me", "/api/tenants"}:
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
        log.warning("AUTH_ENABLED=false: using explicit local development identity")
        return
    required = {
        "HCL_IAM_ISSUER": settings.hcl_iam_issuer,
        "HCL_IAM_AUDIENCE": settings.hcl_iam_audience,
        "HCL_IAM_CLIENT_ID": settings.hcl_iam_client_id,
    }
    missing = [name for name, value in required.items() if not value.strip()]
    if missing:
        raise RuntimeError(f"HCL IAM configuration missing: {', '.join(missing)}")
    if settings.dev_default_tenant:
        raise RuntimeError("DEV_DEFAULT_TENANT must be false when AUTH_ENABLED=true")
    for name, value in {
        "HCL_IAM_ISSUER": settings.hcl_iam_issuer,
        "HCL_IAM_DISCOVERY_URL": settings.hcl_iam_discovery_url,
        "HCL_IAM_JWKS_URL": settings.hcl_iam_jwks_url,
    }.items():
        if value and not value.lower().startswith("https://") and not os.getenv("PYTEST_CURRENT_TEST"):
            raise RuntimeError(f"{name} must use HTTPS")
    algorithms = [item.strip().upper() for item in settings.hcl_iam_allowed_algorithms.split(",") if item.strip()]
    if algorithms != ["RS256"]:
        raise RuntimeError("HCL_IAM_ALLOWED_ALGORITHMS must be exactly RS256")
