from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import AsyncIterator, Callable
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
from .identity_states import (
    AuthorizationState,
    IdentityAuditEvent,
    IdentityErrorCode,
    identity_http_error,
)
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
        values: list[Any] = value.replace(";", ",").split(",")
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
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
    from ..services.identity_service import validate_external_identity_claims

    validate_external_identity_claims(claims)
    return claims


def get_current_claims(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.auth_enabled:
        return {
            "iss": "https://local-dev.invalid",
            "sub": "dev-user",
            "email": "dev@local",
            "name": "Dev User",
            "preferred_username": "dev@local",
            "employee_id": "LOCAL-DEV",
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


_CONTEXT_CACHE: dict[tuple[Any, str | None, Any], tuple[float, CurrentContext]] = {}
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


def _block_user_access(
    db: Session,
    user: IAMUser,
    *,
    state: AuthorizationState,
    request: Request | None,
) -> None:
    from ..services import audit_service

    if state == AuthorizationState.ACCOUNT_DISABLED:
        event = IdentityAuditEvent.ACCESS_BLOCKED_DISABLED
        code = IdentityErrorCode.ACCOUNT_DISABLED
        message = "This SBOM Analyzer account is disabled. Contact support."
    elif state == AuthorizationState.ACCOUNT_PENDING_APPROVAL:
        event = IdentityAuditEvent.ACCESS_BLOCKED_PENDING
        code = IdentityErrorCode.ACCOUNT_PENDING_APPROVAL
        message = "This SBOM Analyzer account is awaiting administrator approval."
    else:
        event = IdentityAuditEvent.ACCESS_BLOCKED_UNVERIFIED
        code = IdentityErrorCode.EMAIL_VERIFICATION_REQUIRED
        message = "Email verification is required before accessing SBOM Analyzer."
    audit_service.write_authorization_audit(
        db,
        action=str(event),
        outcome="DENIED",
        actor_user_id=user.id,
        target_user_id=user.id,
        tenant_id=None,
        request=request,
        new_value={"reason_code": str(code), "authorization_state": str(state)},
        detail=str(code),
    )
    db.commit()
    raise identity_http_error(code, message)


def require_verified_user(user: IAMUser) -> IAMUser:
    """Enforce local enablement and SBOM email verification."""
    if user.status == "DISABLED":
        raise identity_http_error(
            IdentityErrorCode.ACCOUNT_DISABLED,
            "This SBOM Analyzer account is disabled. Contact support.",
        )
    if user.status == "PENDING":
        raise identity_http_error(
            IdentityErrorCode.ACCOUNT_PENDING_APPROVAL,
            "This SBOM Analyzer account is awaiting administrator approval.",
        )
    if not user.email_verified or user.verification_required:
        raise identity_http_error(
            IdentityErrorCode.EMAIL_VERIFICATION_REQUIRED,
            "Email verification is required before accessing SBOM Analyzer.",
        )
    return user


def _resolve_context(
    db: Session,
    claims: dict[str, Any],
    selected_tenant: str | None,
    *,
    allow_platform_context: bool = False,
    request: Request | None = None,
) -> CurrentContext:
    from ..services import audit_service
    from ..services.auth_context_service import resolve_authorization_state
    from ..services.email_verification_service import (
        ensure_initial_verification_delivery,
    )
    from ..services.identity_service import provision_local_identity

    settings = get_settings()
    provisioned = provision_local_identity(db, claims, request=request)
    user = provisioned.user
    db.commit()
    ensure_initial_verification_delivery(db, user, request=request)
    db.refresh(user)
    identity_roles = _roles(_claim(claims, settings.hcl_iam_role_claim))
    state = resolve_authorization_state(
        db,
        user,
        selected_tenant=selected_tenant,
        selector_hint=_claim(claims, settings.hcl_iam_tenant_claim),
        allow_platform_context=allow_platform_context,
        request=request,
    )
    if state.status in {
        AuthorizationState.ACCOUNT_DISABLED,
        AuthorizationState.ACCOUNT_PENDING_APPROVAL,
        AuthorizationState.VERIFICATION_REQUIRED,
    }:
        _block_user_access(db, user, state=state.status, request=request)
    if state.status == AuthorizationState.NO_TENANT:
        db.commit()
        raise identity_http_error(
            IdentityErrorCode.NO_TENANT,
            "No active tenant membership is available. Contact an administrator.",
        )
    if state.status == AuthorizationState.TENANT_SELECTION_REQUIRED:
        db.commit()
        raise identity_http_error(
            IdentityErrorCode.TENANT_SELECTION_REQUIRED,
            "Select an authorized tenant before accessing SBOM Analyzer.",
        )

    if state.is_platform_admin and state.active_membership is None and state.active_tenant is not None:
        audit_service.write_authorization_audit(
            db,
            action="platform.cross_tenant_access",
            outcome="SUCCESS",
            actor_user_id=user.id,
            target_user_id=user.id,
            tenant_id=state.active_tenant.id,
            request=request,
            detail="Explicit platform administrator selected a tenant without local membership",
        )
    from ..services import tenant_role_assignment_service

    roles = (
        set(
            tenant_role_assignment_service.effective_role_codes(
                db,
                state.active_membership,
                actor_user_id=user.id,
                request=request,
            )
        )
        if state.active_membership
        else set()
    )
    permissions = (
        set(
            tenant_role_assignment_service.effective_permissions(
                db,
                state.active_membership,
                actor_user_id=user.id,
                request=request,
            )
        )
        if state.active_membership
        else set()
    )
    if state.is_platform_admin:
        roles.add("PLATFORM_ADMIN")
    from ..services.authorization_catalog_service import resolve_permissions_for_roles

    if state.is_platform_admin:
        permissions.update(
            resolve_permissions_for_roles(
                db,
                frozenset({"PLATFORM_ADMIN"}),
                actor_user_id=user.id,
                request=request,
            )
        )
    db.commit()
    return CurrentContext(
        user_id=user.id,
        external_user_id=user.external_iam_user_id,
        email=user.email,
        display_name=user.display_name,
        tenant_id=state.active_tenant.id if state.active_tenant is not None else None,
        external_tenant_id=(
            state.active_tenant.external_iam_tenant_id
            if state.active_tenant is not None
            else None
        ),
        roles=frozenset(roles),
        permissions=frozenset(permissions),
        is_platform_admin=state.is_platform_admin,
        identity_roles=identity_roles,
    )


async def get_current_tenant_context(
    request: Request = None,
    claims: dict[str, Any] = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> AsyncIterator[CurrentContext]:
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


def require_platform_permission(permission: str) -> Callable:
    """Require current-request database platform authority and audit denials."""

    def dependency(
        request: Request,
        context: CurrentContext = Depends(get_current_tenant_context),
        db: Session = Depends(get_db),
    ) -> CurrentContext:
        if context.is_platform_admin and context.has_permission(permission):
            return context
        from ..services import audit_service

        audit_service.write_authorization_audit(
            db,
            action="PLATFORM_PERMISSION_DENIED",
            outcome="DENIED",
            actor_user_id=context.user_id,
            target_user_id=context.user_id,
            tenant_id=None,
            request=request,
            new_value={"permission": permission},
            detail=str(IdentityErrorCode.PLATFORM_PERMISSION_DENIED),
        )
        db.commit()
        raise identity_http_error(
            IdentityErrorCode.PLATFORM_PERMISSION_DENIED,
            "Platform permission is required for this action.",
        )

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
    if path.startswith("/api/platform/authorization"):
        return (
            "platform:authorization:read"
            if method == "GET"
            else "platform:authorization:manage"
        )
    if path.startswith("/api/platform/administrators"):
        if method == "GET":
            return "platform:administrator:read"
        if method == "POST":
            return "platform:administrator:grant"
        return "platform:administrator:revoke"
    if path.startswith("/api/platform/users"):
        return (
            "platform:user:read"
            if method == "GET"
            else "platform:user:manage_status"
        )
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
    db: Session = Depends(get_db),
) -> CurrentContext:
    permission = permission_for_request(request)
    if not context.has_permission(permission):
        if permission.startswith("platform:"):
            from ..services import audit_service

            audit_service.write_authorization_audit(
                db,
                action="PLATFORM_PERMISSION_DENIED",
                outcome="DENIED",
                actor_user_id=context.user_id,
                target_user_id=context.user_id,
                tenant_id=None,
                request=request,
                new_value={"permission": permission},
                detail=str(IdentityErrorCode.PLATFORM_PERMISSION_DENIED),
            )
            db.commit()
            raise identity_http_error(
                IdentityErrorCode.PLATFORM_PERMISSION_DENIED,
                "Platform permission is required for this action.",
            )
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
