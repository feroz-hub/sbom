from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from jwt import InvalidTokenError, PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..settings import get_settings
from .context import CurrentContext, bind_context, reset_context
from .permissions import normalize_role, permissions_for_roles

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
    algorithms = [
        value.strip()
        for value in settings.hcl_iam_allowed_algorithms.split(",")
        if value.strip()
    ]
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


def get_current_user(
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.auth_enabled:
        return {
            "sub": "local-dev-admin",
            "email": "local-admin@localhost",
            "name": "Local Development Admin",
            settings.hcl_iam_role_claim: ["PLATFORM_ADMIN"],
            settings.hcl_iam_tenant_claim: "local-default",
        }
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _unauthorized()
    token = authorization[7:].strip()
    if not token:
        raise _unauthorized()
    return validate_hcl_token(token)


def _upsert_user(db: Session, claims: dict[str, Any]):
    from ..models import IAMUser

    external_id = str(claims["sub"])
    now = datetime.now(UTC)
    user = db.execute(
        select(IAMUser).where(IAMUser.external_iam_user_id == external_id)
    ).scalar_one_or_none()
    if user is None:
        user = IAMUser(
            external_iam_user_id=external_id,
            email=claims.get("email"),
            display_name=claims.get("name") or claims.get("preferred_username"),
            status="ACTIVE",
            created_at=now,
            updated_at=now,
            last_login_at=now,
        )
        db.add(user)
        db.flush()
    else:
        user.email = claims.get("email") or user.email
        user.display_name = claims.get("name") or claims.get("preferred_username") or user.display_name
        user.last_login_at = now
        user.updated_at = now
    if user.status != "ACTIVE":
        raise HTTPException(status_code=403, detail="Access denied")
    return user


def _resolve_context(
    db: Session,
    claims: dict[str, Any],
    selected_tenant: str | None,
) -> CurrentContext:
    from ..models import IAMUser, Tenant, TenantUser

    settings = get_settings()
    user: IAMUser = _upsert_user(db, claims)
    token_roles = _roles(_claim(claims, settings.hcl_iam_role_claim))
    is_platform_admin = "PLATFORM_ADMIN" in token_roles
    memberships = db.execute(
        select(TenantUser, Tenant)
        .join(Tenant, Tenant.id == TenantUser.tenant_id)
        .where(
            TenantUser.user_id == user.id,
            TenantUser.status == "ACTIVE",
            Tenant.status == "ACTIVE",
        )
    ).all()

    tenant_claim = _claim(claims, settings.hcl_iam_tenant_claim)
    requested = (selected_tenant or "").strip()
    selected: Tenant | None = None
    membership: TenantUser | None = None
    if requested:
        for member, tenant in memberships:
            if requested in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(
                    Tenant.status == "ACTIVE",
                    sa_or_tenant_identity(Tenant, requested),
                )
            ).scalar_one_or_none()
    elif tenant_claim is not None:
        claim_value = str(tenant_claim)
        for member, tenant in memberships:
            if claim_value in {str(tenant.id), tenant.slug, tenant.external_iam_tenant_id}:
                membership, selected = member, tenant
                break
        if selected is None and is_platform_admin:
            selected = db.execute(
                select(Tenant).where(Tenant.external_iam_tenant_id == claim_value)
            ).scalar_one_or_none()
    elif len(memberships) == 1:
        membership, selected = memberships[0]
    elif not settings.auth_enabled:
        selected = db.execute(
            select(Tenant).where(Tenant.slug == settings.default_tenant_slug)
        ).scalar_one_or_none()
        membership = db.execute(
            select(TenantUser).where(
                TenantUser.tenant_id == selected.id,
                TenantUser.user_id == user.id,
            )
        ).scalar_one_or_none() if selected else None

    if selected is None or (membership is None and not is_platform_admin):
        db.rollback()
        raise HTTPException(status_code=403, detail="Tenant access denied")
    roles = {normalize_role(membership.role)} if membership else set()
    if is_platform_admin:
        roles.add("PLATFORM_ADMIN")
    permissions = permissions_for_roles(frozenset(roles))
    db.commit()
    return CurrentContext(
        user_id=user.id,
        external_user_id=user.external_iam_user_id,
        email=user.email,
        display_name=user.display_name,
        tenant_id=selected.id,
        external_tenant_id=selected.external_iam_tenant_id,
        roles=frozenset(roles),
        permissions=permissions,
        is_platform_admin=is_platform_admin,
    )


def sa_or_tenant_identity(tenant_model, value: str):
    from sqlalchemy import or_

    clauses = [tenant_model.slug == value, tenant_model.external_iam_tenant_id == value]
    if value.isdigit():
        clauses.append(tenant_model.id == int(value))
    return or_(*clauses)


def get_current_tenant_context(
    claims: dict[str, Any] = Depends(get_current_user),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
) -> Iterator[CurrentContext]:
    context = _resolve_context(db, claims, x_tenant_id)
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
            "GET": "project:read", "POST": "project:create",
            "PATCH": "project:update", "PUT": "project:update", "DELETE": "project:delete",
        }.get(method, "project:read")
    if path.startswith("/api/sboms"):
        if method == "GET":
            return "sbom:export" if any(part in path for part in ("/export", "/reports/")) else "sbom:read"
        if method == "DELETE":
            return "sbom:delete"
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
