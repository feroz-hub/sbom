"""Policy lookup and registration validation; never infer privileges from URL words."""

from __future__ import annotations

import inspect

from fastapi import HTTPException
from fastapi.routing import APIRoute
from starlette.routing import compile_path

from .permissions import ALL_PERMISSIONS
from .route_policies import PUBLIC_ROUTE_REASONS, ROUTE_POLICIES

# Route order matches registration order, preserving static/dynamic routing precedence.
_COMPILED = tuple(
    (key.split(" ", 1)[0], compile_path(key.split(" ", 1)[1])[0], policy) for key, policy in ROUTE_POLICIES.items()
)


def lookup_policy(method: str, path: str) -> str | None:
    for expected_method, pattern, policy in _COMPILED:
        if expected_method == method.upper() and pattern.fullmatch(path):
            return policy
    return None


def lookup_request_policy(request) -> str | None:
    # Use the route FastAPI actually selected, including aliases/prefixes.
    # ASGI routing metadata is server-owned; a caller cannot supply it as a header.
    effective = request.scope.get("fastapi", {}).get("effective_route_context")
    template = getattr(effective, "path", None) or getattr(request.scope.get("route"), "path", None)
    if template is not None:
        return ROUTE_POLICIES.get(f"{request.method.upper()} {template}")
    # Direct helper callers / inventory Requests have no routing metadata.
    return lookup_policy(request.method, request.url.path)


def permission_for_registered_request(request) -> str:
    policy = lookup_request_policy(request)
    if policy is None or policy in {"public", "account"}:
        raise HTTPException(status_code=403, detail="No authorization policy for this operation")
    return policy


def permission_for_operation(method: str, path: str) -> str:
    policy = lookup_policy(method, path)
    if policy is None or policy in {"public", "account"}:
        raise HTTPException(status_code=403, detail="No authorization policy for this operation")
    return policy


def iter_registered_routes(app):
    # FastAPI >=0.139 keeps included routers lazy. Older versions flatten routes.
    try:
        from fastapi.routing import _iter_routes_with_context
    except ImportError:
        routes = ((route, None) for route in app.routes)
    else:
        routes = _iter_routes_with_context(app.routes)
    for route, effective in routes:
        yield (effective.path if effective else getattr(route, "path", "")), route, effective


def iter_api_routes(app):
    for path, route, effective in iter_registered_routes(app):
        if isinstance(route, APIRoute):
            yield path, route, effective.dependant if effective else route.dependant


def _dependencies(dependant):
    yield dependant.call
    for child in dependant.dependencies:
        yield from _dependencies(child)


def validate_route_policies(app) -> None:
    """Refuse startup when an application route is unclassified or unguarded."""
    from .security import enforce_request_access, get_current_claims, get_current_tenant_context

    errors = []
    for path, route, _effective in iter_registered_routes(app):
        if not isinstance(route, APIRoute):
            for method in getattr(route, "methods", ()) or ():
                key = f"{method} {path}"
                if ROUTE_POLICIES.get(key) != "public" or key not in PUBLIC_ROUTE_REASONS:
                    errors.append(f"{key}: unclassified framework/Starlette route")
            if not getattr(route, "methods", None):
                errors.append(f"{path}: unsupported mounted route; explicit security review required")
    for path, route, dependant in iter_api_routes(app):
        calls = list(_dependencies(dependant))
        guarded_permissions = set()
        configuration_guard = False
        for call in calls:
            try:
                closure = inspect.getclosurevars(call).nonlocals
                if getattr(call, "__module__", "") == "app.core.security" and getattr(call, "__qualname__", "") in {
                    "require_permission.<locals>.dependency",
                    "require_platform_permission.<locals>.dependency",
                }:
                    guarded_permissions.add(closure["permission"])
                if (
                    getattr(call, "__module__", "") == "app.services.configuration_scope"
                    and getattr(call, "__qualname__", "") == "require_configuration_permission.<locals>.dependency"
                ):
                    configuration_guard = True
            except (TypeError, ValueError, KeyError):
                pass
        for method in route.methods:
            key = f"{method} {path}"
            policy = ROUTE_POLICIES.get(key)
            if policy is None:
                errors.append(f"{key}: missing policy")
            elif policy == "public":
                if key not in PUBLIC_ROUTE_REASONS:
                    errors.append(f"{key}: missing public justification")
            elif policy == "account":
                if get_current_claims not in calls and get_current_tenant_context not in calls:
                    errors.append(f"{key}: missing authenticated account guard")
            elif policy not in ALL_PERMISSIONS:
                errors.append(f"{key}: unknown permission")
            elif enforce_request_access not in calls and policy not in guarded_permissions and not configuration_guard:
                errors.append(f"{key}: missing permission guard")
    if errors:
        raise RuntimeError("Invalid route security policies: " + "; ".join(errors))
