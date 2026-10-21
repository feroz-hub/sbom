"""Public UUID boundary. Domain services and integer FK relations remain internal.

Runs after each route's authentication dependencies, before parameter validation.
Resolution is tenant scoped and never interprets an integer as a public identity.
"""

from __future__ import annotations

import json
from contextlib import nullcontext
from uuid import RFC_4122, UUID

from fastapi import Depends, HTTPException, Request
from fastapi.dependencies.utils import get_dependant
from fastapi.routing import APIRoute, iter_route_contexts
from sqlalchemy import select
from starlette.datastructures import QueryParams
from starlette.routing import request_response

from .core.context import get_bound_context
from .db import SessionLocal, get_db
from .models import LogicalSBOM, Product, Projects, SBOMComponent, SBOMSource, Tenant

MODELS = {
    "tenants": Tenant,
    "projects": Projects,
    "products": Product,
    "logical_sbom": LogicalSBOM,
    "sbom_source": SBOMSource,
    "sbom_component": SBOMComponent,
}
FIELDS = {
    "tenant_id": "tenants",
    "project_id": "projects",
    "projectid": "projects",
    "application_id": "products",
    "product_id": "products",
    "logical_id": "logical_sbom",
    "logical_sbom_id": "logical_sbom",
    "sbom_id": "sbom_source",
    "sbom_ref_id": "sbom_source",
    "posture_sbom_id": "sbom_source",
    "source_sbom_id": "sbom_source",
    "converted_sbom_id": "sbom_source",
    "imported_sbom_id": "sbom_source",
    "current_sbom_id": "sbom_source",
    "designated_current_sbom_id": "sbom_source",
    "latest_sbom_id": "sbom_source",
    "previous_sbom_id": "sbom_source",
    "parent_sbom_id": "sbom_source",
    "baseline_sbom_id": "sbom_source",
    "target_sbom_id": "sbom_source",
    "component_id": "sbom_component",
    "source_component_id": "sbom_component",
    "duplicate_of_component_id": "sbom_component",
}
BATCH_FIELDS = {
    "tenant_ids": "tenants",
    "project_ids": "projects",
    "product_ids": "products",
    "application_ids": "products",
    "sbom_ids": "sbom_source",
    "component_ids": "sbom_component",
    "deleted_sbom_ids": "sbom_source",
    "child_sbom_ids": "sbom_source",
    "failed_sbom_ids": "sbom_source",
}

CONTEXT = {
    "tenants": "tenants",
    "tenant": "tenants",
    "active_tenant": "tenants",
    "available_tenants": "tenants",
    "scanned_project_ids": "projects",
    "scanned-project-ids": "projects",
    "applications": "products",
    "application": "products",
    "recent_sboms": "sbom_source",
    "recent-sboms": "sbom_source",
    "projects": "projects",
    "project": "projects",
    "products": "products",
    "product": "products",
    "logical_sboms": "logical_sbom",
    "logical_sbom": "logical_sbom",
    "sboms": "sbom_source",
    "sbom": "sbom_source",
    "latest_version": "sbom_source",
    "current_sbom": "sbom_source",
    "effective_current_sbom": "sbom_source",
    "latest_analyzed": "sbom_source",
    "latest_uploaded": "sbom_source",
    "posture_sbom": "sbom_source",
    "child_sboms": "sbom_source",
    "components": "sbom_component",
    "component": "sbom_component",
    "current_component": "sbom_component",
    "previous_component": "sbom_component",
    "sample_matched_components": "sbom_component",
    "sample_unknown_components": "sbom_component",
}

SOURCE_VERSION_COLLECTIONS = {
    "/api/sboms/{id}/versions",
    "/api/logical-sboms/{logical_id}/versions",
    "/api/vex/investigations/versions",
}

# Deprecated but still supported until the advertised sunset. Keep their
# request/response identifiers under the same boundary as their successors.
LEGACY_ANALYSIS_PATHS = {
    "/analyze-sbom-nvd",
    "/analyze-sbom-github",
    "/analyze-sbom-osv",
    "/analyze-sbom-vulndb",
    "/analyze-sbom-consolidated",
}


def canonical(value):
    try:
        result = UUID(str(value))
        if result.version != 4 or result.variant != RFC_4122:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(422, "Resource identifier must be a UUIDv4") from None


def schema_entity(schema):
    # Explicit DTO ownership: audit, users, findings, runs and SBOM types keep
    # their separate identities. Never infer identity from a name substring.
    return {
        "CreatedTenantResponse": "tenants",
        "AvailableTenant": "tenants",
        "ProjectOut": "projects",
        "ProductRead": "products",
        "ProductSummary": "products",
        "LogicalSBOMOut": "logical_sbom",
        "SBOMSourceOut": "sbom_source",
        "SBOMComponentOut": "sbom_component",
        "SBOMComponentListItem": "sbom_component",
    }.get(schema.get("title"))


def route_entity(path):
    # The final resource collection controls the unqualified id field.
    # "versions" is not a resource: advisor policy histories have their own
    # integer identities. Only these SBOM version collections contain sources.
    if path in SOURCE_VERSION_COLLECTIONS:
        return "sbom_source"
    entity = None
    for part in path.replace("-", "_").split("/"):
        if part in CONTEXT:
            entity = CONTEXT[part]
    return entity


def field_entity(key, path):
    if key == "version_id" and path == "/api/sboms/{id}/restore/{version_id}":
        return "sbom_source"
    return FIELDS.get(key)


def scoped_table(db, entity, context):
    table = MODELS[entity].__table__
    statement = select(table.c.id, table.c.public_id)
    if entity != "tenants":
        if context is None or context.tenant_id is None:
            raise HTTPException(403, "Active tenant context required")
        statement = statement.where(table.c.tenant_id == context.tenant_id)
    elif context is None:
        raise HTTPException(401, "Authentication required")
    elif context.is_platform_admin:
        # Platform routes retain cross-tenant administrative visibility even
        # when that administrator has selected a working tenant in the UI.
        pass
    elif context.tenant_id is not None:
        statement = statement.where(table.c.id == context.tenant_id)
    elif not context.is_platform_admin:
        # Tenant selection responses are built only from authenticated memberships.
        from .models import TenantUser

        statement = statement.where(
            table.c.id.in_(
                select(TenantUser.__table__.c.tenant_id).where(TenantUser.__table__.c.user_id == context.user_id)
            )
        )
    return table, statement


async def decode_request(request: Request, db=Depends(get_db)):
    context = getattr(request.state, "current_context", None) or get_bound_context()
    request.state.public_identity_session = db
    with nullcontext(db):

        def resolve(entity, value):
            public = canonical(value)
            table, statement = scoped_table(db, entity, context)
            row = db.execute(statement.where(table.c.public_id == public)).first()
            if row is None:
                raise HTTPException(404, "Resource not found")
            if not hasattr(request.state, "public_identity_cache"):
                request.state.public_identity_cache = {}
            request.state.public_identity_cache[(entity, row.id)] = str(row.public_id)
            return row.id

        for key, value in list(request.path_params.items()):
            entity = field_entity(key, request.scope["route"].path)
            if key == "id":
                entity = route_entity(request.scope["route"].path)
            if entity:
                request.path_params[key] = resolve(entity, value)
        if (
            request.method == "DELETE"
            and request.query_params.get("permanent", "").lower() in {"true", "1", "yes", "on", "t", "y"}
            and "sbom_id" in request.path_params
        ):
            # Preserve wire identities before the service physically removes
            # the version tree. Its internal return contract retains integers.
            from .services.sbom_delete_service import SBOMDeleteService

            target = request.path_params["sbom_id"]
            impact = SBOMDeleteService(db, context.tenant_id).get_delete_impact(target)
            table, query = scoped_table(db, "sbom_source", context)
            for row in db.execute(query.where(table.c.id.in_([target, *impact["child_sbom_ids"]]))):
                request.state.public_identity_cache[("sbom_source", row.id)] = str(row.public_id)
        pairs = []
        for key, value in request.query_params.multi_items():
            if key in BATCH_FIELDS and value:
                value = ",".join(str(resolve(BATCH_FIELDS[key], part)) for part in value.split(","))
            entity = field_entity(key, request.scope["route"].path)
            if request.scope["route"].path.endswith("/compare-versions") and key in ("version_a", "version_b"):
                entity = "sbom_source"
            if request.scope["route"].path.rstrip("/") == "/api/sboms" and key == "cursor":
                entity = "sbom_source"
            if entity and value not in ("", "all"):
                value = str(resolve(entity, value))
            pairs.append((key, value))
        request._query_params = QueryParams(pairs)
        if request.headers.get("content-type", "").startswith(
            ("multipart/form-data", "application/x-www-form-urlencoded")
        ):
            form = await request.form()
            pairs = []
            for key, value in form.multi_items():
                entity = field_entity(key, request.scope["route"].path)
                if entity and value not in ("", None):
                    value = str(resolve(entity, value))
                pairs.append((key, value))
            from starlette.datastructures import FormData

            updated = FormData(pairs)
            form._list = updated._list
            form._dict = updated._dict
        if "application/json" in request.headers.get("content-type", ""):
            try:
                body = await request.json()
            except (ValueError, UnicodeDecodeError):
                return

            if isinstance(body, dict) and request.method in ("PATCH", "PUT"):
                if "public_id" in body:
                    raise HTTPException(422, "public_id is immutable; the public wire field is id")
                if "id" in body and route_entity(request.scope["route"].path):
                    expected_ids = set(getattr(request.state, "public_identity_cache", {}).values())
                    if str(body["id"]).lower() not in expected_ids:
                        raise HTTPException(422, "Public identity is immutable")

            if request.scope["route"].path == "/api/sboms/{sbom_id}/vex" and request.method == "POST":
                # This endpoint accepts a source-native VEX document, either
                # wrapped in "document" or directly. CSAF product_id/product_ids
                # and OpenVEX identifiers belong to that document, not our DB.
                # The path's SBOM UUID was already resolved and tenant scoped.
                return

            def convert(obj):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        entity = field_entity(key, request.scope["route"].path)
                        if key in ("metadata_json", "evidence_json", "sbom_data", "validation_report", "raw_document"):
                            continue
                        if key in BATCH_FIELDS and value is not None:
                            obj[key] = [resolve(BATCH_FIELDS[key], item) for item in value]
                        elif entity and value is not None:
                            obj[key] = resolve(entity, value)
                        elif isinstance(value, (dict, list)):
                            convert(value)
                elif isinstance(obj, list):
                    for value in obj:
                        convert(value)

            convert(body)


def install_public_boundary(app):
    wrapped = set()
    for route_context in iter_route_contexts(app.routes):
        original = route_context.original_route
        route = route_context._effective_route
        if not isinstance(original, APIRoute) or not (
            route.path.startswith(("/api/", "/dashboard")) or route.path in LEGACY_ANALYSIS_PATHS
        ):
            continue
        # Business endpoints are already protected; public identity/account routes
        # resolve their own context and have no six-resource request arguments.
        if any(x.call.__name__ == "enforce_request_access" for x in route.dependant.dependencies):
            position = (
                next(
                    i for i, x in enumerate(route.dependant.dependencies) if x.call.__name__ == "enforce_request_access"
                )
                + 1
            )
            route.dependant.dependencies.insert(position, get_dependant(path=route.path_format, call=decode_request))
        else:
            # Tenant endpoints declare their own authorization dependencies.
            if any(k in FIELDS for k in route.param_convertors) or route.body_field is not None:
                route.dependant.dependencies.append(get_dependant(path=route.path_format, call=decode_request))
        if id(original) in wrapped:
            continue
        wrapped.add(id(original))
        handler_factory = original.get_route_handler
        response_model = original.response_model
        schema = {}
        if response_model is not None:
            from pydantic import TypeAdapter

            schema = TypeAdapter(response_model).json_schema()

        def wrap(handler, schema, path):
            async def serve(request):
                try:
                    response = await handler(request)
                except HTTPException as exc:
                    from fastapi.exception_handlers import http_exception_handler

                    response = await http_exception_handler(request, exc)
                if request.app is not app:
                    return response
                # R3-DEF-001: this is the immutable source-native candidate,
                # whose exact bytes are reviewed and SHA256-bound at approval.
                # Authorization/tenant checks already ran in the handler; do
                # not parse, translate native SBOM identities, or reserialize it.
                if (
                    path == "/api/sbom-validation-sessions/{session_id}/repair/{job_id}/download"
                    and 200 <= response.status_code < 300
                ):
                    return response
                if not response.headers.get("content-type", "").startswith("application/json"):
                    return response
                try:
                    data = json.loads(response.body)
                except (ValueError, AttributeError):
                    return response
                context = getattr(request.state, "current_context", None) or get_bound_context()
                shared = getattr(request.state, "public_identity_session", None)
                with nullcontext(shared) if shared is not None else SessionLocal() as db:
                    cache = dict(getattr(request.state, "public_identity_cache", {}))
                    references = {}
                    collecting = True

                    def outward(entity, value):
                        if value is None or not isinstance(value, int):
                            return value
                        cache_key = (entity, value)
                        if cache_key not in cache:
                            if collecting:
                                references.setdefault(entity, set()).add(value)
                                return value
                            raise HTTPException(500, "Unresolvable public resource reference")
                        return cache[cache_key]

                    def walk(value, node, entity=None):
                        if "$ref" in node:
                            node = schema.get("$defs", {}).get(node["$ref"].split("/")[-1], {})
                        if "anyOf" in node:
                            node = next((n for n in node["anyOf"] if n.get("type") != "null"), {})
                            if "$ref" in node:
                                node = schema.get("$defs", {}).get(node["$ref"].split("/")[-1], {})
                        entity = schema_entity(node) or entity
                        if isinstance(value, list):
                            return [walk(x, node.get("items", {}), entity) for x in value]
                        if isinstance(value, dict):
                            result = {}
                            for key, item in value.items():
                                target = FIELDS.get(key)
                                if key == "id":
                                    target = entity
                                if key == "parent_id" and entity == "sbom_source":
                                    target = "sbom_source"
                                batch = BATCH_FIELDS.get(key) or (entity if key == "ids" else None)
                                if batch and isinstance(item, list):
                                    result[key] = [outward(batch, x) for x in item]
                                elif target and isinstance(item, int):
                                    result[key] = outward(target, item)
                                elif key in (
                                    "metadata_json",
                                    "evidence_json",
                                    "sbom_data",
                                    "validation_report",
                                    "raw_document",
                                ):
                                    result[key] = item
                                else:
                                    result[key] = walk(
                                        item,
                                        node.get("properties", {}).get(key, {}),
                                        CONTEXT.get(key, entity if key in ("items", "data", "results") else None),
                                    )
                            return result
                        return value

                    root = (
                        route_entity(path)
                        if path.split("/")[-1] in CONTEXT
                        or path in SOURCE_VERSION_COLLECTIONS
                        or path.split("/")[-1]
                        in (
                            "{tenant_id}",
                            "{project_id}",
                            "{product_id}",
                            "{sbom_id}",
                            "{component_id}",
                            "{logical_sbom_id}",
                        )
                        else None
                    )
                    if response.status_code >= 400:
                        root = None
                    if schema.get("title") and not schema_entity(schema):
                        root = None
                    if path == "/api/report-notifications/targets":
                        root = {
                            "PROJECT": "projects",
                            "PRODUCT": "products",
                            "SBOM": "sbom_source",
                            "TENANT": "tenants",
                        }.get(request.query_params.get("scope"))
                    # Discover exactly the same resource fields as serialization,
                    # then resolve distinct references in bounded scoped batches.
                    # Never cache across requests or broaden the tenant statement.
                    walk(data, schema, root)
                    for entity, identifiers in references.items():
                        table, statement = scoped_table(db, entity, context)
                        ordered = sorted(identifiers)
                        for offset in range(0, len(ordered), 500):
                            chunk = ordered[offset : offset + 500]
                            rows = db.execute(statement.where(table.c.id.in_(chunk))).all()
                            for row in rows:
                                cache[(entity, row.id)] = str(row.public_id)
                            if any((entity, identifier) not in cache for identifier in chunk):
                                raise HTTPException(500, "Unresolvable public resource reference")
                    collecting = False
                    data = walk(data, schema, root)
                    if (
                        path in LEGACY_ANALYSIS_PATHS
                        and response.headers.get("Deprecation") == "true"
                        and isinstance(data, dict)
                        and data.get("sbom_id")
                    ):
                        response.headers["Link"] = (
                            f'</api/sboms/{data["sbom_id"]}/analyze>; rel="successor-version"'
                        )
                    if path.rstrip("/") == "/api/sboms" and response.headers.get("X-Next-Cursor"):
                        response.headers["X-Next-Cursor"] = outward(
                            "sbom_source", int(response.headers["X-Next-Cursor"])
                        )
                response.body = json.dumps(data, separators=(",", ":")).encode()
                response.headers["content-length"] = str(len(response.body))
                return response

            return serve

        def factory(handler_factory=handler_factory, schema=schema, path=route.path):
            return wrap(handler_factory(), schema, path)

        original.get_route_handler = factory
        original.app = request_response(factory())


def install_public_openapi(app):
    """Describe wire UUIDs while validated domain-service parameters remain ints."""
    original = app.openapi

    def generate():
        doc = original()

        def uuid_field(node):
            nullable = any(x.get("type") == "null" for x in node.get("anyOf", []))
            result = {k: v for k, v in node.items() if k in ("title", "description", "default", "deprecated")}
            if nullable:
                result["anyOf"] = [{"type": "string", "format": "uuid"}, {"type": "null"}]
            else:
                result.update(type="string", format="uuid")
            return result

        for name, node in doc.get("components", {}).get("schemas", {}).items():
            entity = schema_entity({**node, "title": name})
            for field, value in list(node.get("properties", {}).items()):
                if field in FIELDS or (field == "id" and entity) or (field == "parent_id" and entity == "sbom_source"):
                    node["properties"][field] = uuid_field(value)
                elif field in BATCH_FIELDS:
                    value = dict(value)
                    if "anyOf" in value:
                        value["anyOf"] = [
                            {**item, "items": {"type": "string", "format": "uuid"}}
                            if item.get("type") == "array"
                            else item
                            for item in value["anyOf"]
                        ]
                    elif value.get("type") == "array":
                        value["items"] = {"type": "string", "format": "uuid"}
                    node["properties"][field] = value
        for path, operations in doc.get("paths", {}).items():
            for operation in operations.values():
                if not isinstance(operation, dict):
                    continue
                for parameter in operation.get("parameters", []):
                    key = parameter["name"]
                    if (
                        field_entity(key, path)
                        or key == "X-Tenant-ID"
                        or (key == "id" and route_entity(path))
                        or (path.endswith("/compare-versions") and key in ("version_a", "version_b"))
                        or (path.rstrip("/") == "/api/sboms" and key == "cursor")
                    ):
                        parameter["schema"] = uuid_field(parameter.get("schema", {}))
        return doc

    app.openapi = generate
