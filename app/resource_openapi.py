"""Explicit public schemas for resource endpoints with internal dictionary DTOs."""

UUID = {
    "type": "string",
    "format": "uuid",
    "pattern": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
}
MEMBERSHIP_KEY = {
    "type": "string",
    "pattern": "^membership:" + UUID["pattern"][1:],
    "description": "Tenant Membership public UUID, distinct from User UUID.",
}


def augment(doc):
    schemas = doc.setdefault("components", {}).setdefault("schemas", {})
    schemas["PublicMembershipReference"] = {
        "type": "object",
        "required": ["membership_id", "user_id"],
        "additionalProperties": True,
        "properties": {
            "membership_id": dict(UUID),
            "user_id": dict(UUID),
            "tenant_id": dict(UUID),
            "role_assignment_version": {"type": "integer"},
            "status": {"type": "string"},
            "roles": {"type": "array", "items": {"type": "string"}},
        },
    }
    schemas["PublicRunReference"] = {
        "type": "object",
        "required": ["id"],
        "additionalProperties": True,
        "properties": {"id": dict(UUID), "sbom_id": dict(UUID), "run_status": {"type": "string"}},
    }
    schemas["PublicVexAssignee"] = {
        "type": "object",
        "required": ["id", "label"],
        "additionalProperties": True,
        "properties": {
            "id": MEMBERSHIP_KEY,
            "label": {"type": "string"},
            "roles": {"type": "array", "items": {"type": "string"}},
        },
    }

    def ref(name):
        return {"$ref": "#/components/schemas/" + name}

    def response(operation, schema):
        for status, definition in operation.get("responses", {}).items():
            if status.startswith("2") and status != "204":
                definition.setdefault("content", {}).setdefault("application/json", {})["schema"] = schema

    for path, operations in doc.get("paths", {}).items():
        for method, operation in operations.items():
            if not isinstance(operation, dict):
                continue
            if path == "/api/tenants/{tenant_id}/users" and method in {"get", "post"}:
                response(
                    operation,
                    {"type": "array", "items": ref("PublicMembershipReference")}
                    if method == "get"
                    else ref("PublicMembershipReference"),
                )
            elif path in {
                "/api/tenants/{tenant_id}/users/{membership_id}",
                "/api/tenants/{tenant_id}/users/{membership_id}/activate",
                "/api/tenants/{tenant_id}/users/{membership_id}/deactivate",
                "/api/v1/auth/tenants/{tenant_id}/memberships",
                "/api/tenants/{tenant_id}/users/{user_id}/roles",
            } and method in {"get", "post", "put", "patch"}:
                response(operation, ref("PublicMembershipReference"))
            elif path == "/api/tenants/{tenant_id}/users/{user_id}/roles/history":
                response(
                    operation,
                    {
                        "type": "object",
                        "additionalProperties": True,
                        "properties": {
                            "membership_id": dict(UUID),
                            "history": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                )
            elif path in {
                "/api/runs/recent",
                "/api/runs/search",
                "/api/sboms/{sbom_id}/analysis-runs",
                "/dashboard/runs",
            }:
                response(operation, {"type": "array", "items": ref("PublicRunReference")})
            elif path == "/api/vex/investigations/analysis-runs":
                response(
                    operation,
                    {"type": "object", "properties": {"items": {"type": "array", "items": ref("PublicRunReference")}}},
                )
            elif path == "/api/vex/investigations/assignees":
                response(
                    operation,
                    {
                        "type": "object",
                        "properties": {
                            "items": {"type": "array", "items": ref("PublicVexAssignee")},
                            "total": {"type": "integer"},
                        },
                    },
                )
            if path.endswith("/stream") and (path.startswith("/api/v1/runs/") or path.startswith("/api/sboms/")):
                operation.setdefault("responses", {}).setdefault("200", {}).update(
                    {
                        "description": "Server-sent events; event data uses persisted Run UUIDv4 (run_id for AI progress, runId for analysis creation). Task/batch identifiers and counters retain their own contracts.",
                        "content": {"text/event-stream": {"schema": {"type": "string"}}},
                    }
                )
    assignment = schemas.get("InvestigationAssignmentRequest", {}).get("properties", {})
    if "assigned_to" in assignment:
        assignment["assigned_to"] = {"anyOf": [MEMBERSHIP_KEY, {"type": "null"}]}
    return doc
