"""Output-only record labels, never alternate resource selectors.

Only business resources already resolved by the scoped public boundary qualify.
Global tenant/IAM/membership/grant sequences intentionally remain private.
"""

ENTITIES = frozenset({"projects", "products", "logical_sbom", "sbom_source", "sbom_component", "analysis_run"})


def presentable_path(path):
    # Operational AI progress/store envelopes are not record-label DTOs. Their
    # strict wire contract and worker/SSE identities stay exactly as reviewed.
    return not path.startswith(("/api/v1/runs/", "/api/v1/scans/"))


def display_field(key, entity):
    if entity not in ENTITIES:
        return None
    if key == "id":
        return "display_id"
    if key.endswith("_id"):
        return key[:-3] + "_display_id"
    if key in {"projectid", "runId", "scanId"}:
        return {"projectid": "project_display_id", "runId": "run_display_id", "scanId": "scan_display_id"}[key]
    return None


def add_display(result, key, entity, internal):
    field = display_field(key, entity)
    if field and type(internal) is int and 0 < internal <= 2**53 - 1:
        result[field] = internal


def integer_label(kind, value):
    if type(value) is int and 0 < value <= 2**53 - 1:
        return f"{kind} #{value}"
    return f"{kind} —"


def schema_field():
    return {
        "anyOf": [{"type": "integer", "minimum": 1, "maximum": 2**53 - 1}, {"type": "null"}],
        "readOnly": True,
        "description": "Existing persisted integer key for authorized display only. Never a resource selector; use the UUID.",
    }


def augment_openapi(doc, schema_entity, field_entity):
    """Decorate successful response schemas only, including existing DTO refs."""
    schemas = doc.get("components", {}).get("schemas", {})
    seen = set()

    def visit(node, path):
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            marker = (name, path)
            if marker in seen:
                return
            seen.add(marker)
            node = schemas.get(name, {})
        entity = schema_entity(node)
        if node is schemas.get("PublicRunReference"):
            entity = "analysis_run"
        properties = node.get("properties", {})
        for key, value in list(properties.items()):
            target = entity if key == "id" else field_entity(key, path)
            field = display_field(key, target)
            if field:
                properties[field] = schema_field()
            visit(value, path)
        for key in ("items", "additionalProperties"):
            if isinstance(node.get(key), dict):
                visit(node[key], path)
        for key in ("anyOf", "allOf", "oneOf"):
            for item in node.get(key, []):
                visit(item, path)

    for path, operations in doc.get("paths", {}).items():
        if not presentable_path(path):
            continue
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            for status, response in operation.get("responses", {}).items():
                if status.startswith("2"):
                    visit(response.get("content", {}).get("application/json", {}).get("schema", {}), path)
    return doc
