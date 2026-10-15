from __future__ import annotations

import json

from app.deprecation import deprecated_call_count


def test_legacy_json_sbom_creation_has_successor_metadata(client, sample_sbom_dict):
    before = deprecated_call_count("POST /api/sboms")
    response = client.post(
        "/api/sboms",
        json={"sbom_name": "legacy-metadata", "sbom_data": json.dumps(sample_sbom_dict)},
    )

    assert response.status_code == 201, response.text
    assert response.headers["Deprecation"] == "true"
    assert response.headers["Sunset"] == "Sun, 31 Jan 2027 23:59:59 GMT"
    assert response.headers["Link"] == '</api/sboms/upload>; rel="successor-version"'
    assert deprecated_call_count("POST /api/sboms") == before + 1


def test_deprecated_compatibility_routes_are_hidden_from_swagger_but_still_registered(client):
    """Hide superseded routes from Swagger without breaking older API clients."""
    from app.core.route_policy import iter_api_routes

    paths = client.get("/openapi.json").json()["paths"]
    registered = {
        (method.lower(), path): route
        for path, route, _ in iter_api_routes(client.app)
        for method in route.methods
    }
    legacy_operations = [
        ("post", "/api/sboms"),
        ("post", "/analyze-sbom-nvd"),
        ("post", "/analyze-sbom-github"),
        ("post", "/analyze-sbom-osv"),
        ("post", "/analyze-sbom-vulndb"),
        ("post", "/analyze-sbom-consolidated"),
        ("get", "/api/v1/runs/{run_id}/ai-fixes/estimate"),
        ("get", "/api/v1/runs/{run_id}/ai-fixes/progress"),
        ("post", "/api/v1/runs/{run_id}/ai-fixes/cancel"),
        ("get", "/api/v1/runs/{run_id}/ai-fixes/stream"),
        ("patch", "/api/platform/users/{user_id}"),
    ]
    for method, path in legacy_operations:
        assert (method, path) in registered, f"Compatibility route removed: {method} {path}"
        assert registered[(method, path)].deprecated is True
        assert method not in paths.get(path, {}), f"Deprecated route still in Swagger: {method} {path}"

    successors = [
        ("post", "/api/sboms/upload"),
        ("post", "/api/sboms/{sbom_id}/analyze"),
        ("post", "/api/v1/runs/{run_id}/ai-fixes/estimate"),
        ("get", "/api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}"),
        ("post", "/api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/cancel"),
        ("get", "/api/v1/runs/{run_id}/ai-fixes/batches/{batch_id}/stream"),
        ("patch", "/api/platform/users/{user_id}/status"),
    ]
    for method, path in successors:
        assert method in paths.get(path, {}), f"Supported successor missing: {method} {path}"
    assert "get" in paths["/api/sboms"]
