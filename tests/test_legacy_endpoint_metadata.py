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


def test_legacy_routes_are_marked_deprecated_in_openapi(client):
    paths = client.get("/openapi.json").json()["paths"]
    for path in (
        "/api/sboms",
        "/analyze-sbom-nvd",
        "/analyze-sbom-github",
        "/analyze-sbom-osv",
        "/analyze-sbom-vulndb",
        "/analyze-sbom-consolidated",
    ):
        assert paths[path]["post"]["deprecated"] is True
