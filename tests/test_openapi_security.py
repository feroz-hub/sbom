"""Documentation security must match the existing method/path access policy."""

from copy import deepcopy
from types import SimpleNamespace

from app.core.route_policies import ROUTE_POLICIES
from app.public_api import install_public_openapi
from fastapi import FastAPI
from fastapi.openapi.models import OpenAPI
from starlette.routing import compile_path


def test_openapi_security_and_parameters(client, app):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    OpenAPI.model_validate(schema)
    assert schema["openapi"] == "3.1.0"
    assert schema["components"]["securitySchemes"]["BearerAuth"] == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    assert "security" not in schema

    # Compare against FastAPI's unmodified generator to protect every request,
    # response, tenant header and other parameter from documentation regressions.
    cached = app.openapi_schema
    try:
        app.openapi_schema = None
        original = deepcopy(FastAPI.openapi(app))
    finally:
        app.openapi_schema = cached
    # Security decorates the already-published UUID wire contract. Testing it
    # against FastAPI's internal integer-domain schema predates that boundary.
    # UUID correctness is independently asserted below and through HTTP tests.
    public_contract = SimpleNamespace(openapi=lambda raw=original: deepcopy(raw))
    install_public_openapi(public_contract)
    expected = public_contract.openapi()
    project_id = schema["components"]["schemas"]["ProjectOut"]["properties"]["id"]
    run_id = schema["components"]["schemas"]["AnalysisRunOut"]["properties"]["id"]
    assert project_id["type"] == "string" and project_id["format"] == "uuid"
    assert run_id["type"] == "string" and run_id["format"] == "uuid"

    expected["components"].setdefault("securitySchemes", {})["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    policies = {
        f"{method} {compile_path(path)[1]}": policy
        for key, policy in ROUTE_POLICIES.items()
        for method, path in [key.split(" ", 1)]
    }
    protected = public = 0
    for path, item in expected["paths"].items():
        for method, operation in item.items():
            policy = policies[f"{method.upper()} {path}"]
            if policy == "public":
                public += 1
                assert "security" not in schema["paths"][path][method]
                continue
            protected += 1
            operation["security"] = [{"BearerAuth": []}]
            if "parameters" in operation:
                operation["parameters"] = [
                    parameter
                    for parameter in operation["parameters"]
                    if not (parameter.get("in") == "header" and parameter["name"].lower() == "authorization")
                ]
    assert protected > 0 and public > 0
    assert schema == expected
    assert app.openapi() is cached
    assert any(
        parameter["name"] == "X-Tenant-ID"
        for item in schema["paths"].values()
        for operation in item.values()
        for parameter in operation.get("parameters", [])
    )
    assert "/docs" in client.get("/docs").text
