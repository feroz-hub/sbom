"""Documentation security must match the existing method/path access policy."""

from copy import deepcopy

from app.core.route_policies import ROUTE_POLICIES
from fastapi import FastAPI
from fastapi.openapi.models import OpenAPI
from starlette.routing import compile_path


def test_openapi_security_and_parameters(client, app):
    response = client.get('/openapi.json')
    assert response.status_code == 200
    schema = response.json()
    OpenAPI.model_validate(schema)
    assert schema['openapi'] == '3.1.0'
    assert schema['components']['securitySchemes']['BearerAuth'] == {
        'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT',
    }
    assert 'security' not in schema

    # Compare against FastAPI's unmodified generator to protect every request,
    # response, tenant header and other parameter from documentation regressions.
    cached = app.openapi_schema
    try:
        app.openapi_schema = None
        original = deepcopy(FastAPI.openapi(app))
    finally:
        app.openapi_schema = cached
    expected = deepcopy(original)
    expected['components'].setdefault('securitySchemes', {})['BearerAuth'] = {
        'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT',
    }
    policies = {
        f'{method} {compile_path(path)[1]}': policy
        for key, policy in ROUTE_POLICIES.items()
        for method, path in [key.split(' ', 1)]
    }
    protected = public = 0
    for path, item in expected['paths'].items():
        for method, operation in item.items():
            policy = policies[f'{method.upper()} {path}']
            if policy == 'public':
                public += 1
                assert 'security' not in schema['paths'][path][method]
                continue
            protected += 1
            operation['security'] = [{'BearerAuth': []}]
            if 'parameters' in operation:
                operation['parameters'] = [
                    parameter for parameter in operation['parameters']
                    if not (parameter.get('in') == 'header' and parameter['name'].lower() == 'authorization')
                ]
    assert protected > 0 and public > 0
    assert schema == expected
    assert app.openapi() is cached
    assert any(
        parameter['name'] == 'X-Tenant-ID'
        for item in schema['paths'].values()
        for operation in item.values()
        for parameter in operation.get('parameters', [])
    )
    assert '/docs' in client.get('/docs').text
