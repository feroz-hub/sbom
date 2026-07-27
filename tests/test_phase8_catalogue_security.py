from app.core.security import permission_for_request
from starlette.requests import Request


def _request(path: str, method: str):
    return Request(
        {
            "type": "http",
            "path": path,
            "method": method,
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "client": ("test", 1),
            "scheme": "http",
        }
    )


def test_catalog_routes_have_distinct_read_and_manage_permissions():
    path = "/api/platform/authorization/roles/1"
    assert permission_for_request(_request(path, "GET")) == "platform:authorization:read"
    assert permission_for_request(_request(path, "PATCH")) == "platform:authorization:manage"


def test_database_is_secure_default(monkeypatch):
    monkeypatch.delenv("AUTHORIZATION_CATALOG_MODE", raising=False)
    from app.settings import Settings

    assert Settings().authorization_catalog_mode == "DATABASE"
    assert Settings().authorization_catalog_fail_closed is True
