"""
Bearer-token authentication tests (Finding A).

Covers:

  * mode=none — every request goes through, no auth header required
  * mode=bearer — missing/malformed/unknown token returns 401
  * mode=bearer — valid token returns 200
  * mode=bearer — case-insensitive scheme matching (RFC 6750 §2.1)
  * Unprotected ``/`` and ``/health`` stay reachable in bearer mode
  * Route-level protection on ``/api/analysis/config`` works even though
    it shares a router with the unprotected health endpoints
  * ``validate_auth_setup`` startup validator behaviour:
      - mode=none → no-op
      - mode=bearer + tokens → ok
      - mode=bearer + no tokens → AuthConfigError
      - unknown mode → AuthConfigError

``API_AUTH_MODE`` / ``API_AUTH_TOKENS`` are read from ``os.environ`` each
request so ``monkeypatch.setenv`` works. JWT validation reads secrets from
``get_settings()`` — call ``reset_settings()`` when tests change JWT env vars.
"""

from __future__ import annotations

import pytest
from app.auth import AuthConfigError, _read_tokens, validate_auth_setup


def _set_auth_env(monkeypatch, *, mode: str, tokens: str = "") -> None:
    """Set the auth env vars for the duration of the current test."""
    monkeypatch.setenv("API_AUTH_MODE", mode)
    if tokens:
        monkeypatch.setenv("API_AUTH_TOKENS", tokens)
    else:
        monkeypatch.delenv("API_AUTH_TOKENS", raising=False)


# ---------------------------------------------------------------------------
# Mode = none
# ---------------------------------------------------------------------------


def test_mode_none_lets_unauthenticated_requests_through(client, monkeypatch):
    _set_auth_env(monkeypatch, mode="none")
    resp = client.get("/api/types")
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Mode = bearer
# ---------------------------------------------------------------------------


def test_mode_bearer_rejects_missing_authorization_header(client, monkeypatch):
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get("/api/types")
    assert resp.status_code == 401, resp.text
    assert resp.headers.get("www-authenticate", "").lower().startswith("bearer")
    assert resp.json() == {"detail": "Authentication required"}


def test_mode_bearer_rejects_malformed_authorization_header(client, monkeypatch):
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    # Wrong scheme — should still 401, not 500
    resp = client.get("/api/types", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert resp.status_code == 401
    # Empty token after Bearer prefix
    resp = client.get("/api/types", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


def test_mode_bearer_rejects_unknown_token(client, monkeypatch):
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get("/api/types", headers={"Authorization": "Bearer tok-NOPE"})
    assert resp.status_code == 401


def test_mode_bearer_accepts_valid_token(client, monkeypatch):
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get(
        "/api/types",
        headers={"Authorization": "Bearer tok-good-2"},
    )
    assert resp.status_code == 200, resp.text


def test_mode_bearer_accepts_token_with_case_insensitive_scheme(client, monkeypatch):
    """Per RFC 6750 §2.1 the auth scheme matching is case-insensitive."""
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get(
        "/api/types",
        headers={"Authorization": "bearer tok-good-1"},
    )
    assert resp.status_code == 200
    resp = client.get(
        "/api/types",
        headers={"Authorization": "BEARER tok-good-1"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unprotected endpoints stay reachable in mode=bearer
# ---------------------------------------------------------------------------


def test_unprotected_routes_stay_open_in_bearer_mode(client, monkeypatch):
    """
    `/`, `/health` are unprotected by design — liveness probes and
    `/docs` need to keep working without credentials.
    """
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("service") == "sbom-analyzer-api"

    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Protected endpoints in health.py also enforce auth
# ---------------------------------------------------------------------------


def test_analysis_config_endpoint_is_protected(client, monkeypatch):
    """
    `/api/analysis/config` exposes feature flags and env-var names — it
    must require auth in bearer mode even though it lives in the same
    router as the unprotected `/health`.
    """
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get("/api/analysis/config")
    assert resp.status_code == 401
    resp = client.get(
        "/api/analysis/config",
        headers={"Authorization": "Bearer tok-good-1"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Startup validator
# ---------------------------------------------------------------------------


def test_validate_auth_setup_raises_when_bearer_mode_has_no_tokens(monkeypatch):
    """
    Defence-in-depth: if ops set API_AUTH_MODE=bearer but forgot to
    populate API_AUTH_TOKENS, the server must REFUSE to start. The
    alternative — silently letting every request through — would be
    the worst possible failure mode.
    """
    monkeypatch.setenv("API_AUTH_MODE", "bearer")
    monkeypatch.delenv("API_AUTH_TOKENS", raising=False)
    with pytest.raises(AuthConfigError, match="API_AUTH_TOKENS is empty"):
        validate_auth_setup()


def test_validate_auth_setup_raises_on_unknown_mode(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "magic")
    monkeypatch.setenv("API_AUTH_TOKENS", "tok")
    with pytest.raises(AuthConfigError, match="Unsupported API_AUTH_MODE"):
        validate_auth_setup()


def test_validate_auth_setup_passes_when_bearer_mode_has_tokens(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "bearer")
    monkeypatch.setenv("API_AUTH_TOKENS", "tok-1,tok-2,tok-3")
    validate_auth_setup()  # must not raise
    assert _read_tokens() == {"tok-1", "tok-2", "tok-3"}


def test_validate_auth_setup_no_op_in_none_mode(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "none")
    monkeypatch.delenv("API_AUTH_TOKENS", raising=False)
    validate_auth_setup()  # must not raise


# ---------------------------------------------------------------------------
# Mode = jwt
# ---------------------------------------------------------------------------


def test_validate_auth_setup_passes_when_jwt_mode_has_secret(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "jwt")
    monkeypatch.setenv("JWT_SECRET_KEY", "ok-secret")
    from app.settings import reset_settings

    reset_settings()
    validate_auth_setup()


def test_validate_auth_setup_jwt_requires_secret(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "jwt")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    from app.settings import reset_settings

    reset_settings()
    with pytest.raises(AuthConfigError, match="JWT_SECRET_KEY"):
        validate_auth_setup()


def test_mode_jwt_accepts_valid_token(app, monkeypatch):
    import jwt as pyjwt

    monkeypatch.setenv("API_AUTH_MODE", "jwt")
    monkeypatch.setenv("JWT_SECRET_KEY", "unit-test-secret")
    from app.settings import reset_settings

    reset_settings()
    token = pyjwt.encode({"sub": "test"}, "unit-test-secret", algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/api/types", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


def test_mode_jwt_rejects_bad_signature(app, monkeypatch):
    import jwt as pyjwt

    monkeypatch.setenv("API_AUTH_MODE", "jwt")
    monkeypatch.setenv("JWT_SECRET_KEY", "unit-test-secret")
    from app.settings import reset_settings

    reset_settings()
    token = pyjwt.encode({"sub": "x"}, "wrong-secret", algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/api/types", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
