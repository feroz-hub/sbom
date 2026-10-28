"""Centralized HTTP authentication and legacy configuration compatibility.

Historical node IDs are retained for the D0 recovery ledger. Protected routes
use signed HCL credentials and database roles, regardless of API_AUTH_MODE.
Only explicit local-development identity and isolated legacy startup-validator
unit tests use conftest's local mode. No authentication dependency is replaced.
"""

from __future__ import annotations

import pytest
from app.auth import AuthConfigError, _read_tokens, validate_auth_setup


@pytest.fixture
def secured(app, monkeypatch):
    """Real JWT validation and database RBAC; only the trusted key transport is fake.

    API_AUTH_MODE is legacy configuration, not a credential-validation path.
    These HTTP tests must explicitly enable the central pipeline instead of
    inheriting conftest's local development principal.
    """
    import time
    from types import SimpleNamespace

    import jwt
    from app.core import security
    from app.db import SessionLocal
    from app.settings import get_settings
    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient

    from tests.phase6_helpers import identity_claims, seed_membership, seed_user
    from tests.tenant_fixture_scope import verified_fixture_tenant

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings = get_settings()
    for name, value in dict(
        auth_enabled=True, dev_default_tenant=False, hcl_auth_enabled=True,
        native_auth_enabled=False, entra_enabled=False,
        hcl_iam_issuer="https://hcl-cs.test", hcl_iam_audience="sbom-test",
        hcl_iam_client_id="sbom-test", hcl_iam_clock_skew_seconds=0,
    ).items():
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(security, "get_jwks_client", lambda: SimpleNamespace(
        get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key())
    ))
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        user = seed_user(db)
        membership = seed_membership(db, user, role="TENANT_ADMIN")
        db.commit()
        now = int(time.time())
        claims = identity_claims(user, aud="sbom-test", iat=now, nbf=now - 1,
                                 exp=now + 300, tenant_id="local-default")
        user_id, membership_id = user.id, membership.id
    def sign(**overrides):
        return jwt.encode(claims | overrides, key, algorithm="RS256")
    validate_auth_setup()
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, token=sign(), sign=sign, claims=claims,
                              user_id=user_id, membership_id=membership_id)


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


def test_mode_bearer_rejects_missing_authorization_header(secured, monkeypatch):
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get("/api/types")
    assert resp.status_code == 401, resp.text
    assert resp.headers.get("www-authenticate", "").lower().startswith("bearer")
    assert resp.json() == {"detail": "Authentication required"}


def test_mode_bearer_rejects_malformed_authorization_header(secured, monkeypatch):
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    # Wrong scheme — should still 401, not 500
    resp = client.get("/api/types", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert resp.status_code == 401
    # Empty token after Bearer prefix
    resp = client.get("/api/types", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


def test_mode_bearer_rejects_unknown_token(secured, monkeypatch):
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get("/api/types", headers={"Authorization": "Bearer tok-NOPE"})
    assert resp.status_code == 401


def test_mode_bearer_accepts_valid_token(secured, monkeypatch):
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1,tok-good-2")
    resp = client.get(
        "/api/types",
        headers={"Authorization": f"Bearer {secured.token}"},
    )
    assert resp.status_code == 200, resp.text


def test_mode_bearer_accepts_token_with_case_insensitive_scheme(secured, monkeypatch):
    """Per RFC 6750 §2.1 the auth scheme matching is case-insensitive."""
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get(
        "/api/types",
        headers={"Authorization": f"bearer {secured.token}"},
    )
    assert resp.status_code == 200
    resp = client.get(
        "/api/types",
        headers={"Authorization": f"BEARER {secured.token}"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unprotected endpoints stay reachable in mode=bearer
# ---------------------------------------------------------------------------


def test_unprotected_routes_stay_open_in_bearer_mode(secured, monkeypatch):
    """
    `/`, `/health` are unprotected by design — liveness probes and
    `/docs` need to keep working without credentials.
    """
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("service") == "sbom-analyzer-api"

    resp = client.get("/health")
    assert resp.status_code == 200
    # Phase 6.2: /health was extended with an `nvd_mirror` status block.
    # This auth test only checks reachability + overall status — the
    # health-shape contract lives in tests/nvd_mirror/test_health_endpoint.py.
    assert resp.json().get("status") == "ok"


# ---------------------------------------------------------------------------
# Protected endpoints in health.py also enforce auth
# ---------------------------------------------------------------------------


def test_analysis_config_endpoint_is_protected(secured, monkeypatch):
    """
    `/api/analysis/config` exposes feature flags and env-var names — it
    must require auth in bearer mode even though it lives in the same
    router as the unprotected `/health`.
    """
    client = secured.client
    _set_auth_env(monkeypatch, mode="bearer", tokens="tok-good-1")
    resp = client.get("/api/analysis/config")
    assert resp.status_code == 401
    resp = client.get(
        "/api/analysis/config",
        headers={"Authorization": f"Bearer {secured.token}"},
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


def test_mode_jwt_accepts_valid_token(secured, monkeypatch):
    _set_auth_env(monkeypatch, mode="jwt")
    response = secured.client.get("/api/types", headers={"Authorization": f"Bearer {secured.token}"})
    assert response.status_code == 200, response.text


def test_mode_jwt_rejects_bad_signature(secured, monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    _set_auth_env(monkeypatch, mode="jwt")
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(secured.claims, foreign_key, algorithm="RS256")
    response = secured.client.get("/api/types", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


@pytest.mark.parametrize("mode", ["none", "bearer", "jwt"])
def test_legacy_mode_cannot_disable_central_authentication(secured, monkeypatch, mode):
    _set_auth_env(monkeypatch, mode=mode, tokens="static-token-is-not-a-principal")
    assert secured.client.get("/api/types").status_code == 401
    assert secured.client.get("/api/types", headers={"Authorization": "Bearer static-token-is-not-a-principal"}).status_code == 401
    assert secured.client.get("/api/types", headers={"Authorization": f"Bearer {secured.token}"}).status_code == 200


@pytest.mark.parametrize("change", ["expired", "wrong_issuer", "wrong_audience"])
def test_rejected_credentials_cannot_mutate_business_data(secured, change):
    import time

    from app.db import SessionLocal
    from app.models import Projects
    from sqlalchemy import func, select

    from tests.tenant_fixture_scope import verified_fixture_tenant

    changes = {"expired": {"exp": int(time.time()) - 60},
               "wrong_issuer": {"iss": "https://foreign.test"},
               "wrong_audience": {"aud": "another-application"}}
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        before = db.scalar(select(func.count()).select_from(Projects))
    response = secured.client.post("/api/projects", json={"project_name": "denied"},
                                   headers={"Authorization": f"Bearer {secured.sign(**changes[change])}"})
    assert response.status_code == 401
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.scalar(select(func.count()).select_from(Projects)) == before


@pytest.mark.parametrize("revocation", ["disabled_user", "removed_membership"])
def test_authenticated_principal_revocation_is_immediate(secured, revocation):
    from app.db import SessionLocal
    from app.models import IAMUser, Projects, TenantUser
    from sqlalchemy import func, select

    from tests.tenant_fixture_scope import verified_fixture_tenant

    headers = {"Authorization": f"Bearer {secured.token}"}
    assert secured.client.get("/api/types", headers=headers).status_code == 200
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        before = db.scalar(select(func.count()).select_from(Projects))
        if revocation == "disabled_user":
            db.get(IAMUser, secured.user_id).status = "DISABLED"
        else:
            db.delete(db.get(TenantUser, secured.membership_id))
        db.commit()
    assert secured.client.post("/api/projects", headers=headers, json={"project_name": "denied"}).status_code == 403
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.scalar(select(func.count()).select_from(Projects)) == before


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize("mode", ["none", "bearer", "jwt"])
def test_production_disabled_authentication_fails_startup(monkeypatch, environment, mode):
    from app.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "app_environment", environment)
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setenv("API_AUTH_MODE", mode)
    with pytest.raises(RuntimeError, match="AUTH_ENABLED must be true"):
        validate_auth_setup()


@pytest.mark.parametrize("setting,value", [
    ("native_auth_enabled", True), ("entra_enabled", True),
    ("native_iam_production", True), ("dev_default_tenant", False),
])
def test_disabled_auth_cannot_silently_override_enabled_providers(monkeypatch, setting, value):
    from app.settings import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "app_environment", "test")
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(settings, setting, value)
    with pytest.raises(RuntimeError, match="AUTH_ENABLED must be true"):
        validate_auth_setup()
