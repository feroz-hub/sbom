"""
HCL IAM authentication + multi-tenant context resolution tests.

Covers:
  * validate_hcl_token() with RSA-signed JWTs
  * get_current_user() with auth enabled/disabled
  * _resolve_context() tenant membership resolution
  * Token claim extraction (roles, tenant)
  * Startup validation (validate_hcl_auth_setup)

Uses in-process RSA key pairs and PyJWKClient mocking — no network calls.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from jwt import InvalidTokenError
from app.core.security import (
    _claim,
    _resolve_context,
    _roles,
    get_current_user,
    validate_hcl_token,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

# ─── RSA key fixture (session-scoped) ─────────────────────────────────────────


@pytest.fixture(scope="session")
def rsa_keypair():
    """Generate an RSA key pair for test JWT signing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="session")
def rsa_private_pem(rsa_keypair):
    priv, _ = rsa_keypair
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def rsa_public_jwk(rsa_keypair):
    """Return a JWK dict for the public key (for mocking JWKS)."""
    from jwt.algorithms import RSAAlgorithm

    _, pub = rsa_keypair
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk_dict["kid"] = "test-kid-001"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return jwk_dict


def _make_token(
    private_key,
    *,
    sub: str = "ext-user-001",
    email: str = "test@hcl.example.com",
    name: str = "Test User",
    roles: list[str] | None = None,
    tenant: str = "local-default",
    issuer: str = "https://iam.hcl.example.com/realms/sbom",
    audience: str = "sbom-analyzer",
    exp_offset: int = 3600,
    extra: dict | None = None,
) -> str:
    """Build an RS256-signed JWT for testing."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "email": email,
        "name": name,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now - 10,
        "exp": now + exp_offset,
        "realm_access": {"roles": roles or ["SECURITY_ANALYST"]},
        "tenant_id": tenant,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-kid-001"})


# ─── Helpers ──────────────────────────────────────────────────────────────────


class TestClaimExtraction:
    """Test the _claim() dot-path resolver."""

    def test_simple_path(self):
        assert _claim({"sub": "user1"}, "sub") == "user1"

    def test_nested_path(self):
        claims = {"realm_access": {"roles": ["ADMIN", "VIEWER"]}}
        assert _claim(claims, "realm_access.roles") == ["ADMIN", "VIEWER"]

    def test_missing_path(self):
        assert _claim({"sub": "x"}, "nonexistent") is None

    def test_deeply_missing(self):
        assert _claim({"a": {"b": 1}}, "a.b.c") is None


class TestRoleNormalization:
    """Test _roles() extraction and normalization."""

    def test_list_input(self):
        result = _roles(["ADMIN", "viewer", "Security-Analyst"])
        assert result == frozenset({"ADMIN", "VIEWER", "SECURITY_ANALYST"})

    def test_csv_string(self):
        result = _roles("ADMIN,viewer")
        assert result == frozenset({"ADMIN", "VIEWER"})

    def test_semicolon_delimited(self):
        result = _roles("ADMIN;viewer")
        assert result == frozenset({"ADMIN", "VIEWER"})

    def test_empty(self):
        assert _roles(None) == frozenset()
        assert _roles([]) == frozenset()
        assert _roles("") == frozenset()


# ─── Token validation ────────────────────────────────────────────────────────


class TestValidateHclToken:
    """Test validate_hcl_token() with RSA-signed JWTs."""

    @pytest.fixture(autouse=True)
    def _setup_settings(self, monkeypatch, rsa_public_jwk):
        """Configure HCL IAM settings for token validation."""
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com/realms/sbom")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.hcl.example.com/realms/sbom/protocol/openid-connect/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        monkeypatch.setenv("HCL_IAM_ALLOWED_ALGORITHMS", "RS256")
        monkeypatch.setenv("HCL_IAM_ROLE_CLAIM", "realm_access.roles")
        monkeypatch.setenv("HCL_IAM_TENANT_CLAIM", "tenant_id")

        from app.settings import reset_settings

        reset_settings()

        # Mock JWKS client to return our test key
        mock_signing_key = MagicMock()
        from jwt.algorithms import RSAAlgorithm

        mock_signing_key.key = RSAAlgorithm.from_jwk(json.dumps(rsa_public_jwk))

        mock_jwks = MagicMock()
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key
        self.mock_jwks = mock_jwks

        self._jwks_patcher = patch("app.core.security.get_jwks_client", return_value=mock_jwks)
        self._jwks_patcher.start()
        yield
        self._jwks_patcher.stop()

    def test_valid_token_returns_claims(self, rsa_keypair):
        priv, _ = rsa_keypair
        token = _make_token(priv, sub="ext-user-001", email="test@hcl.example.com")
        claims = validate_hcl_token(token)
        assert claims["sub"] == "ext-user-001"
        assert claims["email"] == "test@hcl.example.com"

    def test_expired_token_raises_401(self, rsa_keypair):
        priv, _ = rsa_keypair
        token = _make_token(priv, exp_offset=-100)  # already expired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(token)
        assert exc_info.value.status_code == 401

    def test_empty_sub_raises_401(self, rsa_keypair):
        priv, _ = rsa_keypair
        token = _make_token(priv, sub="   ")
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(token)
        assert exc_info.value.status_code == 401

    def test_non_string_email_raises_401(self, rsa_keypair):
        priv, _ = rsa_keypair
        token = _make_token(priv, extra={"email": 123})
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(token)
        assert exc_info.value.status_code == 401

    @pytest.mark.parametrize(
        ("overrides", "label"),
        [
            ({"issuer": "https://wrong-issuer.example"}, "issuer"),
            ({"audience": "wrong-audience"}, "audience"),
            ({"exp_offset": -100}, "expiration"),
        ],
    )
    def test_invalid_mandatory_claims_raise_401(self, rsa_keypair, overrides, label):
        del label
        priv, _ = rsa_keypair
        token = _make_token(priv, **overrides)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(token)
        assert exc_info.value.status_code == 401
        assert exc_info.value.headers["WWW-Authenticate"].startswith("Bearer")

    def test_unsigned_or_unsupported_algorithm_is_rejected(self):
        token = pyjwt.encode(
            {"iss": "https://iam.hcl.example.com/realms/sbom", "sub": "user", "aud": "sbom-analyzer", "exp": int(time.time()) + 300},
            "not-an-asymmetric-key-32-bytes-long!",
            algorithm="HS256",
            headers={"kid": "test-kid-001"},
        )
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(token)
        assert exc_info.value.status_code == 401

    def test_unknown_kid_fails_closed(self, rsa_keypair):
        self.mock_jwks.get_signing_key_from_jwt.side_effect = InvalidTokenError("unknown kid")
        priv, _ = rsa_keypair
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            validate_hcl_token(_make_token(priv))
        assert exc_info.value.status_code == 401


class TestGetCurrentUser:
    """Test get_current_user() — the FastAPI dependency."""

    def test_auth_disabled_returns_dev_claims(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "false")
        from app.settings import reset_settings

        reset_settings()

        claims = get_current_user(authorization=None)
        assert claims["sub"] == "dev-user"
        assert claims["email"] == "dev@local"

    def test_missing_auth_header_raises_401(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com/realms/sbom")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.hcl.example.com/realms/sbom/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        from app.settings import reset_settings

        reset_settings()

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization=None)
        assert exc_info.value.status_code == 401

    def test_non_bearer_scheme_raises_401(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com/realms/sbom")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.hcl.example.com/realms/sbom/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        from app.settings import reset_settings

        reset_settings()

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization="Basic dXNlcjpwYXNz")
        assert exc_info.value.status_code == 401

    def test_empty_bearer_token_raises_401(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com/realms/sbom")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.hcl.example.com/realms/sbom/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        from app.settings import reset_settings

        reset_settings()

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization="Bearer ")
        assert exc_info.value.status_code == 401


class TestValidateHclAuthSetup:
    """Test validate_hcl_auth_setup() — startup configuration validator."""

    def test_disabled_auth_is_noop(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "false")
        from app.settings import reset_settings

        reset_settings()
        from app.core.security import validate_hcl_auth_setup

        validate_hcl_auth_setup()  # must not raise

    def test_missing_issuer_raises(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("HCL_IAM_ISSUER", "")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "https://iam.hcl.example.com/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        from app.settings import reset_settings

        reset_settings()
        from app.core.security import validate_hcl_auth_setup

        with pytest.raises(RuntimeError, match="HCL_IAM_ISSUER"):
            validate_hcl_auth_setup()

    def test_http_jwks_url_raises(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com/realms/sbom")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyzer")
        monkeypatch.setenv("HCL_IAM_JWKS_URL", "http://iam.hcl.example.com/certs")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-frontend")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        from app.settings import reset_settings

        reset_settings()
        from app.core.security import validate_hcl_auth_setup

        with pytest.raises(RuntimeError, match="HTTPS"):
            validate_hcl_auth_setup()

    def test_auth_rejects_dev_default_tenant(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("DEV_DEFAULT_TENANT", "true")
        monkeypatch.setenv("HCL_IAM_ISSUER", "https://iam.hcl.example.com")
        monkeypatch.setenv("HCL_IAM_AUDIENCE", "sbom-analyser-api")
        monkeypatch.setenv("HCL_IAM_CLIENT_ID", "sbom-analyser-web")
        from app.settings import reset_settings

        reset_settings()
        from app.core.security import validate_hcl_auth_setup

        with pytest.raises(RuntimeError, match="DEV_DEFAULT_TENANT"):
            validate_hcl_auth_setup()


class TestPrincipalTenantResolution:
    def test_unknown_tenant_and_missing_membership_return_403(self, monkeypatch):
        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
        monkeypatch.setenv("HCL_IAM_ROLE_CLAIM", "role")
        monkeypatch.setenv("HCL_IAM_TENANT_CLAIM", "tenant_id")
        from app.settings import reset_settings
        from app.db import SessionLocal

        reset_settings()
        with SessionLocal() as db:
            with pytest.raises(HTTPException) as exc_info:
                _resolve_context(db, {
                    "sub": f"unassigned-{time.time_ns()}",
                    "tenant_id": "unknown-tenant",
                    "role": ["SECURITY_ANALYST"],
                }, None)
            assert exc_info.value.status_code == 403
            db.rollback()

    def test_active_membership_role_is_authoritative(self, monkeypatch):
        from datetime import UTC, datetime
        from uuid import uuid4
        from app.db import SessionLocal
        from app.models import IAMUser, Tenant, TenantUser
        from app.settings import reset_settings

        monkeypatch.setenv("AUTH_ENABLED", "true")
        monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
        monkeypatch.setenv("HCL_IAM_ROLE_CLAIM", "role")
        monkeypatch.setenv("HCL_IAM_TENANT_CLAIM", "tenant_id")
        reset_settings()
        suffix = uuid4().hex
        now = datetime.now(UTC)
        with SessionLocal() as db:
            tenant = Tenant(name="Auth Tenant", slug=f"auth-{suffix}", external_iam_tenant_id=f"ext-{suffix}",
                            status="ACTIVE", created_at=now, updated_at=now)
            user = IAMUser(external_iam_user_id=f"subject-{suffix}", status="ACTIVE", created_at=now, updated_at=now)
            db.add_all([tenant, user]); db.flush()
            db.add(TenantUser(tenant_id=tenant.id, user_id=user.id, role="VIEWER", status="ACTIVE",
                              created_at=now, updated_at=now)); db.commit()
            context = _resolve_context(db, {
                "sub": user.external_iam_user_id, "tenant_id": tenant.external_iam_tenant_id,
                "role": ["SECURITY_ANALYST"],
            }, None)
            assert context.roles == frozenset({"VIEWER"})
            assert not context.has_permission("sbom:upload")
