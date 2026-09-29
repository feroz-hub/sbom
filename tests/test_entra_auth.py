"""Real RSA verification and PostgreSQL provisioning, without Microsoft network calls."""
import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock
from uuid import uuid4

import jwt
import pytest
from app.core.security import _resolve_context, get_current_claims
from app.models import AuthorizationAuditLog, IAMUser, NativeUserCredential, PlatformUserRole, TenantUser, UserIdentity
from app.services import entra_auth_service as entra
from app.services import platform_service
from app.services.auth_context_service import resolve_authorization_state
from app.services.authenticated_principal_service import resolve_principal
from app.settings import get_settings
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.phase6_helpers import seed_membership, seed_user


@pytest.fixture
def entra_setup(monkeypatch):
    settings = get_settings()
    for key, value in {
        "auth_enabled": True, "dev_default_tenant": False, "entra_enabled": True,
        "entra_tenant_id": "11111111-1111-4111-8111-111111111111",
        "entra_frontend_client_id": "22222222-2222-4222-8222-222222222222",
        "entra_api_client_id": "33333333-3333-4333-8333-333333333333",
        "entra_api_scope": "api://33333333-3333-4333-8333-333333333333/access_as_user",
        "hcl_auth_enabled": False,
    }.items():
        monkeypatch.setattr(settings, key, value)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid="entra-test-key", use="sig", alg="RS256", issuer=entra.issuer())
    client = jwt.PyJWKClient("https://login.microsoftonline.com/test/keys")
    monkeypatch.setattr(client, "fetch_data", lambda: {"keys": [jwk]})
    monkeypatch.setattr(entra, "_jwks_client", lambda _tenant: client)
    claims = {
        "iss": entra.issuer(), "aud": settings.entra_api_client_id,
        "tid": settings.entra_tenant_id, "azp": settings.entra_frontend_client_id,
        "oid": str(uuid4()), "sub": "opaque-pairwise-subject", "ver": "2.0", "acct": 0,
        "exp": int(time.time()) + 3600, "iat": int(time.time()), "nbf": int(time.time()) - 5,
        "scp": "access_as_user", "email": "feroze@example.test", "name": "Feroze",
        "roles": ["PLATFORM_ADMIN", "TENANT_ADMIN"], "groups": ["untrusted-role-group"],
    }
    def token(**overrides):
        return jwt.encode({**claims, **overrides}, private, algorithm="RS256", headers={"kid": jwk["kid"]})
    return claims, token


def test_valid_access_token_routes_to_fixed_validator(entra_setup):
    claims, token = entra_setup
    assert get_current_claims(f"Bearer {token()}")["oid"] == claims["oid"]


@pytest.mark.parametrize("override", [
    {"tid": "44444444-4444-4444-8444-444444444444"}, {"iss": "https://attacker.test"},
    {"aud": "22222222-2222-4222-8222-222222222222"}, {"aud": ["33333333-3333-4333-8333-333333333333"]},
    {"exp": 1}, {"nbf": 9999999999}, {"scp": "other_scope"}, {"scp": None},
    {"oid": None}, {"oid": "email@example.test"}, {"sub": ""}, {"acct": 1}, {"acct": None},
    {"acct": False}, {"idtyp": "app"}, {"ver": "1.0"}, {"azp": "44444444-4444-4444-8444-444444444444"},
])
def test_invalid_token_claims_rejected(entra_setup, override):
    _, token = entra_setup
    with pytest.raises(HTTPException) as error:
        get_current_claims(f"Bearer {token(**override)}")
    assert error.value.status_code == 401


def test_signature_algorithm_unknown_kid_and_missing_claim_rejected(entra_setup):
    claims, _ = entra_setup
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tokens = [
        jwt.encode(claims, other, algorithm="RS256", headers={"kid": "entra-test-key"}),
        jwt.encode(claims, other, algorithm="RS256", headers={"kid": "unknown"}),
        jwt.encode(claims, "not-an-rsa-key", algorithm="HS256", headers={"kid": "entra-test-key"}),
    ]
    for token in tokens:
        with pytest.raises(HTTPException) as error:
            entra.validate_token(token)
        assert token not in str(error.value)


def test_first_login_pending_no_authority_and_same_email_not_linked(entra_setup):
    from app.db import SessionLocal
    claims, token = entra_setup
    with SessionLocal() as db:
        existing = seed_user(db, email=claims["email"])
        db.commit()
        principal = resolve_principal(db, entra.validate_token(token()))
        user = principal.user
        assert user.id != existing.id
        assert principal.provider == "MICROSOFT_ENTRA"
        assert user.status == "PENDING"
        assert user.external_subject is None and user.external_issuer is None
        identity = db.scalar(select(UserIdentity).where(UserIdentity.user_id == user.id))
        assert identity.subject == claims["oid"] and identity.issuer == claims["iss"]
        assert resolve_authorization_state(db, user, provider=principal.provider).status == "USER_ACCESS_PENDING"
        for model in (NativeUserCredential, PlatformUserRole, TenantUser):
            assert db.scalar(select(func.count()).select_from(model).where(model.user_id == user.id)) == 0
        events = list(db.scalars(select(AuthorizationAuditLog.action).where(AuthorizationAuditLog.target_user_id == user.id)))
        assert "IAM_USER_PROVISIONED" in events and "IAM_EXTERNAL_IDENTITY_LINKED" in events
        repeated = resolve_principal(db, entra.validate_token(token(email="changed@example.test")))
        assert repeated.user.id == user.id
        assert db.scalar(select(func.count()).select_from(UserIdentity)) == 1


@pytest.mark.parametrize(("status", "state", "code"), [
    ("PENDING", "USER_ACCESS_PENDING", "USER_ACCESS_PENDING"),
    ("DISABLED", "ACCOUNT_DISABLED", "IAM_ACCOUNT_DISABLED"),
    ("SUSPENDED", "USER_SUSPENDED", "USER_SUSPENDED"),
    ("ACTIVE", "NO_TENANT", "IAM_NO_TENANT"),
])
def test_local_status_overrides_token_without_recreating_user(entra_setup, status, state, code):
    from app.db import SessionLocal
    claims, _ = entra_setup
    with SessionLocal() as db:
        user = resolve_principal(db, claims).user
        uid = user.id
        user.status = status
        db.commit()
        assert resolve_authorization_state(db, user, provider="MICROSOFT_ENTRA").status == state
        with pytest.raises(HTTPException) as error:
            _resolve_context(db, claims, None)
        assert error.value.detail["code"] == code
        assert db.scalar(select(func.count()).select_from(UserIdentity).where(UserIdentity.user_id == uid)) == 1


def test_approval_does_not_assign_authority_and_tenant_permission_isolation(entra_setup):
    from app.db import SessionLocal
    claims, _ = entra_setup
    with SessionLocal() as db:
        user = resolve_principal(db, claims).user
        platform_service.update_user_status(db, user.id, "ACTIVE")
        db.commit()
        assert resolve_authorization_state(db, user, provider="MICROSOFT_ENTRA").status == "NO_TENANT"
        seed_membership(db, user, role="VIEWER")
        db.commit()
        context = _resolve_context(db, claims, "1")
        assert context.user_id == user.id
        assert context.roles == frozenset({"VIEWER"})
        assert not context.is_platform_admin
        assert context.has_permission("project:read")
        assert not context.has_permission("project:write")
        with pytest.raises(HTTPException) as error:
            _resolve_context(db, claims, "99999")
        assert error.value.detail["code"] == "IAM_UNAUTHORIZED_TENANT"


def test_concurrent_first_login_has_one_user_and_identity(entra_setup):
    from app.db import SessionLocal
    claims, _ = entra_setup
    barrier = Barrier(2)
    def login():
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            return resolve_principal(db, claims).user.id
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: login(), range(2)))
    assert len(set(results)) == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(UserIdentity)) == 1
        assert db.scalar(select(func.count()).select_from(IAMUser).where(IAMUser.email == claims["email"])) == 1


def test_audit_failure_rolls_back_user_and_identity(entra_setup, monkeypatch):
    from app.db import SessionLocal
    claims, _ = entra_setup
    monkeypatch.setattr(entra.audit_service, "write_authorization_audit", Mock(side_effect=RuntimeError("audit unavailable")))
    with SessionLocal() as db:
        with pytest.raises(RuntimeError):
            resolve_principal(db, claims)
        assert db.scalar(select(func.count()).select_from(UserIdentity)) == 0
        assert db.scalar(select(func.count()).select_from(IAMUser).where(IAMUser.email == claims["email"])) == 0


@pytest.mark.parametrize("field,value", [("entra_tenant_id", "common"), ("entra_frontend_client_id", ""), ("entra_api_client_id", ""), ("entra_api_scope", ""), ("entra_api_scope", "api://example/.default"), ("auth_enabled", False), ("dev_default_tenant", True)])
def test_configuration_fails_closed(entra_setup, monkeypatch, field, value):
    settings = get_settings()
    monkeypatch.setattr(settings, field, value)
    with pytest.raises(RuntimeError, match="configuration invalid"):
        entra.validate_configuration()


def test_disabled_provider_needs_no_configuration(entra_setup, monkeypatch):
    settings = get_settings()
    _, token = entra_setup
    monkeypatch.setattr(settings, "entra_enabled", False)
    monkeypatch.setattr(settings, "entra_tenant_id", "")
    entra.validate_configuration()
    with pytest.raises(HTTPException):
        get_current_claims(f"Bearer {token()}")


def test_session_and_context_endpoint_pending_and_business_denial(client, entra_setup):
    _, token = entra_setup
    headers = {"Authorization": f"Bearer {token()}"}
    session = client.get("/api/auth/entra/session", headers=headers)
    assert session.status_code == 200
    assert session.json()["status"] == "USER_ACCESS_PENDING"
    context = client.get("/api/auth/context", headers=headers)
    assert context.status_code == 200 and context.json()["status"] == "USER_ACCESS_PENDING"
    assert client.get("/api/tenants", headers=headers).status_code == 403
    assert client.get("/api/platform/users", headers=headers).status_code == 403


def test_display_metadata_is_optional(entra_setup):
    from app.db import SessionLocal
    claims, _ = entra_setup
    with SessionLocal() as db:
        user = resolve_principal(db, {**claims, "email": "not an address", "name": None}).user
        assert user.status == "PENDING" and user.email is None and user.display_name == "Microsoft Entra user"


def test_directory_identity_is_not_mailbox_verification(entra_setup):
    from app.db import SessionLocal
    from app.services.identity_verification_policy import verification_complete, verification_complete_clause
    claims, _ = entra_setup
    with SessionLocal() as db:
        user = resolve_principal(db, claims).user
        assert user.email_verified is False and user.email_verified_at is None
        assert verification_complete(user)
        assert db.scalar(select(IAMUser.id).where(IAMUser.id == user.id, verification_complete_clause())) == user.id
        user.verification_required = True
        db.flush()
        assert not verification_complete(user)
        assert db.scalar(select(IAMUser.id).where(IAMUser.id == user.id, verification_complete_clause())) is None


def test_approval_suspension_and_resume_use_existing_admin_api(client, entra_setup, monkeypatch):
    from app.core.context import CurrentContext
    from app.core.security import get_current_tenant_context
    from app.db import SessionLocal
    from app.services import audit_service

    from tests.phase6_helpers import seed_platform_grant
    claims, _ = entra_setup
    with SessionLocal() as db:
        admin = seed_user(db)
        seed_platform_grant(db, admin)
        db.commit()
        uid = resolve_principal(db, claims).user.id
        admin_id = admin.id
    context = CurrentContext(user_id=admin_id, external_user_id='admin', email=None, display_name=None, tenant_id=None, external_tenant_id=None,
        roles=frozenset({'PLATFORM_ADMIN'}), permissions=frozenset({'platform:user:manage_status', 'platform:user:read'}), is_platform_admin=True)
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        directory = client.get('/api/platform/users?provider=MICROSOFT_ENTRA&local_status=PENDING')
        assert directory.status_code == 200
        assert [u['id'] for u in directory.json()['items']] == [uid]
        for status in ('ACTIVE', 'SUSPENDED', 'ACTIVE', 'DISABLED'):
            response = client.patch(f'/api/platform/users/{uid}/status', json={'status': status})
            assert response.status_code == 200, response.text
            with SessionLocal() as db:
                assert db.get(IAMUser, uid).status == status
                assert db.scalar(select(func.count()).select_from(TenantUser).where(TenantUser.user_id == uid)) == 0
        with SessionLocal() as db:
            events = set(db.scalars(select(AuthorizationAuditLog.action).where(AuthorizationAuditLog.target_user_id == uid)))
            assert {'PLATFORM_USER_ACTIVATED', 'USER_SUSPENDED', 'USER_DISABLED'}.issubset(events)
        monkeypatch.setattr(audit_service, 'write_authorization_audit', Mock(side_effect=RuntimeError('audit unavailable')))
        with pytest.raises(RuntimeError):
            client.patch(f'/api/platform/users/{uid}/status', json={'status': 'ACTIVE'})
        with SessionLocal() as db:
            assert db.get(IAMUser, uid).status == 'DISABLED'
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_signing_key_issuer_is_bound_to_configured_directory(entra_setup, monkeypatch):
    _, token = entra_setup
    client = entra._jwks_client(get_settings().entra_tenant_id)
    key = client.get_signing_key_from_jwt(token())
    key._jwk_data['issuer'] = 'https://attacker.test'
    monkeypatch.setattr(client, 'get_signing_key_from_jwt', lambda _token: key)
    with pytest.raises(HTTPException):
        entra.validate_token(token())


def test_required_claims_cannot_be_omitted(entra_setup, monkeypatch):
    claims, _ = entra_setup
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid='required-claims', use='sig', alg='RS256')
    client = entra._jwks_client(get_settings().entra_tenant_id)
    monkeypatch.setattr(client, 'fetch_data', lambda: {'keys': [jwk]})
    for field in ('exp', 'iat', 'tid', 'oid', 'sub', 'scp', 'azp', 'acct'):
        payload = {key: value for key, value in claims.items() if key != field}
        token = jwt.encode(payload, private, algorithm='RS256', headers={'kid': 'required-claims'})
        with pytest.raises(HTTPException):
            entra.validate_token(token)


def test_entra_only_startup_and_missing_token_are_fail_closed(entra_setup, monkeypatch):
    from app.auth import validate_auth_setup
    settings = get_settings()
    monkeypatch.setattr(settings, 'native_auth_enabled', False)
    validate_auth_setup()
    with pytest.raises(HTTPException):
        get_current_claims(None)


def test_directory_admin_counts_preserve_last_administrator_protection(entra_setup):
    from app.db import SessionLocal

    from tests.phase6_helpers import seed_platform_grant
    claims, _ = entra_setup
    with SessionLocal() as db:
        user = resolve_principal(db, claims).user
        platform_service.update_user_status(db, user.id, 'ACTIVE')
        seed_platform_grant(db, user)
        db.commit()
        assert platform_service.get_effective_platform_grant(db, user) is not None
        for target in ('DISABLED', 'SUSPENDED'):
            with pytest.raises(HTTPException) as error:
                platform_service.update_user_status(db, user.id, target)
            assert error.value.detail['code'] == 'IAM_LAST_PLATFORM_ADMIN_PROTECTED'
            db.rollback()
        assert db.get(IAMUser, user.id).status == 'ACTIVE'
