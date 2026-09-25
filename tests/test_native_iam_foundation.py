"""Native Phase 1: real PostgreSQL constraints, concurrency and compatibility."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from app.core.native_identity import AccountActionPurpose, canonicalize_email
from app.core.security import require_verified_user
from app.db import SessionLocal
from app.models import AccountActionToken, AuthorizationAuditLog, IAMUser, NativeUserCredential, UserIdentity
from app.services import audit_service, password_service
from app.services.account_action_token_service import (
    InvalidAccountActionToken,
    consume_action_token,
    hash_action_token,
    invalidate_action_tokens,
    issue_activation_token,
)
from app.services.account_state_service import InvalidAccountTransition, transition_account, validate_transition
from app.services.auth_context_service import resolve_authorization_state
from app.services.identity_service import provision_local_identity
from app.services.tenant_role_assignment_service import (
    AssignmentProblem,
    grant_role,
    replace_roles,
    validate_role_delegation,
)
from app.settings import Settings, get_settings
from argon2 import PasswordHasher
from fastapi import HTTPException
from scripts.check_native_identity_data import duplicate_email_user_ids
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from tests.phase6_helpers import identity_claims, seed_user
from tests.phase9_helpers import seed_role_membership


def native_user(db, email="native@example.test", *, status="PENDING_EMAIL_VERIFICATION"):
    now = datetime.now(UTC)
    user = IAMUser(email=email, status=status, created_at=now, updated_at=now)
    db.add(user)
    db.flush()
    db.add(
        UserIdentity(user_id=user.id, provider_type="NATIVE", provider_identifier=email, created_at=now, updated_at=now)
    )
    db.flush()
    return user


@pytest.fixture
def native_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "native_user_creation_enabled", True)


def test_native_defaults_do_not_enable_authentication():
    settings = Settings(_env_file=None)
    assert not settings.native_auth_enabled
    assert not settings.native_user_creation_enabled
    assert settings.native_account_activation_ttl_seconds == 18000
    with pytest.raises(ValueError):
        Settings(_env_file=None, native_account_activation_ttl_seconds=86400)


@pytest.mark.parametrize("email", ["Foo@Example.com", "foo@example.com", " \tFoo@Example.COM\n"])
def test_email_normalization(email):
    assert canonicalize_email(email) == "foo@example.com"
    with SessionLocal() as db:
        user = native_user(db, email)
        assert user.normalized_email == "foo@example.com"
        identity = db.scalar(select(UserIdentity).where(UserIdentity.user_id == user.id))
        assert identity.provider_identifier == "foo@example.com"
        assert user.external_iam_user_id is None
        assert identity.subject is None


def test_one_person_can_have_both_identities_without_email_linking():
    with SessionLocal() as db:
        user = seed_user(db)
        result = provision_local_identity(db, identity_claims(user))
        assert result.user.id == user.id
        now = datetime.now(UTC)
        db.add(
            UserIdentity(
                user_id=user.id, provider_type="NATIVE", provider_identifier=user.email, created_at=now, updated_at=now
            )
        )
        db.flush()
        assert db.scalar(select(func.count(UserIdentity.id)).where(UserIdentity.user_id == user.id)) == 2
        # A different issuer/subject with the same email remains a different person.
        claims = identity_claims(user)
        claims["sub"] = "another-subject"
        other = provision_local_identity(db, claims).user
        assert other.id != user.id


def test_hcl_identity_uniqueness_and_idempotent_mirror():
    with SessionLocal() as db:
        user = seed_user(db)
        claims = identity_claims(user)
        provision_local_identity(db, claims)
        provision_local_identity(db, claims)
        assert db.scalar(select(func.count(UserIdentity.id))) == 1
        other = seed_user(db)
        now = datetime.now(UTC)
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                UserIdentity(
                    user_id=other.id,
                    provider_type="HCL_CS",
                    issuer=claims["iss"],
                    subject=claims["sub"],
                    created_at=now,
                    updated_at=now,
                )
            )
            db.flush()


def test_email_collision_report_does_not_merge_hcl_profiles():
    assert duplicate_email_user_ids([(1, " Foo@Example.com "), (2, "foo@example.com"), (3, None)]) == [[1, 2]]
    with SessionLocal() as db:
        first = seed_user(db, email=" Foo@Example.com ")
        second = seed_user(db, email="foo@example.com")
        db.flush()
        assert first.id != second.id
        assert first.normalized_email == second.normalized_email


def test_concurrent_native_identifier_creation_has_one_winner():
    barrier = Barrier(2)

    def create(index):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                native_user(db, [" Race@Example.com ", "race@example.com"][index])
                db.commit()
                return "CREATED"
            except IntegrityError:
                db.rollback()
                return "DUPLICATE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(create, range(2))) == ["CREATED", "DUPLICATE"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count(IAMUser.id))) == 1


@pytest.mark.parametrize(
    "before,after,proof",
    [
        ("PENDING_EMAIL_VERIFICATION", "ACTIVE", {"activation_completed": True}),
        ("ACTIVE", "LOCKED", {}),
        ("LOCKED", "ACTIVE", {"explicitly_authorized": True}),
        ("ACTIVE", "DISABLED", {}),
        ("LOCKED", "DISABLED", {}),
        ("PENDING_EMAIL_VERIFICATION", "DISABLED", {}),
        ("DISABLED", "ACTIVE", {"explicitly_authorized": True}),
        ("ACTIVE", "FORCE_PASSWORD_CHANGE", {}),
        ("FORCE_PASSWORD_CHANGE", "ACTIVE", {"password_updated": True}),
        ("PENDING", "ACTIVE", {"legacy_approval": True}),
    ],
)
def test_valid_status_transitions(before, after, proof):
    validate_transition(before, after, **proof)


@pytest.mark.parametrize(
    "before,after",
    [
        ("PENDING_EMAIL_VERIFICATION", "LOCKED"),
        ("DISABLED", "LOCKED"),
        ("ACTIVE", "PENDING_EMAIL_VERIFICATION"),
        ("ACTIVE", "UNKNOWN"),
        ("UNKNOWN", "ACTIVE"),
        ("PENDING", "ACTIVE"),
        ("PENDING", "DISABLED"),
        ("DISABLED", "ACTIVE"),
        ("LOCKED", "ACTIVE"),
        ("PENDING_EMAIL_VERIFICATION", "ACTIVE"),
        ("FORCE_PASSWORD_CHANGE", "ACTIVE"),
    ],
)
def test_invalid_or_unproven_transitions_fail_closed(before, after):
    with pytest.raises(InvalidAccountTransition):
        validate_transition(before, after)


@pytest.mark.parametrize(
    "status", ["LOCKED", "FORCE_PASSWORD_CHANGE", "PENDING_EMAIL_VERIFICATION", "DISABLED", "PENDING"]
)
def test_all_non_active_states_have_no_authority(status):
    with SessionLocal() as db:
        user = seed_user(db, status=status)
        state = resolve_authorization_state(db, user)
        assert state.status != "READY"
        assert not state.platform_permissions and not state.memberships
        with pytest.raises(HTTPException):
            require_verified_user(user)


def test_password_primitives_and_no_secret_logging(caplog):
    secret = "native test passphrase ! do not log"
    encoded = password_service.hash_password(secret)
    assert encoded != secret and encoded.startswith("$argon2id$")
    assert password_service.verify_password(secret, encoded)
    assert not password_service.verify_password("wrong", encoded)
    assert not password_service.verify_password(secret, "malformed")
    assert not password_service.needs_rehash(encoded)
    old = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(secret)
    assert password_service.needs_rehash(old)
    assert secret not in caplog.text and encoded not in caplog.text


def test_credential_storage_rejects_plaintext_and_duplicates():
    with SessionLocal() as db:
        user = native_user(db)
        now = datetime.now(UTC)
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                NativeUserCredential(
                    user_id=user.id,
                    password_hash="plaintext",
                    password_hash_scheme="argon2id",
                    password_changed_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.flush()
        credential = NativeUserCredential(
            user_id=user.id,
            password_hash=password_service.hash_password("example test password"),
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(credential)
        db.flush()
        assert credential.security_version == 1 and credential.failed_login_count == 0


def test_activation_randomness_hash_purpose_ttl_single_use(native_enabled):
    with SessionLocal() as db:
        user = native_user(db)
        first = issue_activation_token(db, user.id, actor_user_id=None)
        second = issue_activation_token(db, user.id, actor_user_id=None)
        assert first.raw_token != second.raw_token
        assert second.raw_token not in repr(second)
        row = db.get(AccountActionToken, second.id)
        assert row.token_hash == hash_action_token(second.raw_token)
        assert row.token_hash != second.raw_token
        assert row.purpose == "ACCOUNT_ACTIVATION"
        assert (row.expires_at - row.created_at).total_seconds() == 18000
        with pytest.raises(InvalidAccountActionToken):
            consume_action_token(db, first.raw_token, user_id=user.id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION)
        consume_action_token(db, second.raw_token, user_id=user.id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION)
        with pytest.raises(InvalidAccountActionToken):
            consume_action_token(db, second.raw_token, user_id=user.id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION)
        # Foundation token consumption does not activate the user or create a password.
        assert user.status == "PENDING_EMAIL_VERIFICATION"


@pytest.mark.parametrize(
    "condition", ["expired", "invalidated", "wrong_user", "wrong_purpose", "changed_email", "disabled"]
)
def test_activation_rejections(native_enabled, condition):
    with SessionLocal() as db:
        user = native_user(db)
        other = native_user(db, "other@example.test")
        issued = issue_activation_token(db, user.id, actor_user_id=None)
        token = db.get(AccountActionToken, issued.id)
        if condition == "expired":
            token.created_at -= timedelta(hours=6)
            token.expires_at -= timedelta(hours=6)
        elif condition == "invalidated":
            invalidate_action_tokens(db, user.id, actor_user_id=None)
        elif condition == "changed_email":
            identity = db.scalar(select(UserIdentity).where(UserIdentity.user_id == user.id))
            identity.provider_identifier = "changed@example.test"
        elif condition == "disabled":
            user.status = "DISABLED"
        db.flush()
        with pytest.raises(InvalidAccountActionToken):
            consume_action_token(
                db,
                issued.raw_token,
                user_id=other.id if condition == "wrong_user" else user.id,
                purpose=AccountActionPurpose.PASSWORD_RESET
                if condition == "wrong_purpose"
                else AccountActionPurpose.ACCOUNT_ACTIVATION,
            )


def test_activation_concurrent_consumption_one_winner(native_enabled):
    with SessionLocal() as db:
        user_id = native_user(db).id
        issued = issue_activation_token(db, user_id, actor_user_id=None)
        db.commit()
    barrier = Barrier(2)

    def consume(_):
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            try:
                consume_action_token(
                    db, issued.raw_token, user_id=user_id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION
                )
                db.commit()
                return "CONSUMED"
            except InvalidAccountActionToken:
                db.rollback()
                return "REJECTED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, range(2))) == ["CONSUMED", "REJECTED"]


def test_required_audit_failure_rolls_back_token_and_state(native_enabled, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    with SessionLocal() as db:
        user = native_user(db)
        issued = issue_activation_token(db, user.id, actor_user_id=None)
        user_id = user.id
        db.commit()
        monkeypatch.setattr(audit_service, "write_authorization_audit", fail)
        with pytest.raises(RuntimeError):
            consume_action_token(db, issued.raw_token, user_id=user_id, purpose=AccountActionPurpose.ACCOUNT_ACTIVATION)
        db.commit()
        assert db.get(AccountActionToken, issued.id, populate_existing=True).consumed_at is None
        with pytest.raises(RuntimeError):
            issue_activation_token(db, user_id, actor_user_id=None)
        db.commit()
        assert db.scalar(select(func.count(AccountActionToken.id))) == 1
        user.status = "ACTIVE"
        db.commit()
        with pytest.raises(RuntimeError):
            transition_account(db, user_id, "LOCKED", actor_user_id=None)
        db.commit()
        assert db.get(IAMUser, user_id, populate_existing=True).status == "ACTIVE"


@pytest.mark.parametrize("role", ["SECURITY_ANALYST", "DEVELOPER", "VIEWER"])
def test_tenant_admin_can_delegate_basic_roles(role):
    validate_role_delegation([role], is_platform_admin=False)


@pytest.mark.parametrize("role", ["TENANT_ADMIN", "PLATFORM_ADMIN"])
def test_tenant_admin_cannot_delegate_admin_roles(role):
    with pytest.raises(AssignmentProblem):
        validate_role_delegation([role], is_platform_admin=False)


def test_platform_admin_can_delegate_tenant_admin():
    with SessionLocal() as db:
        user, membership, _ = seed_role_membership(db)
        grant_role(
            db,
            1,
            user.id,
            role_code="TENANT_ADMIN",
            expected_version=1,
            make_primary=False,
            reason=None,
            actor_user_id=user.id,
            is_platform_admin=True,
        )


@pytest.mark.parametrize("operation", ["grant", "replace"])
def test_service_enforces_delegation_without_frontend(operation):
    with SessionLocal() as db:
        user, _, _ = seed_role_membership(db)
        with pytest.raises(AssignmentProblem) as caught:
            if operation == "grant":
                grant_role(
                    db,
                    1,
                    user.id,
                    role_code="TENANT_ADMIN",
                    expected_version=1,
                    make_primary=False,
                    reason=None,
                    actor_user_id=user.id,
                    is_platform_admin=False,
                )
            else:
                replace_roles(
                    db,
                    1,
                    user.id,
                    role_codes=["TENANT_ADMIN"],
                    primary_role_code="TENANT_ADMIN",
                    expected_version=1,
                    reason=None,
                    actor_user_id=user.id,
                    is_platform_admin=False,
                )
        assert caught.value.status_code == 403


def test_legacy_membership_endpoint_cannot_bypass_role_delegation(client):
    with SessionLocal() as db:
        user = seed_user(db)
        target_id = user.id
        db.commit()
    response = client.post("/api/tenants/1/users", json={"user_id": target_id, "role": "TENANT_ADMIN"})
    assert response.status_code == 403, response.text


def test_token_audit_contains_no_raw_secret(native_enabled):
    with SessionLocal() as db:
        user = native_user(db)
        issued = issue_activation_token(db, user.id, actor_user_id=None)
        audit = db.scalar(select(AuthorizationAuditLog).where(AuthorizationAuditLog.target_user_id == user.id))
        assert audit.action == "ACCOUNT_ACTIVATION_TOKEN_CREATED"
        assert issued.raw_token not in str(audit.new_value)
        assert "token_hash" not in str(audit.new_value)


def test_database_checks_reject_unknown_status_and_noncanonical_native_identifier():
    with SessionLocal() as db:
        user = native_user(db)
        with pytest.raises(IntegrityError), db.begin_nested():
            db.execute(
                text("UPDATE user_identities SET provider_identifier='Foo@Example.com' WHERE user_id=:id"),
                {"id": user.id},
            )
        with pytest.raises(IntegrityError), db.begin_nested():
            db.execute(text("UPDATE iam_users SET status='UNKNOWN' WHERE id=:id"), {"id": user.id})


def test_native_security_state_mutations_are_audited_and_revoke_versions():
    with SessionLocal() as db:
        user = native_user(db, status="ACTIVE")
        now = datetime.now(UTC)
        credential = NativeUserCredential(
            user_id=user.id,
            password_hash=password_service.hash_password("native test credential"),
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(credential)
        db.commit()
        transition_account(db, user.id, "LOCKED", actor_user_id=None)
        assert user.status == "LOCKED"
        assert credential.locked_at is not None and credential.security_version == 2
        transition_account(db, user.id, "ACTIVE", actor_user_id=None, explicitly_authorized=True)
        assert credential.locked_at is None and credential.security_version == 3
        transition_account(db, user.id, "FORCE_PASSWORD_CHANGE", actor_user_id=None)
        with pytest.raises(InvalidAccountTransition):
            transition_account(db, user.id, "ACTIVE", actor_user_id=None)
        transition_account(db, user.id, "ACTIVE", actor_user_id=None, password_updated=True)
        actions = set(db.scalars(select(AuthorizationAuditLog.action)))
        assert {"USER_LOCKED", "USER_UNLOCKED", "FORCE_PASSWORD_CHANGE_SET", "PASSWORD_CHANGED"} <= actions


def test_activation_cannot_enable_account_without_credentials_and_verification():
    with SessionLocal() as db:
        user = native_user(db)
        with pytest.raises(InvalidAccountTransition):
            transition_account(db, user.id, "ACTIVE", actor_user_id=None, activation_completed=True)
        assert db.get(IAMUser, user.id).status == "PENDING_EMAIL_VERIFICATION"


def test_native_access_removal_preserves_last_admin_guard():
    from tests.phase6_helpers import seed_platform_grant

    with SessionLocal() as db:
        user = seed_user(db)
        seed_platform_grant(db, user)
        db.commit()
        with pytest.raises(HTTPException) as caught:
            transition_account(db, user.id, "LOCKED", actor_user_id=user.id)
        assert caught.value.detail["code"] == "IAM_LAST_PLATFORM_ADMIN_PROTECTED"
        assert db.get(IAMUser, user.id).status == "ACTIVE"


@pytest.mark.parametrize("status", ["LOCKED", "FORCE_PASSWORD_CHANGE", "PENDING_EMAIL_VERIFICATION"])
def test_native_non_active_user_cannot_receive_platform_grant(status):
    from app.services.platform_service import grant_platform_administrator

    with SessionLocal() as db:
        user = seed_user(db, status=status)
        with pytest.raises(HTTPException):
            grant_platform_administrator(db, user_id=user.id, created_by_user_id=None)


def test_feature_flag_blocks_token_issuance():
    with SessionLocal() as db:
        user = native_user(db)
        with pytest.raises(ValueError, match="disabled"):
            issue_activation_token(db, user.id, actor_user_id=None)
        assert db.scalar(select(func.count(AccountActionToken.id))) == 0


def test_credential_and_native_identity_user_uniqueness():
    with SessionLocal() as db:
        user = native_user(db)
        now = datetime.now(UTC)
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                UserIdentity(
                    user_id=user.id,
                    provider_type="NATIVE",
                    provider_identifier="second@example.test",
                    created_at=now,
                    updated_at=now,
                )
            )
            db.flush()
        encoded = password_service.hash_password("test unique credential")
        db.add(
            NativeUserCredential(
                user_id=user.id, password_hash=encoded, password_changed_at=now, created_at=now, updated_at=now
            )
        )
        db.flush()
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                NativeUserCredential(
                    user_id=user.id, password_hash=encoded, password_changed_at=now, created_at=now, updated_at=now
                )
            )
            db.flush()


def test_database_exception_does_not_print_credential_hash():
    with SessionLocal() as db:
        now = datetime.now(UTC)
        encoded = password_service.hash_password("test logging boundary")
        with pytest.raises(IntegrityError) as caught, db.begin_nested():
            db.add(
                NativeUserCredential(
                    user_id=999999, password_hash=encoded, password_changed_at=now, created_at=now, updated_at=now
                )
            )
            db.flush()
        assert encoded not in str(caught.value)
