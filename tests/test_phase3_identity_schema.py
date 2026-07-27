"""Phase 3 local identity model, normalization, and compatibility tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.models import IAMUser
from app.services.identity_service import (
    find_by_external_identity,
    find_by_legacy_external_id,
    normalize_email,
    normalize_employee_id,
    normalize_issuer,
    normalize_optional_profile_value,
    normalize_subject,
    normalize_user_principal_name,
)
from app.services.tenant_service import get_or_create_user_from_claims
from sqlalchemy.exc import IntegrityError


def _user(*, issuer: str | None, subject: str, legacy_id: str | None = None) -> IAMUser:
    now = datetime.now(UTC)
    return IAMUser(
        external_iam_user_id=legacy_id or subject,
        external_issuer=issuer,
        external_subject=subject if issuer else None,
        status="PENDING",
        created_at=now,
        updated_at=now,
    )


def test_external_identity_uniqueness_and_email_is_not_an_identity_key():
    from app.db import SessionLocal

    suffix = uuid4().hex
    issuer = f"https://issuer-{suffix}.example"
    with SessionLocal() as db:
        first = _user(issuer=issuer, subject="stable-subject", legacy_id=f"legacy-a-{suffix}")
        first.email = "shared@example.test"
        same_subject_other_issuer = _user(
            issuer=f"https://other-{suffix}.example",
            subject="stable-subject",
            legacy_id=f"legacy-b-{suffix}",
        )
        same_subject_other_issuer.email = "shared@example.test"
        other_subject = _user(
            issuer=issuer,
            subject="different-subject",
            legacy_id=f"legacy-c-{suffix}",
        )
        db.add_all([first, same_subject_other_issuer, other_subject])
        db.commit()

        duplicate = _user(
            issuer=issuer,
            subject="stable-subject",
            legacy_id=f"legacy-d-{suffix}",
        )
        db.add(duplicate)
        with pytest.raises(IntegrityError):
            db.commit()


def test_identity_normalization_preserves_security_significant_values():
    assert normalize_issuer(" https://Identity.Example/Path/ ") == "https://Identity.Example/Path/"
    assert normalize_subject(" Subject-AbC ") == "Subject-AbC"
    assert normalize_email(" Employee@Example.COM ") == "employee@example.com"
    assert normalize_user_principal_name(" Employee@Example.COM ") == "employee@example.com"
    assert normalize_employee_id(" 001234 ") == "001234"
    assert normalize_optional_profile_value(None, field="department") is None
    assert normalize_optional_profile_value("  Security Engineering  ", field="department") == "Security Engineering"
    with pytest.raises(ValueError, match="issuer must not be empty"):
        normalize_issuer(" ")
    with pytest.raises(ValueError, match="subject must not be empty"):
        normalize_subject("\t")


def test_composite_and_legacy_lookups_are_both_available():
    from app.db import SessionLocal

    suffix = uuid4().hex
    issuer = f"https://lookup-{suffix}.example"
    with SessionLocal() as db:
        user = _user(issuer=issuer, subject=f"subject-{suffix}", legacy_id=f"legacy-{suffix}")
        db.add(user)
        db.commit()
        assert find_by_external_identity(db, issuer=issuer, subject=f"subject-{suffix}").id == user.id
        assert find_by_legacy_external_id(db, f"legacy-{suffix}").id == user.id
        assert user.effective_external_subject == f"subject-{suffix}"


def test_claim_sync_populates_profile_with_secure_verification_defaults():
    from app.db import SessionLocal

    suffix = uuid4().hex
    claims = {
        "iss": f"https://claims-{suffix}.example",
        "sub": f"subject-{suffix}",
        "email": " Employee@Example.COM ",
        "name": "  Example Employee ",
        "preferred_username": " Employee@Example.COM ",
        "employee_id": " 000042 ",
        "department": " Security ",
    }
    with SessionLocal() as db:
        user, changed = get_or_create_user_from_claims(db, claims)
        db.commit()
        assert changed is True
        assert user.status == "ACTIVE"
        assert user.external_iam_user_id == claims["sub"]
        assert user.external_issuer == claims["iss"]
        assert user.external_subject == claims["sub"]
        assert user.email == "employee@example.com"
        assert user.user_principal_name == "employee@example.com"
        assert user.employee_id == "000042"
        assert user.department == "Security"
        assert user.email_verified is False
        assert user.verification_required is True
        assert user.last_claim_sync_at is not None


def test_legacy_identity_is_linked_without_changing_local_status():
    from app.db import SessionLocal

    suffix = uuid4().hex
    subject = f"legacy-link-{suffix}"
    now = datetime.now(UTC)
    with SessionLocal() as db:
        legacy = IAMUser(
            external_iam_user_id=subject,
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(legacy)
        db.commit()
        original_id = legacy.id

        linked, changed = get_or_create_user_from_claims(
            db,
            {
                "iss": f"https://legacy-link-{suffix}.example",
                "sub": subject,
                "email": "legacy@example.test",
                "name": "Legacy User",
                "preferred_username": "legacy@example.test",
                "employee_id": "000099",
            },
        )
        db.commit()
        assert changed is True
        assert linked.id == original_id
        assert linked.status == "ACTIVE"
        assert linked.external_subject == subject


def test_auth_me_compatibility_aliases_return_the_same_contract(client):
    legacy = client.get("/api/auth/me")
    versioned = client.get("/api/v1/auth/me")
    assert legacy.status_code == 200
    assert versioned.status_code == 200
    assert versioned.json() == legacy.json()


def test_verification_timestamp_constraint_is_enforced():
    from app.db import SessionLocal

    suffix = uuid4().hex
    with SessionLocal() as db:
        user = _user(
            issuer=f"https://verification-{suffix}.example",
            subject=f"subject-{suffix}",
        )
        user.email_verified = True
        user.email_verified_at = None
        db.add(user)
        with pytest.raises(IntegrityError):
            db.commit()
