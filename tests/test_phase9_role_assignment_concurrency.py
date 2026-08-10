from concurrent.futures import ThreadPoolExecutor

import pytest
from app.db import SessionLocal
from app.services import platform_service
from app.services import tenant_role_assignment_service as service
from fastapi import HTTPException

from .phase9_helpers import seed_role_membership


def test_stale_membership_version_is_rejected_without_merging():
    with SessionLocal() as db:
        user, _membership, _ = seed_role_membership(db)
        service.grant_role(
            db,
            1,
            user.id,
            role_code="DEVELOPER",
            expected_version=1,
            make_primary=False,
            reason=None,
            actor_user_id=user.id,
            is_platform_admin=False,
        )
        with pytest.raises(service.AssignmentProblem) as caught:
            service.grant_role(
                db,
                1,
                user.id,
                role_code="SECURITY_ANALYST",
                expected_version=1,
                make_primary=False,
                reason=None,
                actor_user_id=user.id,
                is_platform_admin=False,
            )
    assert caught.value.code.value == "IAM_TENANT_ROLE_VERSION_CONFLICT"
    assert caught.value.current_version == 2


def test_concurrent_grants_with_same_version_have_one_winner():
    with SessionLocal() as db:
        user, _membership, _ = seed_role_membership(db)
        user_id = user.id

    def grant(code: str):
        with SessionLocal() as db:
            try:
                service.grant_role(
                    db,
                    1,
                    user_id,
                    role_code=code,
                    expected_version=1,
                    make_primary=False,
                    reason="concurrent",
                    actor_user_id=user_id,
                    is_platform_admin=False,
                )
                return "SUCCESS"
            except service.AssignmentProblem as exc:
                return exc.code.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(grant, ("DEVELOPER", "SECURITY_ANALYST")))
    assert sorted(results) == ["IAM_TENANT_ROLE_VERSION_CONFLICT", "SUCCESS"]


def test_concurrent_last_two_admin_disables_leave_one_effective_admin():
    with SessionLocal() as db:
        first, _membership, _ = seed_role_membership(db, role="TENANT_ADMIN")
        second, _membership, _ = seed_role_membership(db, role="TENANT_ADMIN")
        user_ids = (first.id, second.id)

    def disable(user_id: int):
        with SessionLocal() as db:
            try:
                platform_service.update_user_status(db, user_id, "DISABLED")
                db.commit()
                return "SUCCESS"
            except HTTPException as exc:
                db.rollback()
                return exc.detail["code"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(disable, user_ids))
    assert sorted(results) == ["IAM_LAST_TENANT_ADMIN_PROTECTED", "SUCCESS"]


def test_concurrent_primary_changes_have_one_winner():
    with SessionLocal() as db:
        user, _membership, _ = seed_role_membership(db, role="VIEWER")
        user_id = user.id
        service.grant_role(
            db,
            1,
            user_id,
            role_code="DEVELOPER",
            expected_version=1,
            make_primary=False,
            reason=None,
            actor_user_id=user_id,
            is_platform_admin=False,
        )
        service.grant_role(
            db,
            1,
            user_id,
            role_code="SECURITY_ANALYST",
            expected_version=2,
            make_primary=False,
            reason=None,
            actor_user_id=user_id,
            is_platform_admin=False,
        )

    def make_primary(code: str):
        with SessionLocal() as db:
            try:
                service.grant_role(
                    db,
                    1,
                    user_id,
                    role_code=code,
                    expected_version=3,
                    make_primary=True,
                    reason="primary race",
                    actor_user_id=user_id,
                    is_platform_admin=False,
                )
                return "SUCCESS"
            except service.AssignmentProblem as exc:
                return exc.code.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(make_primary, ("DEVELOPER", "SECURITY_ANALYST"))
        )
    assert sorted(results) == ["IAM_TENANT_ROLE_VERSION_CONFLICT", "SUCCESS"]
