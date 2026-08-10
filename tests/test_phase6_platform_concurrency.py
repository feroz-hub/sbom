from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from app.db import SessionLocal
from app.models import IAMUser, PlatformUserRole
from app.services import platform_service
from fastapi import HTTPException
from sqlalchemy import func, select

from tests.phase6_helpers import seed_platform_grant, seed_user


def test_concurrent_grants_create_one_idempotent_effective_grant():
    with SessionLocal() as db:
        actor = seed_user(db)
        target = seed_user(db)
        actor_id = actor.id
        target_id = target.id
        db.commit()

    barrier = Barrier(2)

    def grant_once() -> str:
        with SessionLocal() as db:
            barrier.wait()
            mutation = platform_service.grant_platform_administrator(
                db,
                user_id=target_id,
                created_by_user_id=actor_id,
            )
            db.commit()
            return mutation.action

    with ThreadPoolExecutor(max_workers=2) as pool:
        actions = sorted(pool.map(lambda _index: grant_once(), range(2)))

    assert actions == ["CREATED", "EXISTING"]
    with SessionLocal() as db:
        grants = list(
            db.scalars(
                select(PlatformUserRole).where(
                    PlatformUserRole.user_id == target_id
                )
            )
        )
        assert len(grants) == 1
        assert grants[0].status == "ACTIVE"


def test_concurrent_last_two_revocations_leave_one_effective_admin():
    with SessionLocal() as db:
        first = seed_user(db)
        second = seed_user(db)
        first_grant = seed_platform_grant(db, first)
        second_grant = seed_platform_grant(db, second)
        grant_ids = (first_grant.id, second_grant.id)
        db.commit()

    barrier = Barrier(2)

    def revoke(grant_id: int) -> str:
        with SessionLocal() as db:
            barrier.wait()
            try:
                mutation = platform_service.revoke_platform_administrator(
                    db, grant_id
                )
                db.commit()
                return mutation.action
            except HTTPException as exc:
                db.rollback()
                return str(exc.detail["code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(revoke, grant_ids))

    assert results.count("REVOKED") == 1
    assert results.count("IAM_LAST_PLATFORM_ADMIN_PROTECTED") == 1
    with SessionLocal() as db:
        assert platform_service._effective_admin_count(db) == 1


def test_concurrent_last_two_disables_leave_one_effective_admin():
    with SessionLocal() as db:
        first = seed_user(db)
        second = seed_user(db)
        seed_platform_grant(db, first)
        seed_platform_grant(db, second)
        user_ids = (first.id, second.id)
        db.commit()

    barrier = Barrier(2)

    def disable(user_id: int) -> str:
        with SessionLocal() as db:
            barrier.wait()
            try:
                mutation = platform_service.update_user_status(
                    db, user_id, "DISABLED"
                )
                db.commit()
                return mutation.user.status
            except HTTPException as exc:
                db.rollback()
                return str(exc.detail["code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(disable, user_ids))

    assert results.count("DISABLED") == 1
    assert results.count("IAM_LAST_PLATFORM_ADMIN_PROTECTED") == 1
    with SessionLocal() as db:
        assert platform_service._effective_admin_count(db) == 1


def test_concurrent_conflicting_status_updates_preserve_valid_state():
    with SessionLocal() as db:
        target = seed_user(db)
        target_id = target.id
        db.commit()

    barrier = Barrier(2)

    def update_status(status: str) -> str:
        with SessionLocal() as db:
            barrier.wait()
            mutation = platform_service.update_user_status(
                db, target_id, status
            )
            db.commit()
            return mutation.user.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update_status, ("DISABLED", "ACTIVE")))

    assert set(results) <= {"ACTIVE", "DISABLED"}
    with SessionLocal() as db:
        assert db.get(IAMUser, target_id).status in {"ACTIVE", "DISABLED"}


def test_concurrent_revoke_and_grant_leave_one_consistent_row():
    with SessionLocal() as db:
        actor = seed_user(db)
        target = seed_user(db)
        backup = seed_user(db)
        grant = seed_platform_grant(db, target)
        seed_platform_grant(db, backup)
        actor_id = actor.id
        target_id = target.id
        grant_id = grant.id
        db.commit()

    barrier = Barrier(2)

    def revoke() -> str:
        with SessionLocal() as db:
            barrier.wait()
            mutation = platform_service.revoke_platform_administrator(
                db, grant_id
            )
            db.commit()
            return mutation.action

    def grant() -> str:
        with SessionLocal() as db:
            barrier.wait()
            mutation = platform_service.grant_platform_administrator(
                db,
                user_id=target_id,
                created_by_user_id=actor_id,
            )
            db.commit()
            return mutation.action

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(revoke), pool.submit(grant)]
        actions = {future.result() for future in results}

    assert actions <= {"REVOKED", "EXISTING", "REACTIVATED"}
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(PlatformUserRole.id)).where(
                PlatformUserRole.user_id == target_id
            )
        ) == 1
        assert platform_service._effective_admin_count(db) >= 1
