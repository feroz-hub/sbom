from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from app.models import IAMUser, Tenant, TenantUser
from app.services.tenant_service import (
    TenantCreationError,
    create_tenant_with_initial_admin,
)
from sqlalchemy import func, select

from .phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


def _run_creation(payload: dict, actor_user_id: int) -> str:
    from app.db import SessionLocal

    with SessionLocal() as db:
        try:
            create_tenant_with_initial_admin(
                db,
                actor_user_id=actor_user_id,
                **payload,
            )
            return "CREATED"
        except TenantCreationError as exc:
            return str(exc.code)


def test_same_slug_race_leaves_one_tenant_and_one_membership():
    from app.db import SessionLocal, engine

    if engine.dialect.name != "postgresql":
        return
    with SessionLocal() as db:
        requester = seed_requester(db)
        admin = seed_eligible_admin(db)
        payload = tenant_payload(admin.id)
        actor_id = requester.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _index: _run_creation(payload, actor_id),
                range(2),
            )
        )
    assert sorted(results) == ["CREATED", "IAM_TENANT_SLUG_CONFLICT"]
    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == payload["slug"]))
        assert db.scalar(
            select(func.count(Tenant.id)).where(Tenant.slug == payload["slug"])
        ) == 1
        assert db.scalar(
            select(func.count(TenantUser.id)).where(
                TenantUser.tenant_id == tenant.id
            )
        ) == 1


def test_same_external_id_race_leaves_one_tenant():
    from app.db import SessionLocal, engine

    if engine.dialect.name != "postgresql":
        return
    with SessionLocal() as db:
        requester = seed_requester(db)
        admin = seed_eligible_admin(db)
        first = tenant_payload(admin.id)
        second = tenant_payload(
            admin.id,
            external_iam_tenant_id=first["external_iam_tenant_id"],
        )
        actor_id = requester.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda payload: _run_creation(payload, actor_id),
                (first, second),
            )
        )
    assert sorted(results) == ["CREATED", "IAM_TENANT_EXTERNAL_ID_CONFLICT"]
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(Tenant.id)).where(
                Tenant.external_iam_tenant_id
                == first["external_iam_tenant_id"]
            )
        ) == 1


@pytest.mark.parametrize("state_change", ["DISABLED", "REVERIFY"])
def test_initial_admin_state_change_locked_first_forces_creation_rollback(
    state_change,
):
    from app.db import SessionLocal, engine

    if engine.dialect.name != "postgresql":
        return
    with SessionLocal() as db:
        requester = seed_requester(db)
        admin = seed_eligible_admin(db)
        payload = tenant_payload(admin.id)
        actor_id = requester.id
        admin_id = admin.id

    target_locked = Event()
    release_change = Event()

    def change_state() -> None:
        with SessionLocal() as db:
            with db.begin():
                target = db.scalar(
                    select(IAMUser)
                    .where(IAMUser.id == admin_id)
                    .with_for_update()
                )
                target_locked.set()
                assert release_change.wait(timeout=10)
                if state_change == "DISABLED":
                    target.status = "DISABLED"
                else:
                    target.email_verified = False
                    target.verification_required = True

    with ThreadPoolExecutor(max_workers=2) as pool:
        state_future = pool.submit(change_state)
        assert target_locked.wait(timeout=10)
        create_future = pool.submit(_run_creation, payload, actor_id)
        release_change.set()
        state_future.result(timeout=10)
        result = create_future.result(timeout=10)

    expected = (
        "IAM_ACCOUNT_DISABLED"
        if state_change == "DISABLED"
        else "IAM_EMAIL_VERIFICATION_REQUIRED"
    )
    assert result == expected
    with SessionLocal() as db:
        assert db.scalar(
            select(func.count(Tenant.id)).where(Tenant.slug == payload["slug"])
        ) == 0
        assert db.scalar(
            select(func.count(TenantUser.id)).where(
                TenantUser.user_id == admin_id
            )
        ) == 0
