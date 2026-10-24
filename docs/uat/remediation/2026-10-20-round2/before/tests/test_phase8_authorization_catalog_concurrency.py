from datetime import UTC, datetime

from app.core.context import CurrentContext
from app.db import SessionLocal
from app.models import AuthorizationRole, IAMUser
from app.services.authorization_catalog_service import CatalogProblem, update_role_metadata
from sqlalchemy import select


def test_stale_role_version_is_rejected():
    context = CurrentContext(
        0,
        "phase8",
        None,
        None,
        None,
        None,
        frozenset({"PLATFORM_ADMIN"}),
        frozenset({"platform:authorization:manage"}),
        True,
    )
    with SessionLocal() as db:
        role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER"))
        try:
            update_role_metadata(
                db,
                role.id,
                name=None,
                description=None,
                status=None,
                expected_version=role.version + 1,
                context=context,
                request=None,
            )
        except CatalogProblem as exc:
            assert exc.status_code == 409
        else:
            raise AssertionError("stale version was accepted")


def test_independent_sessions_cannot_lose_role_update():
    now = datetime.now(UTC)
    with SessionLocal() as seed:
        actor = IAMUser(
            external_iam_user_id="phase8-concurrency",
            external_issuer="https://phase8.test",
            external_subject="phase8-concurrency",
            email="phase8-concurrency@example.test",
            display_name="Phase 8 concurrency",
            status="ACTIVE",
            email_verified=True,
            email_verified_at=now,
            verification_required=False,
            created_at=now,
            updated_at=now,
        )
        seed.add(actor)
        seed.flush()
        actor_id = actor.id
        role = seed.scalar(
            select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER")
        )
        role_id, starting_version = role.id, role.version
        seed.commit()

    context = CurrentContext(
        actor_id,
        "phase8-concurrency",
        None,
        None,
        None,
        None,
        frozenset({"PLATFORM_ADMIN"}),
        frozenset({"platform:authorization:manage"}),
        True,
    )
    first = SessionLocal()
    second = SessionLocal()
    try:
        update_role_metadata(
            first,
            role_id,
            name=None,
            description="first writer",
            status=None,
            expected_version=starting_version,
            context=context,
            request=None,
        )
        first.commit()
        try:
            update_role_metadata(
                second,
                role_id,
                name=None,
                description="stale second writer",
                status=None,
                expected_version=starting_version,
                context=context,
                request=None,
            )
        except CatalogProblem as exc:
            assert exc.code == "IAM_ROLE_VERSION_CONFLICT"
            second.rollback()
        else:
            raise AssertionError("concurrent stale update was accepted")
        with SessionLocal() as verification:
            current = verification.get(AuthorizationRole, role_id)
            assert current.version == starting_version + 1
            assert current.description == "first writer"
    finally:
        first.close()
        second.close()
