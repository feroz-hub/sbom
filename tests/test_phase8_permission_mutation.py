from datetime import UTC, datetime

from app.core.context import CurrentContext
from app.db import SessionLocal
from app.models import AuthorizationRole, IAMUser
from app.services.authorization_catalog_service import (
    CatalogProblem,
    replace_role_permissions,
    update_role_metadata,
)
from sqlalchemy import select


def _context(db):
    now = datetime.now(UTC)
    user = IAMUser(
        external_iam_user_id="phase8-mutation",
        external_issuer="https://phase8.test",
        external_subject="phase8-mutation",
        email="phase8-mutation@example.test",
        display_name="Phase 8",
        status="ACTIVE",
        email_verified=True,
        email_verified_at=now,
        verification_required=False,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    return CurrentContext(
        user_id=user.id,
        external_user_id="phase8-test",
        email=None,
        display_name="Phase 8",
        tenant_id=None,
        external_tenant_id=None,
        roles=frozenset({"PLATFORM_ADMIN"}),
        permissions=frozenset({"platform:authorization:manage"}),
        is_platform_admin=True,
    )


def test_metadata_update_uses_optimistic_version():
    with SessionLocal() as db:
        context = _context(db)
        role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "VIEWER"))
        updated = update_role_metadata(
            db,
            role.id,
            name="Viewer temporary",
            description=None,
            status=None,
            expected_version=role.version,
            context=context,
            request=None,
        )
        assert updated.version == role.version
        db.rollback()


def test_protected_tenant_admin_mapping_cannot_be_removed():
    with SessionLocal() as db:
        context = _context(db)
        role = db.scalar(select(AuthorizationRole).where(AuthorizationRole.code == "TENANT_ADMIN"))
        codes = [
            mapping.permission.code for mapping in role.permissions if mapping.permission.code != "tenant:user:read"
        ]
        try:
            replace_role_permissions(
                db,
                role.id,
                permission_codes=codes,
                expected_version=role.version,
                reason="negative test",
                context=context,
                request=None,
            )
        except CatalogProblem as exc:
            assert exc.code == "IAM_PROTECTED_PERMISSION_MAPPING"
        else:
            raise AssertionError("protected mapping removal was accepted")
