from app.authorization_catalog_seed_v1 import ROLE_PERMISSIONS_V1
from app.core.permissions import ROLE_PERMISSIONS
from app.db import SessionLocal
from app.models import AuthorizationRole, AuthorizationRolePermission
from scripts.compare_authorization_catalog import comparison, has_mismatch
from sqlalchemy import select


def test_frozen_seed_exactly_matches_phase8_legacy_matrix():
    assert {key: set(value) for key, value in ROLE_PERMISSIONS_V1.items()} == {
        key: set(value) for key, value in ROLE_PERMISSIONS.items()
    }


def test_database_seed_contains_every_legacy_mapping():
    with SessionLocal() as db:
        roles = db.scalars(select(AuthorizationRole)).all()
        actual = {
            role.code: {
                mapping.permission.code
                for mapping in db.scalars(
                    select(AuthorizationRolePermission).where(AuthorizationRolePermission.role_id == role.id)
                )
            }
            for role in roles
        }
    assert actual == {key: set(value) for key, value in ROLE_PERMISSIONS_V1.items()}


def test_operator_comparison_reports_zero_mismatches():
    assert has_mismatch(comparison()) is False
