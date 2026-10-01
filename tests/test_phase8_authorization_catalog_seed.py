from app.authorization_catalog_seed_v1 import ROLE_PERMISSIONS_V1
from app.authorization_catalog_seed_v2 import PLATFORM_ADMIN_PERMISSIONS_V2, TENANT_CONFIGURATION_PERMISSIONS_V2
from app.core.permissions import ROLE_PERMISSIONS
from app.db import SessionLocal
from app.models import AuthorizationRole, AuthorizationRolePermission
from scripts.compare_authorization_catalog import comparison, has_mismatch
from sqlalchemy import select


def test_frozen_v1_preserved_and_only_platform_mapping_changed():
    assert ROLE_PERMISSIONS['PLATFORM_ADMIN'] == PLATFORM_ADMIN_PERMISSIONS_V2
    assert 'sbom:read' in ROLE_PERMISSIONS_V1['PLATFORM_ADMIN']
    assert 'sbom:read' not in ROLE_PERMISSIONS['PLATFORM_ADMIN']


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
    expected = {key: set(value) for key, value in ROLE_PERMISSIONS_V1.items()}
    expected['PLATFORM_ADMIN'] = set(PLATFORM_ADMIN_PERMISSIONS_V2)
    expected['TENANT_ADMIN'].update(TENANT_CONFIGURATION_PERMISSIONS_V2)
    assert actual == expected


def test_operator_comparison_reports_zero_mismatches():
    assert has_mismatch(comparison()) is False
