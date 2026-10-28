"""Platform defaults are protected, versioned, audited and inherited independently."""
import pytest
from sqlalchemy import select
from app.db import SessionLocal
from app.models import AdvisorPolicy, AuthorizationAuditLog
from tests.test_scoped_configuration import configured_actors

BASE = '/api/platform/configuration/advisor-policies'
TENANT = '/api/component-advisor/policies'


def body(status='ACTIVE', row_version=0, rules=None):
    return {'status': status, 'rules': rules or {'max_actionable_severity': 'MEDIUM'}, 'reason': 'Approved platform baseline', 'row_version': row_version}


def test_platform_publish_inheritance_override_disable_and_audit(configured_actors):
    call = configured_actors
    result = call('platform', 'POST', f'{BASE}/accepted-risk/versions', headers={'X-Tenant-ID': '1'}, json=body())
    assert result.status_code == 201, result.text
    state = result.json()
    assert state['effective']['scope'] == 'PLATFORM'
    assert state['tenant_override'] is None
    assert state['row_version'] == 1
    for actor in ('olympus', 'astra'):
        inherited = call(actor, 'GET', f'{TENANT}/accepted-risk').json()
        assert inherited['effective']['id'] == state['effective']['id']
    assert call('olympus', 'POST', f'{TENANT}/accepted-risk/versions', json=body(rules={'max_actionable_severity': 'LOW'})).status_code == 201
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body(row_version=1, rules={'max_actionable_severity': 'LOW'})).status_code == 201
    assert call('olympus', 'GET', f'{TENANT}/accepted-risk').json()['effective']['scope'] == 'TENANT'
    assert call('astra', 'GET', f'{TENANT}/accepted-risk').json()['effective']['version'] == 2
    assert call('olympus', 'POST', f'{TENANT}/accepted-risk/versions', json=body('INHERIT', 1)).status_code == 201
    assert call('olympus', 'GET', f'{TENANT}/accepted-risk').json()['effective']['scope'] == 'PLATFORM'
    assert call('astra', 'POST', f'{TENANT}/accepted-risk/versions', json=body('DISABLED')).status_code == 201
    assert call('astra', 'GET', f'{TENANT}/accepted-risk').json()['configured'] is False
    history = call('platform', 'GET', f'{BASE}/accepted-risk/versions').json()['items']
    assert [v['version'] for v in history] == [2, 1]
    assert all(v['scope'] == 'PLATFORM' for v in history)
    with SessionLocal() as db:
        assert db.scalar(select(AdvisorPolicy).where(AdvisorPolicy.tenant_id.is_(None)))
        assert db.scalar(select(AuthorizationAuditLog).where(AuthorizationAuditLog.tenant_id.is_(None), AuthorizationAuditLog.action == 'component_advisor.policy.version_published'))


@pytest.mark.parametrize('actor', ['olympus', 'astra', 'viewer'])
def test_tenant_roles_cannot_read_or_publish_platform_defaults(configured_actors, actor):
    call = configured_actors
    assert call(actor, 'GET', f'{BASE}/accepted-risk').status_code == 403
    assert call(actor, 'POST', f'{BASE}/accepted-risk/versions', json=body()).status_code == 403


def test_platform_conflict_validation_and_disable(configured_actors):
    call = configured_actors
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body('INHERIT')).status_code == 422
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body(rules={'max_actionable_severity': 'HIGH'})).status_code == 422
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body()).status_code == 201
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body()).status_code == 409
    assert call('platform', 'POST', f'{BASE}/accepted-risk/versions', json=body('DISABLED', 1)).status_code == 201
    assert call('platform', 'GET', f'{BASE}/accepted-risk').json()['configured'] is False
    assert call('olympus', 'GET', f'{TENANT}/accepted-risk').json()['configured'] is False


@pytest.mark.parametrize('kind,rules', [
    ('trust', {'allowed_classifications': ['LOW'], 'allowed_lifecycle': ['SUPPORTED']}),
    ('scoring', {'weights': {'current_risk': 0.3, 'lifecycle': 0.2, 'vulnerability_trend': 0.15, 'compatibility': 0.15, 'maintenance': 0.08, 'license': 0.05, 'tenant_adoption': 0.05, 'evidence_freshness': 0.02}, 'missing_data': 'PENALIZE', 'history_window_months': 24, 'stale_after_days': 90}),
])
def test_platform_other_policy_kinds_are_inherited(configured_actors, kind, rules):
    call = configured_actors
    result = call('platform', 'POST', f'{BASE}/{kind}/versions', json=body(rules=rules))
    assert result.status_code == 201, result.text
    inherited = call('olympus', 'GET', f'{TENANT}/{kind}').json()
    assert inherited['effective']['id'] == result.json()['effective']['id']
    assert inherited['effective']['scope'] == 'PLATFORM'


def test_platform_permission_migration_is_idempotent(configured_actors):
    import importlib.util
    from pathlib import Path
    from app.core.permissions import ROLE_PERMISSIONS
    from app.services.authorization_catalog_service import database_permissions_for_roles
    path = Path(__file__).resolve().parents[1] / 'alembic/versions/075_platform_advisor_policies.py'
    spec = importlib.util.spec_from_file_location('platform_advisor_permissions', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with SessionLocal() as db:
        tenant_before = database_permissions_for_roles(db, {'TENANT_ADMIN'})
        migration._seed(db.connection())
        migration._seed(db.connection())
        assert database_permissions_for_roles(db, {'PLATFORM_ADMIN'}) == ROLE_PERMISSIONS['PLATFORM_ADMIN']
        assert database_permissions_for_roles(db, {'TENANT_ADMIN'}) == tenant_before
