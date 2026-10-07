"""SPDX uses the existing tenant-scoped session/job/approval API and native storage."""
import json
import uuid
from hashlib import sha256

import pytest
from app.core.context import CurrentContext
from app.core.permissions import ROLE_PERMISSIONS
from app.core.security import get_current_tenant_context
from app.db import SessionLocal
from app.models import SBOMRepairJob, SBOMSource, SBOMValidationSession

from tests.test_sbom_spdx_quality_repair import document, raw


def upload(client, doc=None):
    doc = doc or document()
    doc['relationships'][0]['relatedSpdxElement'] = 'pkg:npm/foo@1.0.0'
    response = client.post('/api/sboms', json=dict(sbom_name='spdx-' + str(uuid.uuid4()), sbom_data=raw(doc).decode()))
    assert response.status_code == 422, response.text
    return response.json()['detail']['session_id']


def base(session):
    return f'/api/sbom-validation-sessions/{session}'


def job(client, session):
    response = client.post(base(session) + '/repair')
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize('version', ['2.2', '2.3'])
def test_native_spdx_approve_quality_history_and_original(client, version):
    session = upload(client, document(version))
    source = client.get(base(session) + '/download-original').content
    initial = client.get(base(session) + '/quality').json()
    assert initial['assessment']['format'] == 'SPDX_JSON'
    result = job(client, session)
    assert result['format'] == 'SPDX_JSON' and result['status'] == 'REPAIRED'
    assert result['quality']['improvement'] > 0
    assert result['quality']['before']['artifact_hash'] == sha256(source).hexdigest()
    candidate = client.get(base(session) + f"/repair/{result['repair_job_id']}/download").content
    assert json.loads(candidate)['spdxVersion'] == 'SPDX-' + version
    assert client.get(base(session) + '/download-original').content == source
    approve = base(session) + f"/repair/{result['repair_job_id']}/approve"
    assert client.post(approve, json={'candidate_sha256': '0' * 64}).status_code == 409
    accepted = client.post(approve, json={'candidate_sha256': result['candidate_sha256']})
    assert accepted.status_code == 200, accepted.text
    accepted_id = accepted.json()['imported_sbom_id']
    with SessionLocal() as db:
        stored = db.get(SBOMSource, accepted_id)
        assert stored.sbom_data.encode() == candidate
        assert json.loads(stored.sbom_data)['spdxVersion'] == 'SPDX-' + version
        original = db.get(SBOMValidationSession, session)
        assert original.original_sha256 == sha256(source).hexdigest()
    assessment = client.get(f'/api/sboms/{accepted_id}/quality').json()['assessment']
    assert assessment['engine_version'] == '3.0.0'
    assert assessment['artifact_hash'] == result['candidate_sha256']
    history = client.get(base(session) + '/history').json()
    assert any(e['event_type'] == 'SBOM_REPAIR_APPROVED' for e in history)


def test_rejected_spdx_cannot_activate(client):
    session = upload(client)
    source = client.get(base(session) + '/download-original').content
    result = job(client, session)
    endpoint = base(session) + f"/repair/{result['repair_job_id']}"
    assert client.post(endpoint + '/reject').status_code == 200
    assert client.post(endpoint + '/approve', json={'candidate_sha256': result['candidate_sha256']}).status_code == 409
    assert client.get(base(session) + '/download-original').content == source


def test_spdx_candidate_tampering_hides_quality_and_denies_approval(client):
    session = upload(client)
    result = job(client, session)
    endpoint = base(session) + f"/repair/{result['repair_job_id']}"
    with SessionLocal() as db:
        db.connection().exec_driver_sql('UPDATE sbom_repair_jobs SET candidate_content = candidate_content || %s WHERE id = %s', (' ', result['repair_job_id']))
        db.commit()
    response = client.get(endpoint)
    assert response.status_code == 409 and 'overall_score' not in response.text
    assert client.post(endpoint + '/approve', json={'candidate_sha256': result['candidate_sha256']}).status_code == 409


def test_spdx_cross_tenant_every_artifact_endpoint(client):
    session = upload(client)
    result = job(client, session)
    context = CurrentContext(user_id=2, external_user_id='foreign', email=None, display_name='Foreign', tenant_id=2,
                             external_tenant_id='foreign', roles=frozenset({'TENANT_ADMIN'}), permissions=ROLE_PERMISSIONS['TENANT_ADMIN'])
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        for suffix in ('/quality', f"/repair/{result['repair_job_id']}", f"/repair/{result['repair_job_id']}/changes", f"/repair/{result['repair_job_id']}/download"):
            response = client.get(base(session) + suffix)
            assert response.status_code == 404
            assert 'SPDXRef' not in response.text and 'overall_score' not in response.text
        for action in ('approve', 'reject'):
            assert client.post(base(session) + f"/repair/{result['repair_job_id']}/{action}", json={'candidate_sha256': result['candidate_sha256']}).status_code == 404
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


@pytest.mark.parametrize('role', ['VIEWER', 'DEVELOPER', 'SECURITY_ANALYST', 'TENANT_ADMIN'])
def test_spdx_permission_matrix(client, role):
    session = upload(client)
    context = CurrentContext(user_id=1, external_user_id='role-test', email=None, display_name='Role', tenant_id=1,
                             external_tenant_id='default', roles=frozenset({role}), permissions=ROLE_PERMISSIONS[role])
    client.app.dependency_overrides[get_current_tenant_context] = lambda: context
    try:
        assert client.get(base(session) + '/quality').status_code == 200
        response = client.post(base(session) + '/repair')
        assert response.status_code == (200 if 'sbom:repair:update' in context.permissions else 403)
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_valid_spdx_stays_native_and_creates_no_repair_job(client):
    source = raw(document())
    response = client.post('/api/sboms', json={'sbom_name': 'valid-spdx-' + str(uuid.uuid4()), 'sbom_data': source.decode()})
    assert response.status_code == 201, response.text
    with SessionLocal() as db:
        stored = db.get(SBOMSource, response.json()['id'])
        assert stored.sbom_data.encode() == source
        from sqlalchemy import func, select
        assert db.scalar(select(func.count()).select_from(SBOMRepairJob)) == 0
    quality = client.get(f"/api/sboms/{response.json()['id']}/quality").json()['assessment']
    assert quality['supported'] and quality['validation_status'] == 'PASSED'


def test_spdx_concurrent_quality_and_repair_preserve_binding(client):
    from concurrent.futures import ThreadPoolExecutor
    session = upload(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_quality = pool.submit(client.get, base(session) + '/quality')
        pending_job = pool.submit(job, client, session)
        assessment = pending_quality.result().json()['assessment']
        result = pending_job.result()
    assert assessment['artifact_hash'] == result['source_sha256']
    assert result['quality']['after']['artifact_hash'] == result['candidate_sha256']


def test_spdx_policy_changes_append_history(client, monkeypatch):
    from app.settings import get_settings
    session = upload(client)
    before = client.get(base(session) + '/quality').json()
    monkeypatch.setattr(get_settings(), 'sbom_auto_repair_enabled', False)
    after = client.get(base(session) + '/quality').json()
    assert after['history'][:len(before['history'])] == before['history']
    assert after['assessment']['configuration_hash'] != before['assessment']['configuration_hash']
    assert all(not f['repairable'] for f in after['assessment']['findings'])


def test_legacy_spdx_job_is_preserved_and_does_not_block_native_run(client):
    session = upload(client)
    original = job(client, session)
    with SessionLocal() as db:
        stored = db.get(SBOMRepairJob, original['repair_job_id'])
        report = dict(stored.report_json)
        report.pop('format')
        db.connection().exec_driver_sql('UPDATE sbom_repair_jobs SET report_json = %s::json WHERE id = %s', (json.dumps(report), stored.id))
        db.commit()
    fresh = job(client, session)
    assert fresh['repair_job_id'] != original['repair_job_id']
    assert fresh['format'] == 'SPDX_JSON'
    with SessionLocal() as db:
        assert db.get(SBOMRepairJob, original['repair_job_id']) is not None


def test_historical_unsupported_spdx_quality_remains_readable(client):
    from copy import deepcopy

    from app.models import SBOMValidationSessionEvent
    from app.services.validation_repair_service import ValidationRepairService
    session_id = upload(client)
    previous = client.get(base(session_id) + '/quality').json()
    legacy = deepcopy(previous['assessment'])
    legacy.update(engine_version='2.0.0', supported=False, grade='NOT_ASSESSED', overall_score=0, dimensions=[], findings=[])
    legacy.pop('format', None)
    with SessionLocal() as db:
        workspace = db.get(SBOMValidationSession, session_id)
        ValidationRepairService(db, tenant_id=workspace.tenant_id)._record_event(
            workspace, 'SBOM_QUALITY_CALCULATED', summary='Historical Phase 2 fixture',
            metadata={'artifact_role': 'DRAFT', 'artifact_hash': legacy['artifact_hash'], 'engine_version': '2.0.0',
                      'configuration_hash': legacy['configuration_hash'], 'assessment': legacy})
        db.commit()
    current = client.get(base(session_id) + '/quality').json()
    assert current['assessment']['engine_version'] == '3.0.0'
    assert any(e['assessment'] == legacy for e in current['history'])
    with SessionLocal() as db:
        retained = db.query(SBOMValidationSessionEvent).filter_by(session_id=session_id, event_type='SBOM_QUALITY_CALCULATED').all()
        assert any(e.metadata_json.get('assessment') == legacy for e in retained)
