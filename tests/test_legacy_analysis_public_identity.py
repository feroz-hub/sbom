"""R3-DEF-006: advertised legacy routes retain UUID/auth/tenant boundaries."""
import json
from uuid import uuid4

import pytest
from app.db import SessionLocal
from app.models import AnalysisRun, SBOMSource
from app.public_api import LEGACY_ANALYSIS_PATHS
from sqlalchemy import func, select

from tests.public_id_fixture import public_row
from tests.tenant_fixture_scope import verified_fixture_tenant
from tests.test_scoped_configuration import configured_actors as _configured_actors

configured_actors = _configured_actors


@pytest.fixture
def legacy_fixture(configured_actors):
    call = configured_actors
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                      "components": [{"type": "library", "name": "legacy-fixture", "version": "1.0"}]})
    own = call('olympus', 'POST', '/api/sboms', json={'sbom_name': 'owned-' + str(uuid4()), 'sbom_data': raw})
    foreign = call('astra', 'POST', '/api/sboms', json={'sbom_name': 'foreign-' + str(uuid4()), 'sbom_data': raw})
    assert own.status_code == foreign.status_code == 201
    identity = own.json()['id']
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        source = public_row(db, SBOMSource, identity)
        internal = source.id
        run = AnalysisRun(sbom_id=internal, project_id=source.projectid, product_id=source.product_id,
                          sbom_name=source.sbom_name, run_status='RUNNING', source='OSV',
                          trigger_source='api', started_on='2026-10-20T00:00:00Z',
                          completed_on='2026-10-20T00:00:00Z')
        db.add(run)
        db.commit()
        run_id = run.id
    return call, identity, internal, foreign.json()['id'], run_id


@pytest.mark.parametrize('path', sorted(LEGACY_ANALYSIS_PATHS - {'/analyze-sbom-vulndb'}))
def test_legacy_valid_uuid_returns_existing_run_with_public_successor(legacy_fixture, path):
    call, identity, _, _, run_id = legacy_fixture
    response = call('olympus', 'POST', path, json={'sbom_id': identity})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['status'] == 'already_running'
    assert body['run_id'] == body['id'] == run_id
    assert body['sbom_id'] == identity
    assert response.headers['Deprecation'] == 'true'
    assert response.headers['Link'] == f'</api/sboms/{identity}/analyze>; rel="successor-version"'
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 1


@pytest.mark.parametrize('path', sorted(LEGACY_ANALYSIS_PATHS))
def test_legacy_invalid_integer_foreign_and_viewer_never_mutate(legacy_fixture, path):
    call, identity, internal, foreign, run_id = legacy_fixture
    for actor, resource, status in [('olympus', internal, 422), ('olympus', str(internal), 422),
                                    ('olympus', str(uuid4()), 404), ('olympus', foreign, 404),
                                    ('viewer', identity, 403), ('viewer', internal, 403)]:
        response = call(actor, 'POST', path, json={'sbom_id': resource})
        assert response.status_code == status, response.text
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 1
        assert db.get(AnalysisRun, run_id).run_status == 'RUNNING'
    with SessionLocal() as db, verified_fixture_tenant(db, 2):
        assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 0


def test_legacy_vulndb_uuid_reaches_required_provider_configuration(legacy_fixture):
    call, identity, _, _, run_id = legacy_fixture
    response = call('olympus', 'POST', '/analyze-sbom-vulndb', json={'sbom_id': identity})
    assert response.status_code == 400, response.text
    assert response.json()['detail'] == 'VULNDB_API_KEY is required for VulDB-only analysis.'
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.scalar(select(func.count()).select_from(AnalysisRun)) == 1
        assert db.get(AnalysisRun, run_id).run_status == 'RUNNING'
