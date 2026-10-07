"""Application-level SPDX release gates using the shared Phase 1/2 workflow."""
import copy
import json
import logging
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest
from app.db import SessionLocal
from app.models import SBOMRepairJob, SBOMSource, SBOMValidationSession, SBOMValidationSessionEvent
from app.services.sbom.quality.engine import QualityEngine
from app.services.sbom.repair.engine import RepairEngine
from app.validation import run
from sqlalchemy import func, select

from tests.test_sbom_spdx_integration import base, job, upload
from tests.test_sbom_spdx_quality_repair import document, raw


@pytest.mark.parametrize('version', ['2.2', '2.3'])
def test_version_categories_never_cross_normalized(version):
    doc = document(version)
    original = raw(doc)
    report = run(original)
    assert not report.has_errors()
    result = RepairEngine().run(original)
    assert result.report['spec_version'] == version
    assert result.candidate == original
    opposite = 'PACKAGE-MANAGER' if version == '2.2' else 'PACKAGE_MANAGER'
    doc['packages'][0]['externalRefs'][0]['referenceCategory'] = opposite
    result = RepairEngine().run(raw(doc))
    assert run(raw(doc)).has_errors()
    if result.candidate:
        assert json.loads(result.candidate)['packages'][0]['externalRefs'][0]['referenceCategory'] == opposite


@pytest.mark.parametrize('payload', [
    b'SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: example\n',
    b'spdxVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\n',
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>',
    b'{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","type":"SpdxDocument"}',
    Path('tests/fixtures/sboms/valid/cyclonedx_1_6_realistic.xml').read_bytes(),
])
def test_unsupported_format_matrix(payload):
    quality = QualityEngine().calculate(payload)
    result = RepairEngine().run(payload)
    assert not quality.supported
    assert result.candidate == payload
    assert not result.report['analysis']['repair_supported']
    assert result.report['repairs_applied'] == 0


@pytest.mark.parametrize('version', ['SPDX-2.1', 'SPDX-2.4', 'SPDX-3.0'])
def test_unsupported_spdx_versions_remain_manual(version):
    doc = document()
    doc['spdxVersion'] = version
    assert not QualityEngine().calculate(raw(doc)).supported
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_spdx_evidence_identical_across_fresh_process():
    content = raw(document())
    script = "import sys,json; from app.services.sbom.quality.engine import QualityEngine; d=QualityEngine().calculate(sys.stdin.buffer.read()).model_dump(mode='json'); d.pop('calculated_at'); print(json.dumps(d,sort_keys=True))"
    results = [subprocess.check_output([sys.executable, '-c', script], input=content) for _ in range(2)]
    assert results[0] == results[1]


@pytest.mark.parametrize('payload', [b'{"spdxVersion":"SPDX-2.3","x":-Infinity}', b'{"spdxVersion":"SPDX-2.3","x":1e999}', b'{"spdxVersion":"SPDX-2.3","name":"\xff"}', b'{"spdxVersion":"SPDX-2.3","x":[}'])
def test_strict_malformed_inputs_consistent(payload):
    assert run(payload).has_errors()
    assert not QualityEngine().calculate(payload).supported
    assert RepairEngine().run(payload).candidate == payload


@pytest.mark.parametrize('kind', ['CONTAINED_BY', 'DESCRIBED_BY', 'GENERATED_FROM'])
def test_relationship_direction_comment_preserved(kind):
    doc = document()
    relation = {'spdxElementId': 'SPDXRef-Package-foo', 'relatedSpdxElement': 'SPDXRef-DOCUMENT', 'relationshipType': kind, 'comment': 'producer evidence'}
    doc['relationships'].extend([copy.deepcopy(relation), copy.deepcopy(relation)])
    result = RepairEngine().run(raw(doc))
    candidate = json.loads(result.candidate)
    assert candidate['relationships'].count(relation) == 1


def test_self_relationship_never_removed():
    doc = document()
    relation = {'spdxElementId': 'SPDXRef-Package-foo', 'relatedSpdxElement': 'SPDXRef-Package-foo', 'relationshipType': 'DEPENDS_ON'}
    doc['relationships'].append(relation)
    result = RepairEngine().run(raw(doc))
    assert result.report['status'] == 'MANUAL_REVIEW_REQUIRED'
    assert result.candidate == raw(doc)


@pytest.mark.parametrize('mode', ['duplicate', 'malformed', 'missing'])
def test_external_documents_never_guessed(mode):
    doc = document()
    declaration = {'externalDocumentId': 'DocumentRef-other', 'spdxDocument': 'https://example.invalid/external', 'checksum': {'algorithm': 'SHA256', 'checksumValue': 'a' * 64}}
    doc['externalDocumentRefs'] = [declaration, copy.deepcopy(declaration)] if mode == 'duplicate' else []
    doc['relationships'][0]['relatedSpdxElement'] = 'DocumentRef-other:SPDXRef-foreign' if mode != 'malformed' else 'DocumentRef-other'
    result = RepairEngine().run(raw(doc))
    assert result.candidate == raw(doc)
    assert run(raw(doc)).has_errors()


@pytest.mark.parametrize('field', ['signature', 'nested'])
def test_signed_spdx_does_not_rewrite(field):
    doc = document()
    doc['packages'][0]['externalRefs'][0]['referenceLocator'] = ' pkg:npm/foo@1.0.0 '
    doc[field] = {'signature': {'value': 'opaque'}} if field == 'nested' else {'value': 'opaque'}
    content = raw(doc)
    result = RepairEngine().run(content)
    assert result.candidate == content and result.report['status'] == 'MANUAL_REVIEW_REQUIRED'
    assert sha256(content).hexdigest() == sha256(result.candidate).hexdigest()


@pytest.mark.parametrize('action', ['repair', 'approve', 'race'])
def test_spdx_concurrent_terminal_decisions(client, action):
    session = upload(client)
    if action == 'repair':
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: client.post(base(session) + '/repair'), range(2)))
        assert [r.status_code for r in responses] == [200, 200]
        assert len({r.json()['repair_job_id'] for r in responses}) == 1
        return
    result = job(client, session)
    endpoint = base(session) + f"/repair/{result['repair_job_id']}"
    actions = ['approve', 'approve'] if action == 'approve' else ['approve', 'reject']
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda a: client.post(endpoint + '/' + a, json={'candidate_sha256': result['candidate_sha256']}), actions))
    assert sorted(r.status_code for r in responses) == ([200, 200] if action == 'approve' else [200, 409])
    with SessionLocal() as db:
        events = db.scalars(select(SBOMValidationSessionEvent).where(SBOMValidationSessionEvent.session_id == session, SBOMValidationSessionEvent.event_type.in_(['SBOM_REPAIR_APPROVED', 'SBOM_REPAIR_REJECTED']))).all()
        assert len(events) == 1
        accepted = db.scalar(select(func.count()).select_from(SBOMSource))
        assert accepted <= 1


def test_spdx_tamper_restore_and_quality_during_approval(client):
    session = upload(client)
    result = job(client, session)
    endpoint = base(session) + f"/repair/{result['repair_job_id']}"
    with SessionLocal() as db:
        saved = db.get(SBOMRepairJob, result['repair_job_id']).candidate_content
        db.connection().exec_driver_sql('UPDATE sbom_repair_jobs SET candidate_content = %s WHERE id = %s', (saved + ' ', result['repair_job_id']))
        db.commit()
    assert client.get(endpoint).status_code == 409
    with SessionLocal() as db:
        db.connection().exec_driver_sql('UPDATE sbom_repair_jobs SET candidate_content = %s WHERE id = %s', (saved, result['repair_job_id']))
        db.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        approval = pool.submit(client.post, endpoint + '/approve', json={'candidate_sha256': result['candidate_sha256']})
        quality = pool.submit(client.get, base(session) + '/quality')
        assert approval.result().status_code == 200
        assessment = quality.result().json()['assessment']
    assert assessment['artifact_hash'] in {result['source_sha256'], result['candidate_sha256']}
    assert client.get(endpoint).json()['quality']['after']['artifact_hash'] == result['candidate_sha256']


def test_spdx_deletion_cascades_evidence_retains_original_files(client, monkeypatch, tmp_path):
    from app.services.sbom_delete_service import SBOMDeleteService
    monkeypatch.setenv('SBOM_SMALL_FILE_MAX_BYTES', '1')
    monkeypatch.setenv('SBOM_WORKSPACE_STORAGE_DIR', str(tmp_path))
    items = []
    for _ in range(2):
        session = upload(client)
        result = job(client, session)
        accepted = client.post(base(session) + f"/repair/{result['repair_job_id']}/approve", json={'candidate_sha256': result['candidate_sha256']}).json()['imported_sbom_id']
        items.append((session, result['repair_job_id'], accepted))
    deleted, kept = items
    with SessionLocal() as db:
        workspace = db.get(SBOMValidationSession, deleted[0])
        paths = [Path(p) for p in (workspace.raw_storage_path, workspace.repair_storage_path) if p]
        originals = {p: p.read_bytes() for p in paths}
        SBOMDeleteService(db, tenant_id=1).permanently_delete_sbom(deleted[2], 'spdx-release', True)
        assert db.get(SBOMRepairJob, deleted[1]) is None
        assert db.get(SBOMValidationSession, deleted[0]) is None
        assert db.scalar(select(func.count()).select_from(SBOMValidationSessionEvent).where(SBOMValidationSessionEvent.session_id == deleted[0])) == 0
        assert db.get(SBOMRepairJob, kept[1]) is not None
        assert originals == {p: p.read_bytes() for p in paths}


def test_spdx_audit_includes_format_without_payload(client, caplog):
    session = upload(client)
    caplog.set_level(logging.INFO)
    client.get(base(session) + '/quality', headers={'X-Request-ID': 'spdx-quality'})
    client.post(base(session) + '/repair/analyze', headers={'X-Request-ID': 'spdx-analyze'})
    result = client.post(base(session) + '/repair', headers={'X-Request-ID': 'spdx-repair'}).json()
    client.post(base(session) + f"/repair/{result['repair_job_id']}/approve", json={'candidate_sha256': result['candidate_sha256']}, headers={'X-Request-ID': 'spdx-approve'})
    records = [r for r in caplog.records if getattr(r, 'event', '').startswith(('SBOM_REPAIR_', 'SBOM_QUALITY_'))]
    assert {r.event for r in records} >= {'SBOM_QUALITY_CALCULATED', 'SBOM_REPAIR_RULE_APPLIED', 'SBOM_REPAIR_REVALIDATED', 'SBOM_REPAIR_APPROVED'}
    for record in records:
        assert record.tenant_id == 1 and record.user_id is not None and record.request_id
        assert record.format.upper() == 'SPDX_JSON' and record.spec_version in {'2.3', 'SPDX-2.3'}
        assert 'candidate_content' not in record.__dict__ and 'sbom_data' not in record.__dict__
        assert 'pkg:npm/foo' not in record.getMessage()


def test_many_spdx_findings_build_one_index_per_analysis(monkeypatch):
    from app.services.sbom.quality import spdx_inspection
    calls = []
    original = spdx_inspection.SpdxIndex.__init__
    def count_index(self, doc):
        calls.append(id(doc))
        original(self, doc)
    monkeypatch.setattr(spdx_inspection.SpdxIndex, '__init__', count_index)
    doc = document()
    package = doc['packages'][0]
    doc['packages'] = []
    for i in range(120):
        value = copy.deepcopy(package)
        value['SPDXID'] = f'SPDXRef-Package-{i}'
        value['name'] = f'package-{i}'
        value['externalRefs'][0]['referenceLocator'] = f' pkg:generic/package-{i}@1.0.0 '
        doc['packages'].append(value)
    doc['relationships'][0]['relatedSpdxElement'] = 'SPDXRef-Package-0'
    assert RepairEngine().analyze(raw(doc))['auto_fixable'] == 120
    assert len(calls) == 1
    calls.clear()
    QualityEngine().calculate(raw(doc))
    assert len(calls) == 1
    assert spdx_inspection._PREPARED.get() is None


def test_independent_rules_do_not_retain_stale_identity_cache():
    from app.services.sbom.repair.rules.spdx import SpdxReferenceRule
    rule = SpdxReferenceRule()
    doc = document()
    doc['relationships'][0]['relatedSpdxElement'] = 'pkg:npm/foo@1.0.0'
    error = {'code': 'QUALITY_SPDX_DANGLING_REFERENCE', 'path': '/relationships/0/relatedSpdxElement'}
    assert rule.propose(doc, error).new_value == 'SPDXRef-Package-foo'
    doc['packages'][0]['SPDXID'] = 'SPDXRef-New'
    assert rule.propose(doc, error).new_value == 'SPDXRef-New'


@pytest.mark.parametrize('version', ['1.4', '1.5', '1.6'])
def test_cyclonedx_overflow_quality_and_repair_stay_manual(version):
    content = ('{"bomFormat":"CycloneDX","specVersion":"' + version + '","version":1,"extra":1e999}').encode()
    assert not QualityEngine().calculate(content).supported
    assert RepairEngine().run(content).candidate == content


@pytest.mark.parametrize('identifier', [['malformed'], {'invalid': 'identifier'}])
def test_malformed_extracted_license_id_is_quality_finding_not_exception(identifier):
    doc = document()
    doc['packages'][0]['licenseDeclared'] = 'MIT'
    doc['hasExtractedLicensingInfos'] = [{'licenseId': identifier, 'extractedText': 'existing producer evidence'}]
    assessment = QualityEngine().calculate(raw(doc))
    assert assessment.validation_status == 'FAILED'
    assert assessment.findings
    assert next(d for d in assessment.dimensions if d.code == 'QD-07').score == 100
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_extracted_license_index_is_built_once_for_many_assertions(monkeypatch):
    from app.services.sbom.quality import spdx_inspection
    seen = []
    original = spdx_inspection.records
    def counted_records(doc, key):
        if key == 'hasExtractedLicensingInfos':
            seen.append(key)
        return original(doc, key)
    monkeypatch.setattr(spdx_inspection, 'records', counted_records)
    doc = document()
    doc['packages'][0]['licenseDeclared'] = doc['packages'][0]['licenseConcluded'] = 'LicenseRef-Custom'
    doc['hasExtractedLicensingInfos'] = [{'licenseId': 'LicenseRef-Custom', 'extractedText': 'existing producer evidence'}]
    package = doc['packages'][0]
    doc['packages'] = []
    for i in range(100):
        value = copy.deepcopy(package)
        value['SPDXID'] = f'SPDXRef-Package-{i}'
        doc['packages'].append(value)
    doc['relationships'][0]['relatedSpdxElement'] = 'SPDXRef-Package-0'
    QualityEngine().calculate(raw(doc))
    assert seen == ['hasExtractedLicensingInfos']
