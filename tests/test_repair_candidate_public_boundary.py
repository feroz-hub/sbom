"""R3-DEF-001: review/download/approval must bind the same immutable bytes."""
import hashlib
import json
import uuid


def test_reviewed_candidate_hash_is_accepted_and_retry_does_not_import_twice(client):
    raw = json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "LIBRARY", "bom-ref": "a", "name": "alpha", "version": "1.0"}],
        "dependencies": [],
    }, indent=3).encode()
    uploaded = client.post('/api/sboms/upload', data={'sbom_name': 'r3-review-' + str(uuid.uuid4())},
                           files={'file': ('review.cdx.json', raw, 'application/json')})
    assert uploaded.status_code == 422, uploaded.text
    base = '/api/sbom-validation-sessions/' + uploaded.json()['detail']['session_id']
    job_response = client.post(base + '/repair')
    assert job_response.status_code == 200, job_response.text
    job = job_response.json()
    assert job['status'] == 'REPAIRED'
    route = base + '/repair/' + job['repair_job_id']
    download = client.get(route + '/download')
    assert download.status_code == 200
    reviewed_hash = hashlib.sha256(download.content).hexdigest()
    assert reviewed_hash == job['candidate_sha256']
    assert download.headers['content-type'].startswith('application/json')
    assert download.headers['x-content-type-options'] == 'nosniff'
    assert client.get(base + '/download-original').content == raw
    rejected = client.post(route + '/approve', json={'candidate_sha256': '0' * 64})
    assert rejected.status_code == 409
    assert client.get(base).json()['imported_sbom_id'] is None
    approved = client.post(route + '/approve', json={'candidate_sha256': reviewed_hash})
    assert approved.status_code == 200, approved.text
    identity = approved.json()['imported_sbom_id']
    assert str(uuid.UUID(identity)).lower() == identity
    retry = client.post(route + '/approve', json={'candidate_sha256': reviewed_hash})
    assert retry.status_code == 200
    assert retry.json()['imported_sbom_id'] == identity
    assert retry.json()['already_approved'] is True
    assert client.get(base + '/download-original').content == raw
    history = client.get(base + '/history')
    assert history.status_code == 200
    assert sum(x['event_type'] == 'SBOM_REPAIR_APPROVED' for x in history.json()) == 1
