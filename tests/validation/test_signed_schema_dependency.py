"""R3-DEF-004: signed CycloneDX structural schemas resolve offline and fail closed."""
import json

import pytest
from app.validation import run


def signed(version):
    return {"bomFormat": "CycloneDX", "specVersion": version, "version": 1,
            "components": [{"type": "library", "bom-ref": "a", "name": "synthetic", "version": "1"}],
            "signature": {"algorithm": "RS256", "value": "AA"}}


@pytest.mark.parametrize('version', ['1.4', '1.5', '1.6'])
def test_signature_schema_resolves_without_runtime_http(version, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError('Validation must not retrieve a remote schema')

    monkeypatch.setattr(socket, 'create_connection', forbidden)
    report = run(json.dumps(signed(version)).encode())
    assert not report.has_errors(), report.model_dump()
    verified = run(json.dumps(signed(version)).encode(), verify_signature=True)
    assert any('E110' in entry.code for entry in verified.entries)
    assert not any('Internal validator error' in entry.message for entry in verified.entries)


@pytest.mark.parametrize('value', [{"value": "AA"}, {"algorithm": 123, "value": "AA"}])
def test_malformed_signature_is_a_structural_error_not_an_internal_exception(value):
    document = signed('1.6')
    document['signature'] = value
    report = run(json.dumps(document).encode())
    assert report.has_errors()
    assert any(entry.stage == 'schema' and str(entry.severity) == 'error' for entry in report.entries)
    assert not any('Internal validator error' in entry.message for entry in report.entries)
