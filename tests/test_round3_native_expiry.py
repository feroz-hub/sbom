"""Round 3 absolute expiry with synthetic keys; no live lifetime or seed changes."""
from datetime import UTC, datetime
from types import SimpleNamespace

import jwt
import pytest
from app.services import native_jwt_service as native
from fastapi import HTTPException

from tests.test_native_iam_phase2 import native_config as _native_config

native_config = _native_config


@pytest.mark.parametrize('ttl', [60, 900, 86400])
def test_valid_signature_expired_native_token_returns_401(native_config, monkeypatch, ttl):
    settings = native.get_settings().model_copy(update={'native_jwt_access_token_ttl_seconds': ttl})
    monkeypatch.setattr(native, 'get_settings', lambda: settings)
    issued = native.issue_token(SimpleNamespace(id=1), SimpleNamespace(security_version=1))
    valid = native.validate_token(issued)
    assert valid['exp'] - valid['iat'] == ttl
    now = int(datetime.now(UTC).timestamp())
    expired_claims = {**valid, 'iat': now - ttl - 10, 'exp': now - 10}
    expired = jwt.encode(expired_claims, native.active_signing_key(), algorithm='RS256',
                         headers={'kid': settings.native_jwt_active_kid})
    with pytest.raises(HTTPException) as caught:
        native.validate_token(expired)
    assert caught.value.status_code == 401
    assert caught.value.detail == 'Authentication required'
