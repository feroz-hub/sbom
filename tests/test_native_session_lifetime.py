"""Native sessions use a fixed, configurable lifetime of up to one day."""
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from app.settings import Settings
from app.services import native_jwt_service


def test_native_session_defaults_to_one_day():
    assert Settings(_env_file=None).native_jwt_access_token_ttl_seconds == 86400


@pytest.mark.parametrize('duration', [60, 900, 86400])
def test_native_session_accepts_supported_durations(duration):
    settings = Settings(_env_file=None, native_jwt_access_token_ttl_seconds=duration)
    assert settings.native_jwt_access_token_ttl_seconds == duration


@pytest.mark.parametrize('duration', [59, 86401])
def test_native_session_rejects_out_of_range_durations(duration):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, native_jwt_access_token_ttl_seconds=duration)


def test_issued_token_is_valid_for_one_day(monkeypatch):
    settings = Settings(_env_file=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(native_jwt_service, 'get_settings', lambda: settings)
    monkeypatch.setattr(native_jwt_service, 'signing_key', lambda: key)
    token = native_jwt_service.issue_token(SimpleNamespace(id=1), SimpleNamespace(security_version=1))
    claims = jwt.decode(token, key.public_key(), algorithms=['RS256'], audience=settings.native_jwt_audience)
    assert claims['exp'] - claims['iat'] == 86400
