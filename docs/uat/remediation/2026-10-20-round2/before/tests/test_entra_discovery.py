import io
import json

import pytest
from app.services import entra_auth_service as entra

TENANT = "11111111-1111-4111-8111-111111111111"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


@pytest.mark.parametrize("metadata", [
    {"issuer": "https://attacker.test", "jwks_uri": "https://login.microsoftonline.com/keys"},
    {"issuer": ISSUER, "jwks_uri": "https://attacker.test/keys"},
    {"issuer": ISSUER, "jwks_uri": "http://login.microsoftonline.com/keys"},
    {"issuer": ISSUER, "jwks_uri": "https://user:password@login.microsoftonline.com/keys"},
])
def test_discovery_rejects_untrusted_metadata(monkeypatch, metadata):
    entra._jwks_client.cache_clear()
    monkeypatch.setattr(entra, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps(metadata).encode()))
    with pytest.raises(ValueError, match="Invalid Microsoft discovery"):
        entra._jwks_client(TENANT)


def test_discovery_uses_fixed_directory_and_caches_only_public_keys(monkeypatch):
    entra._jwks_client.cache_clear()
    calls = []
    def discovery(url, timeout):
        calls.append(url)
        assert timeout == 5
        return io.BytesIO(json.dumps({"issuer": ISSUER, "jwks_uri": f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"}).encode())
    monkeypatch.setattr(entra, "urlopen", discovery)
    try:
        assert entra._jwks_client(TENANT) is entra._jwks_client(TENANT)
        assert calls == [f"{ISSUER}/.well-known/openid-configuration"]
    finally:
        entra._jwks_client.cache_clear()
