"""Phase 2.5 — FernetSecretsAdapter."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.nvd_mirror.adapters.secrets import (
    FernetSecretsAdapter,
    MissingFernetKeyError,
)


@pytest.fixture
def key() -> bytes:
    return Fernet.generate_key()


def test_round_trip(key: bytes) -> None:
    adapter = FernetSecretsAdapter(key)
    ct = adapter.encrypt("super-secret-nvd-api-key")
    assert isinstance(ct, bytes)
    assert ct != b"super-secret-nvd-api-key"
    assert adapter.decrypt(ct) == "super-secret-nvd-api-key"


def test_round_trip_unicode(key: bytes) -> None:
    adapter = FernetSecretsAdapter(key)
    payload = "πρώτη-key-✓"
    assert adapter.decrypt(adapter.encrypt(payload)) == payload


def test_string_key_accepted(key: bytes) -> None:
    adapter = FernetSecretsAdapter(key.decode())
    ct = adapter.encrypt("x")
    assert adapter.decrypt(ct) == "x"


def test_empty_key_rejected() -> None:
    with pytest.raises(MissingFernetKeyError):
        FernetSecretsAdapter("")
    with pytest.raises(MissingFernetKeyError):
        FernetSecretsAdapter(b"")


def test_malformed_key_rejected() -> None:
    with pytest.raises(MissingFernetKeyError, match="malformed"):
        FernetSecretsAdapter("not-a-real-fernet-key")


def test_decrypt_with_wrong_key_raises_value_error(key: bytes) -> None:
    a = FernetSecretsAdapter(key)
    other = FernetSecretsAdapter(Fernet.generate_key())
    ct = a.encrypt("x")
    with pytest.raises(ValueError, match="invalid token or wrong key"):
        other.decrypt(ct)


def test_decrypt_tampered_ciphertext_raises_value_error(key: bytes) -> None:
    adapter = FernetSecretsAdapter(key)
    ct = bytearray(adapter.encrypt("x"))
    ct[-1] ^= 0xFF
    with pytest.raises(ValueError):
        adapter.decrypt(bytes(ct))


def test_from_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_MIRROR_FERNET_KEY", raising=False)
    with pytest.raises(MissingFernetKeyError, match="NVD_MIRROR_FERNET_KEY"):
        FernetSecretsAdapter.from_env()


def test_from_env_present(monkeypatch: pytest.MonkeyPatch, key: bytes) -> None:
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", key.decode())
    adapter = FernetSecretsAdapter.from_env()
    assert adapter.decrypt(adapter.encrypt("x")) == "x"


def test_from_env_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", "   ")
    with pytest.raises(MissingFernetKeyError):
        FernetSecretsAdapter.from_env()


def test_satisfies_secrets_port_protocol(key: bytes) -> None:
    """Structural check — adapter is acceptable wherever SecretsPort is."""
    from app.nvd_mirror.ports.secrets import SecretsPort

    def consumer(s: SecretsPort, payload: str) -> str:
        return s.decrypt(s.encrypt(payload))

    assert consumer(FernetSecretsAdapter(key), "ok") == "ok"
