"""SecretCipher round-trip + tamper-detection + edge-case tests."""

from __future__ import annotations

import base64

import pytest
from app.security.secrets import SecretCipher, generate_master_key


def _fresh_cipher() -> SecretCipher:
    return SecretCipher.from_b64(generate_master_key())


def test_round_trip():
    c = _fresh_cipher()
    plaintext = "sk-ant-api03-AhB7-very-long-secret-key-payload"
    ct = c.encrypt(plaintext)
    assert ct != plaintext
    assert c.decrypt(ct) == plaintext


def test_round_trip_unicode():
    c = _fresh_cipher()
    pt = "🔑 unicode key with emoji 中文"
    assert c.decrypt(c.encrypt(pt)) == pt


def test_each_encrypt_uses_fresh_nonce():
    """Same plaintext → different ciphertexts (nonce randomness)."""
    c = _fresh_cipher()
    a = c.encrypt("identical-payload")
    b = c.encrypt("identical-payload")
    assert a != b


def test_decrypt_with_wrong_key_fails():
    plaintext = "secret-payload"
    c1 = _fresh_cipher()
    c2 = _fresh_cipher()
    ct = c1.encrypt(plaintext)
    with pytest.raises(ValueError):
        c2.decrypt(ct)


def test_decrypt_tampered_ciphertext_fails():
    c = _fresh_cipher()
    ct = c.encrypt("payload")
    raw = bytearray(base64.b64decode(ct))
    # Flip one byte mid-ciphertext.
    raw[20] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ValueError):
        c.decrypt(tampered)


def test_decrypt_truncated_ciphertext_fails():
    c = _fresh_cipher()
    ct = c.encrypt("payload")
    truncated = ct[:10]
    with pytest.raises(ValueError):
        c.decrypt(truncated)


def test_decrypt_invalid_base64_fails():
    c = _fresh_cipher()
    with pytest.raises(ValueError):
        c.decrypt("!!!not-base64!!!")


def test_decrypt_empty_string_rejected():
    c = _fresh_cipher()
    with pytest.raises(ValueError):
        c.decrypt("")


def test_constructor_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        SecretCipher(b"too-short")
    with pytest.raises(ValueError):
        SecretCipher(b"x" * 31)
    # Exactly 32 bytes is fine.
    SecretCipher(b"\x00" * 32)


def test_from_env_rejects_missing(monkeypatch):
    monkeypatch.delenv("AI_CONFIG_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError):
        SecretCipher.from_env()


def test_from_env_rejects_invalid_base64(monkeypatch):
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", "not!base64@@")
    with pytest.raises(RuntimeError):
        SecretCipher.from_env()


def test_from_env_loads_valid_key(monkeypatch):
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    c = SecretCipher.from_env()
    assert c.decrypt(c.encrypt("ok")) == "ok"


def test_generate_master_key_is_32_bytes_b64():
    key_b64 = generate_master_key()
    raw = base64.b64decode(key_b64)
    assert len(raw) == 32
