"""AES-256-GCM envelope encryption for at-rest credentials.

Phase 2 §2.1 deliverable. Designed for one specific purpose:
**encrypt LLM-provider API keys before they hit Postgres** so the
existing DB backup pipeline doesn't ship plaintext credentials.

Threat model in scope:

  * DB dump leaks (an attacker with read access to the encrypted
    column cannot recover the plaintext without the master key)
  * Backup leaks (same — backups carry only ciphertext)
  * Read-only DB compromise via an injection bug

Threat model **out of scope** (acknowledged limits):

  * Attacker with both DB read access AND env access — they recover
    every credential. The threat model here is at-rest, not active
    compromise.
  * Side-channel timing on the cipher itself — AES-GCM as implemented
    by ``cryptography``'s OpenSSL bindings is constant-time at the
    primitive level.
  * Hardware secure enclaves — KMS / Vault integration is the v2 path;
    documented in docs/runbook-ai-credentials.md.

Why AES-GCM and not Fernet:

  * Fernet uses CBC + HMAC-SHA256 separately — fine, but the standard
    has been AEAD (AES-GCM / ChaCha20-Poly1305) for a decade.
  * AES-GCM gives us authenticated encryption in one primitive, with
    a 12-byte nonce overhead per ciphertext (Fernet adds 32+).
  * ``cryptography.hazmat.primitives.ciphers.aead.AESGCM`` is the
    library's recommended high-level API for this exact use case.

Why a single master key (not per-row keys):

  * Per-row keys would require an external KMS to wrap them; without
    one, we'd just be storing the row keys next to the ciphertext.
  * One master key + AES-GCM is identical to envelope encryption with
    a degenerate (1-key) DEK pool.
  * KMS / Vault integration is the upgrade path when an enterprise
    customer demands it (the cipher class stays; only key resolution
    changes).
"""

from __future__ import annotations

import base64
import os
import secrets
from typing import ClassVar

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12  # AES-GCM standard nonce length
_KEY_BYTES = 32    # AES-256


class SecretCipher:
    """AES-256-GCM authenticated encryption for at-rest credentials.

    Storage shape: ``base64(nonce || ciphertext || tag)``. The nonce is
    random per-encryption (12 bytes from ``secrets.token_bytes``); the
    GCM tag is appended by the underlying primitive.

    Construct via :meth:`from_env` in production; the bare constructor
    is for tests that need a deterministic key.
    """

    ENV_VAR: ClassVar[str] = "AI_CONFIG_ENCRYPTION_KEY"

    def __init__(self, master_key: bytes) -> None:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != _KEY_BYTES:
            raise ValueError(
                f"Master key must be exactly {_KEY_BYTES} raw bytes "
                f"(got {len(master_key) if isinstance(master_key, (bytes, bytearray)) else type(master_key).__name__})"
            )
        self._cipher = AESGCM(bytes(master_key))

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Return base64(nonce || ciphertext || tag)."""
        if not isinstance(plaintext, str):
            raise TypeError("encrypt expects a str")
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ct = self._cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt a previously-encrypted ciphertext.

        Raises :class:`ValueError` on tampering / truncation / bad key
        (the underlying ``InvalidTag`` is normalised so callers don't
        leak which library produced the failure).
        """
        if not isinstance(ciphertext_b64, str) or not ciphertext_b64:
            raise ValueError("decrypt expects a non-empty base64 str")
        try:
            raw = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("ciphertext is not valid base64") from exc
        if len(raw) < _NONCE_BYTES + 16:  # 16 = GCM tag length
            raise ValueError("ciphertext too short to be valid")
        nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        try:
            return self._cipher.decrypt(nonce, ct, None).decode("utf-8")
        except Exception as exc:  # noqa: BLE001 — InvalidTag etc.
            raise ValueError("decryption failed (bad key or tampered ciphertext)") from exc

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, env_var: str | None = None) -> SecretCipher:
        """Load the master key from env. Raises ``RuntimeError`` if missing."""
        var = env_var or cls.ENV_VAR
        raw_b64 = os.environ.get(var)
        if not raw_b64:
            raise RuntimeError(
                f"{var} is not set. Generate one with "
                "`python scripts/generate_encryption_key.py` and add it to your env."
            )
        try:
            key = base64.b64decode(raw_b64.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"{var} is not valid base64") from exc
        return cls(key)

    @classmethod
    def from_b64(cls, key_b64: str) -> SecretCipher:
        """Construct from a base64-encoded key string. Useful for tests."""
        return cls(base64.b64decode(key_b64.encode("ascii"), validate=True))


def generate_master_key() -> str:
    """Return a new random 32-byte key, base64-encoded.

    Used by :file:`scripts/generate_encryption_key.py` and by tests
    that need a fresh cipher.
    """
    return base64.b64encode(secrets.token_bytes(_KEY_BYTES)).decode("ascii")


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------


_singleton: SecretCipher | None = None


def get_cipher() -> SecretCipher:
    """Return the lazily-initialised process-wide cipher.

    Caches across calls so we don't re-read env on every encryption /
    decryption. Tests that change the env should call :func:`reset_cipher`
    afterwards.
    """
    global _singleton
    if _singleton is None:
        _singleton = SecretCipher.from_env()
    return _singleton


def reset_cipher() -> None:
    """Drop the cached singleton — testing helper after env mutation."""
    global _singleton
    _singleton = None


__all__ = [
    "SecretCipher",
    "generate_master_key",
    "get_cipher",
    "reset_cipher",
]
