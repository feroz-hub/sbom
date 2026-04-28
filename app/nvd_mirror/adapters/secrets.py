"""Fernet-backed implementation of ``SecretsPort``.

The NVD API key is encrypted at rest in the ``nvd_settings`` row. The
Fernet key itself is read from an environment variable (default
``NVD_MIRROR_FERNET_KEY``), never persisted.

Generate a key with::

    python -c 'from cryptography.fernet import Fernet; \
               print(Fernet.generate_key().decode())'

The result is a 44-character url-safe base64 string (32 bytes of key
material plus padding).
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


class MissingFernetKeyError(RuntimeError):
    """Raised when the Fernet key env var is unset or empty.

    Application startup is expected to validate this BEFORE handing the
    adapter out — see ``app.main`` lifespan hook (Phase 4 wiring).
    """


class FernetSecretsAdapter:
    """SecretsPort adapter using ``cryptography.fernet``."""

    def __init__(self, key: bytes | str) -> None:
        if isinstance(key, str):
            key_bytes = key.strip().encode("ascii")
        else:
            key_bytes = key.strip() if isinstance(key, bytes) else key
        if not key_bytes:
            raise MissingFernetKeyError(
                "Fernet key must be a non-empty url-safe base64 string"
            )
        # Fernet's constructor validates the key format (44 chars b64).
        # We surface its ValueError as the same MissingFernetKeyError so
        # callers don't have to catch two exception types.
        try:
            self._fernet = Fernet(key_bytes)
        except (ValueError, TypeError) as exc:
            raise MissingFernetKeyError(
                f"Fernet key is malformed (expected 32-byte url-safe b64): {exc}"
            ) from exc

    @classmethod
    def from_env(cls, env_var: str = "NVD_MIRROR_FERNET_KEY") -> FernetSecretsAdapter:
        """Build the adapter from the named env var. Fails fast if unset."""
        raw = os.getenv(env_var)
        if not raw or not raw.strip():
            raise MissingFernetKeyError(
                f"Environment variable {env_var!r} is unset or empty. "
                f"Generate a key with: "
                f"python -c 'from cryptography.fernet import Fernet; "
                f"print(Fernet.generate_key().decode())'"
            )
        return cls(raw)

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a UTF-8 string. Returns opaque ciphertext bytes."""
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt back to the original string. Raises on tamper / wrong key."""
        try:
            return self._fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken as exc:
            # Re-raise with a non-leaky message — never include key
            # material or a partial plaintext in the exception text.
            raise ValueError("Failed to decrypt ciphertext (invalid token or wrong key)") from exc
