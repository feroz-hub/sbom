"""Secrets port — symmetric encryption for the NVD API key at rest."""

from __future__ import annotations

from typing import Protocol


class SecretsPort(Protocol):
    """Symmetric encryption interface.

    Implementations MUST round-trip: ``decrypt(encrypt(s)) == s`` for
    every str ``s``. The ciphertext is opaque; callers must not parse it.
    """

    def encrypt(self, plaintext: str) -> bytes: ...

    def decrypt(self, ciphertext: bytes) -> str: ...
