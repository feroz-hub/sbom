"""Argon2id primitives. Inputs must never be logged or included in errors."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.profiles import RFC_9106_LOW_MEMORY

_HASHER = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
PASSWORD_HASH_SCHEME = "argon2id"
MAX_PASSWORD_BYTES = 1024


def _valid_input(password: str) -> bool:
    return isinstance(password, str) and 0 < len(password.encode("utf-8")) <= MAX_PASSWORD_BYTES


def hash_password(password: str) -> str:
    """Hash without normalization/truncation; policy belongs to enrollment."""
    if not _valid_input(password):
        raise ValueError("Password must contain between 1 and 1024 UTF-8 bytes.")
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Only accept server-stored hashes, never a hash supplied by a client."""
    if not _valid_input(password) or not isinstance(password_hash, str):
        return False
    try:
        return _HASHER.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(password_hash)
    except (InvalidHashError, TypeError):
        return True
