"""Stable, opaque tenant key generation and validation utilities."""

from __future__ import annotations

import re
import uuid

TENANT_KEY_PREFIX = "tnt_"
TENANT_KEY_PATTERN = re.compile(r"^tnt_[0-9a-f]{32}$")


def generate_tenant_key() -> str:
    """Generate an opaque, globally unique tenant key starting with 'tnt_'.

    Format: 'tnt_' + 32-character lowercase UUID hex string (36 characters total).
    Safe for use inside future machine-readable claims (<tenant_key>:<role>).
    Never derived from tenant name, slug, ID, or external metadata.
    """
    return f"{TENANT_KEY_PREFIX}{uuid.uuid4().hex}"


def is_valid_tenant_key(value: str | None) -> bool:
    """Return True if value matches the canonical tenant key format."""
    if not value or not isinstance(value, str):
        return False
    return bool(TENANT_KEY_PATTERN.fullmatch(value))
