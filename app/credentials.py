"""
Server-side credentials for vulnerability source adapters.

NVD, GitHub, and VulDB tokens are read only from application settings (environment),
never from HTTP request bodies.
"""

from __future__ import annotations

from .settings import get_settings


def nvd_api_key_for_adapters() -> str | None:
    k = (get_settings().nvd_api_key or "").strip()
    return k or None


def github_token_for_adapters() -> str | None:
    k = (get_settings().github_token or "").strip()
    return k or None


def vulndb_api_key_for_adapters() -> str | None:
    k = (get_settings().vulndb_api_key or "").strip()
    return k or None
