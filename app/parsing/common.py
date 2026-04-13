"""Shared helpers for SBOM parsing."""

from __future__ import annotations


def norm(s: str | None) -> str | None:
    return s.strip() if isinstance(s, str) and s.strip() else None
