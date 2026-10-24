"""Shared fixtures for the validation test suite.

Most tests load fixtures from `tests/fixtures/sboms/` via the helpers below;
expected-outcome assertions key on the `code` of the first error / first
warning so contract drift surfaces as a precise diff.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "sboms"


def _read_bytes(rel: str) -> bytes:
    return (FIXTURE_ROOT / rel).read_bytes()


@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    """Absolute path to the fixture corpus root."""
    return FIXTURE_ROOT


@pytest.fixture(scope="session")
def read_fixture():
    """Return a function that reads any fixture file by its relative path."""
    return _read_bytes
