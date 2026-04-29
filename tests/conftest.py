"""
Snapshot test infrastructure.

Goals:
  * Spin the FastAPI app against an isolated temp SQLite database (no
    global state pollution from `sbom_api.db` checked into the repo).
  * Provide a TestClient fixture that runs the startup hook (table
    creation, seed types, ad-hoc migrations).
  * Provide a `mock_external_sources` fixture that monkeypatches the
    `app.analysis.*_query_by_components*` coroutines with deterministic
    fakes. Every analyze endpoint — production and ad-hoc — now goes
    through the `app.sources` adapter registry, and every adapter
    delegates lazily into those coroutines, so a single set of patches
    covers the whole surface.

Why we don't use respx / requests-mock:
  The codebase has zero existing test infra and no lockfile. Adding
  network-mock libraries would expand the dependency surface for what is,
  in practice, a small set of well-typed Python boundaries. Module-level
  monkeypatching at the import sites is sufficient and dependency-free.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Module-level: set DATABASE_URL BEFORE any test imports from ``app.db``.
#
# Why: ``app.db`` creates its engine at module-import time using whatever
# DATABASE_URL is in the environment. If the env var is unset, it falls
# back to ``./sbom_api.db`` (a path inside the repo). Tests that imported
# ``app.db`` before the session-scoped ``app`` fixture set DATABASE_URL
# would lock the engine onto that real on-disk file, polluting it with
# test rows that survived across pytest runs.
#
# The set runs at conftest module-import — pytest imports conftest BEFORE
# collecting any test modules, so this DATABASE_URL is present when any
# subsequent ``from app.db import ...`` happens.
# ---------------------------------------------------------------------------
_SESSION_DB_FD, _SESSION_DB_PATH = tempfile.mkstemp(
    prefix="sbom_test_session_", suffix=".db"
)
os.close(_SESSION_DB_FD)
Path(_SESSION_DB_PATH).unlink(missing_ok=True)
# Use ``setdefault`` so an explicit DATABASE_URL set by the user (or by an
# outer test runner) wins.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_SESSION_DB_PATH}")


# ---------------------------------------------------------------------------
# Database isolation — must run BEFORE any `app.*` import.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _tmp_database_path() -> Iterator[str]:
    fd, path = tempfile.mkstemp(prefix="sbom_test_", suffix=".db")
    os.close(fd)
    # Empty file so SQLite creates a fresh schema on connect.
    Path(path).unlink(missing_ok=True)
    yield path
    Path(path).unlink(missing_ok=True)


@pytest.fixture(scope="session")
def app(_tmp_database_path: str):
    """Import the FastAPI app *after* DATABASE_URL is pointed at the temp DB."""
    os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_database_path}"
    # Avoid CORS noise + force deterministic settings.
    os.environ.setdefault("CORS_ORIGINS", "http://testserver")
    os.environ.setdefault("ANALYSIS_SOURCES", "NVD,OSV,GITHUB")
    # Finding A: lock the existing snapshot suite to mode=none so the
    # bearer-auth dependency is a no-op for these tests. The dedicated
    # auth tests in test_auth.py override this per-test via monkeypatch.
    os.environ["API_AUTH_MODE"] = "none"
    os.environ.pop("API_AUTH_TOKENS", None)
    os.environ["API_RATE_LIMIT_ENABLED"] = "false"
    # Don't let a real GitHub token in the dev shell leak into tests.
    os.environ.pop("GITHUB_TOKEN", None)
    os.environ.pop("NVD_API_KEY", None)
    os.environ.pop("VULNDB_API_KEY", None)

    # Reset cached settings singleton if it exists.
    try:
        from app.settings import reset_settings

        reset_settings()
    except Exception:
        pass

    from app.main import app as fastapi_app

    return fastapi_app


@pytest.fixture()
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Sample SBOM seeding
# ---------------------------------------------------------------------------

_SAMPLE_PATH = Path(__file__).parent / "fixtures" / "sample_sbom.json"


@pytest.fixture(scope="session")
def sample_sbom_dict() -> dict[str, Any]:
    return json.loads(_SAMPLE_PATH.read_text())


@pytest.fixture(scope="session")
def seeded_sbom(app, sample_sbom_dict) -> dict[str, Any]:
    """
    Upload the fixture SBOM exactly once per test session and return the row.

    Session scope + deterministic name = stable `sbom_id` and `sbom_name` in
    every snapshot, so the snapshot diff doesn't trip on the upload echo.
    """
    from fastapi.testclient import TestClient

    name = "snapshot-fixture"
    payload = {
        "sbom_name": name,
        "sbom_data": json.dumps(sample_sbom_dict),
        "created_by": "snapshot-test",
    }
    with TestClient(app) as c:
        resp = c.post("/api/sboms", json=payload)
        assert resp.status_code == 201, resp.text
        return resp.json()


# ---------------------------------------------------------------------------
# Source-fetcher mocks
# ---------------------------------------------------------------------------

from .fixtures import canned_responses as canned  # noqa: E402

# ---- Async source-fetcher fakes for app.analysis.* ----
# Every analyze endpoint (production + ad-hoc) routes through the
# `app.sources` adapter registry, and every adapter delegates lazily into
# the coroutines below. Patching here covers the entire surface in one
# place.


async def _fake_nvd_query_by_components_async(
    components, settings, nvd_api_key=None, lookup_service=None
):
    # `lookup_service` is the R6 mirror-facade hook. The fake intentionally
    # ignores it: snapshot tests assert on the orchestrator-level shape,
    # not on whether the mirror branch was taken — that's covered by the
    # dedicated tests in test_nvd_source_uses_lookup_service.py and
    # tests/nvd_mirror/test_facade_integration.py.
    findings: list[dict[str, Any]] = []
    for c in components:
        if "log4j" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_NVD_FINDING))
    return findings, [], []


async def _fake_osv_query_by_components(components, settings):
    findings: list[dict[str, Any]] = []
    for c in components:
        if "requests" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_OSV_FINDING_REQUESTS))
    return findings, [], []


async def _fake_github_query_by_components(components, settings):
    findings: list[dict[str, Any]] = []
    for c in components:
        if "log4j" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_GHSA_FINDING))
    return findings, [], []


def _fake_nvd_query_by_cpe(cpe, api_key, settings=None):
    """``nvd_query_by_components_async`` calls this per CPE (or the
    mirror facade does, then falls back here on cache miss). Return a
    minimal raw NVD record so ``_finding_from_raw`` produces a
    deterministic finding."""
    if cpe and "log4j" in cpe.lower():
        return [canned.NVD_LOG4J_RESPONSE["vulnerabilities"][0]["cve"]]
    return []


@pytest.fixture()
def mock_external_sources(monkeypatch):
    """
    Patch the underlying source-fetch coroutines with deterministic fakes.

    Every analyze endpoint goes through the same registry-driven path:

        endpoint → NvdSource/OsvSource/GhsaSource → app.analysis.*_query_by_*

    Patching at the `app.analysis` module level catches all four
    `/analyze-sbom-*` ad-hoc endpoints, the production
    `POST /api/sboms/{id}/analyze`, and the streaming
    `POST /api/sboms/{id}/analyze/stream` in one shot.
    """
    # ---- Production multi-source path (now ALSO used by /analyze-sbom-*
    # after the Phase 4 cut-over — both routes go through the registry
    # adapters, which delegate lazily into app.analysis.* coroutines) ----
    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _fake_osv_query_by_components)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _fake_github_query_by_components)
    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_nvd_query_by_cpe)

    # Phase 3 (Finding B): the SSE stream + manual analyze paths now consume
    # the source registry. Patch the underlying analysis.* coroutines that
    # the adapters delegate to so the streaming endpoint sees the same
    # canned data as the snapshot tests above.
    import app.analysis as analysis_mod_for_adapters

    monkeypatch.setattr(
        analysis_mod_for_adapters,
        "nvd_query_by_components_async",
        _fake_nvd_query_by_components_async,
    )
    # osv_query_by_components / github_query_by_components are already
    # patched on `app.analysis` above; the adapters import them lazily from
    # the same module attribute, so the patch propagates.

    yield
