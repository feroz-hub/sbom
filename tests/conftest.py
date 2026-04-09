"""
Phase-0 snapshot test infrastructure.

Goals:
  * Spin the FastAPI app against an isolated temp SQLite database (no global
    state pollution from `sbom_api.db` checked into the repo).
  * Provide a TestClient fixture that runs the startup hook (table creation,
    seed types, ad-hoc migrations).
  * Provide a `mock_external_sources` fixture that monkeypatches every
    outbound source-fetcher to return canned data — both the legacy
    `vuln_sources` path (used by `/analyze-sbom-*`) and the
    `app.analysis.*_query_by_components` path (used by
    `POST /api/sboms/{id}/analyze`). This is the boundary that Finding B's
    refactor will move; mocking here lets the snapshot tests stay valid
    across that refactor.

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
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest


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
    # Don't let a real GitHub token in the dev shell leak into tests.
    os.environ.pop("GITHUB_TOKEN", None)
    os.environ.pop("NVD_API_KEY", None)

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
def sample_sbom_dict() -> Dict[str, Any]:
    return json.loads(_SAMPLE_PATH.read_text())


@pytest.fixture(scope="session")
def seeded_sbom(app, sample_sbom_dict) -> Dict[str, Any]:
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


def _fake_nvd_fetch(name, version_str, cpe, nvd_api_key, results_per_page=20):
    if "log4j" in (name or "").lower():
        return canned.NVD_LOG4J_RESPONSE
    return canned.NVD_EMPTY_RESPONSE


def _fake_github_fetch_advisories(ecosystem, pkg_name, token, first=100):
    if "log4j" in (pkg_name or "").lower():
        return canned.GHSA_LOG4J_RESPONSE
    return canned.GHSA_EMPTY_RESPONSE


def _fake_osv_querybatch(queries):
    # Return one canned vuln per query so each component sees an advisory.
    out: List[Dict[str, Any]] = []
    for q in queries:
        pkg = (q.get("package") or {}).get("name", "")
        if "log4j" in pkg.lower():
            out.append({"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01T00:00:00Z"}]})
        elif "requests" in pkg.lower():
            out.append({"vulns": [{"id": "PYSEC-2018-28", "modified": "2024-01-01T00:00:00Z"}]})
        else:
            out.append({"vulns": []})
    return out


def _fake_osv_get_vuln_by_id(osv_id):
    return canned.OSV_VULN_DETAIL.get(osv_id, {"id": osv_id})


# ---- Async source-fetcher fakes for app.analysis.* ----

async def _fake_nvd_query_by_components_async(components, settings, nvd_api_key=None):
    findings: List[Dict[str, Any]] = []
    for c in components:
        if "log4j" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_NVD_FINDING))
    return findings, [], []


async def _fake_osv_query_by_components(components, settings):
    findings: List[Dict[str, Any]] = []
    for c in components:
        if "requests" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_OSV_FINDING_REQUESTS))
    return findings, [], []


async def _fake_github_query_by_components(components, settings):
    findings: List[Dict[str, Any]] = []
    for c in components:
        if "log4j" in (c.get("name") or "").lower():
            findings.append(dict(canned.ASYNC_GHSA_FINDING))
    return findings, [], []


def _fake_nvd_query_by_cpe(cpe, api_key, settings=None):
    """`analyze_sbom_multi_source_async._nvd` calls this per CPE.
    Return a minimal raw NVD record so `_finding_from_raw` produces a
    deterministic finding."""
    if cpe and "log4j" in cpe.lower():
        return [canned.NVD_LOG4J_RESPONSE["vulnerabilities"][0]["cve"]]
    return []


@pytest.fixture()
def mock_external_sources(monkeypatch):
    """
    Patch every outbound source-fetcher with deterministic fakes.

    This fixture intentionally patches at *both* layers:

      1. `app.routers.analyze_endpoints.<name>` for the legacy
         `/analyze-sbom-*` endpoints (which import the helpers from
         `app.services.vuln_sources`).
      2. `app.analysis.<name>` for the production multi-source path used
         by `POST /api/sboms/{id}/analyze` (which goes through
         `analyze_sbom_multi_source_async`).

    After Finding B lands, layer (1) will move into the new
    `services/sources/` adapters. Tests that exercise the *legacy* response
    shapes will need to be updated then; tests that exercise the production
    multi-source path keep working as long as the orchestrator's contract
    stays the same.
    """
    # ---- Legacy /analyze-sbom-* path ----
    import app.routers.analyze_endpoints as legacy
    monkeypatch.setattr(legacy, "nvd_fetch", _fake_nvd_fetch)
    monkeypatch.setattr(legacy, "github_fetch_advisories", _fake_github_fetch_advisories)
    monkeypatch.setattr(legacy, "osv_querybatch", _fake_osv_querybatch)
    monkeypatch.setattr(legacy, "osv_get_vuln_by_id", _fake_osv_get_vuln_by_id)

    # ---- Production multi-source path ----
    import app.analysis as analysis_mod
    monkeypatch.setattr(
        analysis_mod, "osv_query_by_components", _fake_osv_query_by_components
    )
    monkeypatch.setattr(
        analysis_mod, "github_query_by_components", _fake_github_query_by_components
    )
    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_nvd_query_by_cpe)

    # The router also imports nvd_query_by_components_async at module load —
    # patch it there too in case any code path bypasses the orchestrator.
    import app.routers.sboms_crud as crud
    monkeypatch.setattr(
        crud, "nvd_query_by_components_async", _fake_nvd_query_by_components_async
    )
    monkeypatch.setattr(
        crud, "osv_query_by_components", _fake_osv_query_by_components
    )
    monkeypatch.setattr(
        crud, "github_query_by_components", _fake_github_query_by_components
    )

    yield
