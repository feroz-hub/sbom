"""Phase 5 — integration: multi_source orchestrator routes NVD queries
through ``NvdLookupService``.

We don't reach for the FastAPI app here — the orchestrator is callable
directly. We patch ``app.analysis.nvd_query_by_cpe`` with a sentinel
that proves the facade's *live* path was taken (default disabled state).
A second test enables the mirror and seeds the local table to prove
the *mirror* path is taken instead.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.nvd_mirror.adapters.secrets import FernetSecretsAdapter
from app.nvd_mirror.adapters.settings_repository import SqlAlchemySettingsRepository
from app.nvd_mirror.adapters.cve_repository import SqlAlchemyCveRepository
from app.nvd_mirror.domain.models import (
    CpeCriterion,
    CveRecord,
    NvdSettingsSnapshot,
)


UTC = timezone.utc


def _minimal_sbom(name: str = "requests", version: str = "2.31.0") -> str:
    """A CycloneDX SBOM with one PyPI component.

    PyPI mapping in cpe23_from_purl is deterministic: vendor=name=name,
    so 'requests' → 'cpe:2.3:a:requests:requests:2.31.0:...' with stem
    'requests:requests'. We use that to make the seeded CPE match
    multi_source's generated CPE exactly.
    """
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                }
            ],
        }
    )


_EXPECTED_STEM = "requests:requests"
_EXPECTED_CRITERIA = "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*"


@pytest.fixture()
def isolated_session(monkeypatch: pytest.MonkeyPatch):
    """Build an isolated SQLite DB and rebind ``app.db.SessionLocal`` to it.

    Why the rebind: the multi-source orchestrator's facade uses
    ``app.db.SessionLocal``. To inject our test DB we patch the global
    SessionLocal that ``build_nvd_lookup_for_pipeline`` imports.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    from app.db import Base
    import app.nvd_mirror.db.models  # noqa: F401

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    # Rebind the symbol the facade imports.
    import app.db as app_db

    monkeypatch.setattr(app_db, "SessionLocal", SessionLocal)

    yield SessionLocal

    engine.dispose()
    Path(path).unlink(missing_ok=True)


# --- Mirror disabled (default) → live path used ---------------------------


def test_orchestrator_uses_live_when_mirror_disabled(
    isolated_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default snapshot has ``enabled=False``. multi_source's NVD
    fan-out must route through the facade's live path — and we'll prove
    that by patching ``nvd_query_by_cpe`` and asserting it was called.
    """
    captured: list[str] = []

    def _fake_live(cpe, api_key, settings=None):
        captured.append(cpe)
        # Return a minimal raw NVD record so _finding_from_raw produces a finding.
        return [
            {
                "id": "CVE-LIVE-1",
                "descriptions": [{"lang": "en", "value": "from live"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-04-01T00:00:00.000",
                "vulnStatus": "Analyzed",
            }
        ]

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_live)

    # Stop OSV / GitHub from leaking into the test result.
    async def _empty_pair(*_a, **_kw):
        return [], [], []

    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _empty_pair)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _empty_pair)

    from app.pipeline.multi_source import run_multi_source_analysis_async

    result = asyncio.run(
        run_multi_source_analysis_async(
            _minimal_sbom(), sources=["NVD"]
        )
    )

    # The patched live function was called with the requests CPE.
    assert any("requests:requests" in c for c in captured), captured
    # The fake live result flowed through the pipeline.
    findings = result["findings"]
    assert any(f.get("vuln_id") == "CVE-LIVE-1" for f in findings)


# --- Mirror enabled, fresh, has data → mirror path used -------------------


def test_orchestrator_uses_mirror_when_enabled_and_fresh(
    isolated_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enable the mirror, seed a CVE for log4j, and assert that the
    pipeline returns the *mirror* CVE (not the live one).
    """
    fernet_key = Fernet.generate_key()
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", fernet_key.decode())

    # Seed: enable mirror, advance watermark to "fresh", upsert one CVE.
    SessionLocal = isolated_session
    s = SessionLocal()
    try:
        secrets = FernetSecretsAdapter(fernet_key)
        settings_repo = SqlAlchemySettingsRepository(s, secrets)
        cve_repo = SqlAlchemyCveRepository(s)

        now = datetime.now(tz=UTC)
        snap = NvdSettingsSnapshot(
            enabled=True,
            api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
            api_key_plaintext=None,
            download_feeds_enabled=False,
            page_size=2000,
            window_days=119,
            min_freshness_hours=24,
            last_modified_utc=now,
            last_successful_sync_at=now,
            updated_at=now,
        )
        settings_repo.save(snap)
        # save() doesn't move the watermark — set it via advance_watermark.
        settings_repo.advance_watermark(
            last_modified_utc=now, last_successful_sync_at=now
        )

        criterion = CpeCriterion(
            criteria=_EXPECTED_CRITERIA,
            criteria_stem=_EXPECTED_STEM,
            vulnerable=True,
        )
        record = CveRecord(
            cve_id="CVE-MIRROR-1",
            last_modified=now - timedelta(hours=2),
            published=now - timedelta(days=10),
            vuln_status="Analyzed",
            description_en="from mirror",
            score_v40=None,
            score_v31=9.8,
            score_v2=None,
            severity_text="CRITICAL",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            aliases=(),
            cpe_criteria=(criterion,),
            references=(),
            raw={
                "id": "CVE-MIRROR-1",
                "descriptions": [{"lang": "en", "value": "from mirror"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "published": (now - timedelta(days=10)).isoformat(),
                "lastModified": (now - timedelta(hours=2)).isoformat(),
                "vulnStatus": "Analyzed",
            },
        )
        cve_repo.upsert_batch([record])
        s.commit()
    finally:
        s.close()

    # If the live path is hit, this fake's findings would appear instead.
    live_call_count = {"n": 0}

    def _fake_live(cpe, api_key, settings=None):
        live_call_count["n"] += 1
        return [{"id": "CVE-LIVE-WAS-CALLED"}]

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_live)

    async def _empty_pair(*_a, **_kw):
        return [], [], []

    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _empty_pair)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _empty_pair)

    from app.pipeline.multi_source import run_multi_source_analysis_async

    result = asyncio.run(
        run_multi_source_analysis_async(_minimal_sbom(), sources=["NVD"])
    )

    findings = result["findings"]
    vuln_ids = {f.get("vuln_id") for f in findings}
    assert "CVE-MIRROR-1" in vuln_ids
    # Live must not have been called for the matched CPE.
    assert live_call_count["n"] == 0


# --- Mirror enabled, stale → live + warning -------------------------------


def test_orchestrator_falls_back_to_live_when_mirror_stale(
    isolated_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fernet_key = Fernet.generate_key()
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", fernet_key.decode())

    SessionLocal = isolated_session
    s = SessionLocal()
    try:
        secrets = FernetSecretsAdapter(fernet_key)
        repo = SqlAlchemySettingsRepository(s, secrets)
        now = datetime.now(tz=UTC)
        repo.save(
            NvdSettingsSnapshot(
                enabled=True,
                api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
                api_key_plaintext=None,
                download_feeds_enabled=False,
                page_size=2000,
                window_days=119,
                min_freshness_hours=1,  # 1 hour
                last_modified_utc=now - timedelta(days=5),
                last_successful_sync_at=now - timedelta(days=5),  # stale
                updated_at=now,
            )
        )
        # Watermark write
        repo.advance_watermark(
            last_modified_utc=now - timedelta(days=5),
            last_successful_sync_at=now - timedelta(days=5),
        )
        s.commit()
    finally:
        s.close()

    captured: list[str] = []

    def _fake_live(cpe, api_key, settings=None):
        captured.append(cpe)
        return []

    import app.analysis as analysis_mod

    monkeypatch.setattr(analysis_mod, "nvd_query_by_cpe", _fake_live)

    async def _empty_pair(*_a, **_kw):
        return [], [], []

    monkeypatch.setattr(analysis_mod, "osv_query_by_components", _empty_pair)
    monkeypatch.setattr(analysis_mod, "github_query_by_components", _empty_pair)

    from app.pipeline.multi_source import run_multi_source_analysis_async

    asyncio.run(run_multi_source_analysis_async(_minimal_sbom(), sources=["NVD"]))

    # Stale path: live was called (the warning log was checked in the
    # port-based facade tests).
    assert len(captured) >= 1


# --- session-scoped wrapper -----------------------------------------------


def test_session_scoped_facade_opens_and_closes_session_per_call(
    isolated_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each query_legacy call must open AND close a session — proves
    we're safe for concurrent calls from a thread pool."""
    fernet_key = Fernet.generate_key()
    monkeypatch.setenv("NVD_MIRROR_FERNET_KEY", fernet_key.decode())

    # Stub the live path so the disabled-mirror fallback doesn't try to
    # talk to the real network or read .http_user_agent off our settings
    # sentinel.
    import app.analysis as analysis_mod

    monkeypatch.setattr(
        analysis_mod, "nvd_query_by_cpe", lambda cpe, api_key, settings=None: []
    )

    from app.nvd_mirror.application import build_nvd_lookup_for_pipeline

    # Wrap SessionLocal to count constructions/closures.
    SessionLocal = isolated_session
    counts = {"opened": 0, "closed": 0}
    original_session_class = SessionLocal

    class _CountingSession:
        def __init__(self) -> None:
            counts["opened"] += 1
            self._inner = original_session_class()
            self.commit = self._inner.commit
            self.rollback = self._inner.rollback
            self.execute = self._inner.execute
            self.add = self._inner.add
            self.flush = self._inner.flush
            self.get = self._inner.get
            self.get_bind = self._inner.get_bind
            self.query = self._inner.query

        def close(self) -> None:
            counts["closed"] += 1
            self._inner.close()

    import app.db as app_db

    monkeypatch.setattr(app_db, "SessionLocal", _CountingSession)

    facade = build_nvd_lookup_for_pipeline()

    # 3 lookups → 3 sessions opened, 3 closed.
    for _ in range(3):
        facade.query_legacy(
            "cpe:2.3:a:nobody:nothing:1.0.0:*:*:*:*:*:*:*",
            api_key=None,
            settings=object(),
        )
    assert counts == {"opened": 3, "closed": 3}
