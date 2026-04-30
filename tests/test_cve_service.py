"""
CveDetailService integration tests against in-memory SQLite.

Source clients are injected as fakes so no HTTP is touched. Verifies:
  * cache miss → fetch → write → second call is a hit
  * TTL bucketing (KEV-listed CVE → short TTL; older CVE → long TTL)
  * ID validation (HTTP-400-equivalent raise)
  * scan-aware variant joins component context + computes recommended upgrade
  * resilience: a source raising an Exception is captured as ERROR, never escapes

Why injected fakes (not pytest-httpx): the existing tests/conftest.py
explicitly avoids network-mock libraries and wires fake source coroutines
the same way for the existing snapshot tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.integrations.cve.base import FetchOutcome, FetchResult
from app.integrations.cve.identifiers import IdKind
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    CveCache,
    KevEntry,
    Projects,
    SBOMComponent,
    SBOMSource,
)

# Per-source ``accepted_kinds`` mirrors the production declarations on the
# real client classes — kept in one place so test fakes don't drift.
_KINDS_BY_SOURCE = {
    "osv": frozenset({IdKind.CVE, IdKind.GHSA, IdKind.PYSEC, IdKind.RUSTSEC, IdKind.GO, IdKind.OSV_GENERIC}),
    "ghsa": frozenset({IdKind.CVE, IdKind.GHSA}),
    "nvd": frozenset({IdKind.CVE}),
    "kev": frozenset({IdKind.CVE}),
    "epss": frozenset({IdKind.CVE}),
}
from app.services.cve_service import (
    CveDetailService,
    InvalidCveIdError,
    normalise_cve_id,
)


# ----------------------------------------------------------------- fixtures


@pytest.fixture()
def db() -> Session:
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class _FakeSource:
    """A dialled-in source that returns the FetchResult you hand it."""

    def __init__(self, name: str, result: FetchResult, *, raises: Exception | None = None) -> None:
        self.name = name
        self.accepted_kinds = _KINDS_BY_SOURCE[name]
        self._result = result
        self._raises = raises
        self.calls = 0

    async def fetch(self, cve_id: str) -> FetchResult:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._result


def _service(
    db: Session,
    *,
    osv: _FakeSource | None = None,
    ghsa: _FakeSource | None = None,
    nvd: _FakeSource | None = None,
    kev: _FakeSource | None = None,
    epss: _FakeSource | None = None,
) -> CveDetailService:
    """Build a service with all-fake sources by default."""
    osv = osv or _FakeSource("osv", FetchResult(source="osv", outcome=FetchOutcome.NOT_FOUND))
    ghsa = ghsa or _FakeSource("ghsa", FetchResult(source="ghsa", outcome=FetchOutcome.DISABLED))
    nvd = nvd or _FakeSource("nvd", FetchResult(source="nvd", outcome=FetchOutcome.NOT_FOUND))
    kev = kev or _FakeSource("kev", FetchResult(source="kev", outcome=FetchOutcome.NOT_FOUND))
    epss = epss or _FakeSource("epss", FetchResult(source="epss", outcome=FetchOutcome.NOT_FOUND))
    return CveDetailService(db, osv=osv, ghsa=ghsa, nvd=nvd, kev=kev, epss=epss)  # type: ignore[arg-type]


# ----------------------------------------------------------------- ID rules


def test_normalise_cve_id_uppercases_and_validates():
    assert normalise_cve_id("cve-2024-12345") == "CVE-2024-12345"


def test_normalise_cve_id_accepts_ghsa_form():
    """GHSA canonical form: head uppercase, body lowercase. Both case
    spellings normalise to the same canonical key (cache de-dup)."""
    assert normalise_cve_id("ghsa-x2fm-93ww-ggvx") == "GHSA-x2fm-93ww-ggvx"
    assert normalise_cve_id("GHSA-X2FM-93WW-GGVX") == "GHSA-x2fm-93ww-ggvx"
    # CVE form is uppercased verbatim.
    assert normalise_cve_id("cve-2024-12345") == "CVE-2024-12345"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "CVE",
        "GHSA-abc",  # too few segments
        "CVE-2024-1",  # too short
        "ghsa-2024-12345",  # CVE-shaped suffix doesn't match GHSA pattern
        "GHSA-zzzz-zzzz",  # missing third quad
    ],
)
def test_normalise_cve_id_rejects_garbage(bad: str):
    with pytest.raises(InvalidCveIdError):
        normalise_cve_id(bad)


def test_normalise_cve_id_rejects_non_string():
    with pytest.raises(InvalidCveIdError):
        normalise_cve_id(12345)  # type: ignore[arg-type]


# ----------------------------------------------------------------- cache hit


@pytest.mark.asyncio
async def test_get_cache_miss_then_hit(db):
    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={"summary": "ok", "fix_versions": [], "references": []},
        ),
    )
    svc = _service(db, osv=osv)

    first = await svc.get("cve-2024-12345")
    assert first.summary == "ok"
    assert osv.calls == 1
    # Cache row written
    assert db.get(CveCache, "CVE-2024-12345") is not None

    second = await svc.get("CVE-2024-12345")
    assert second.summary == "ok"
    assert osv.calls == 1, "second call must be served from cache"


@pytest.mark.asyncio
async def test_get_cache_expired_refetches(db):
    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={"summary": "fresh", "fix_versions": [], "references": []},
        ),
    )
    svc = _service(db, osv=osv)

    # Pre-seed an expired row.
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    db.add(
        CveCache(
            cve_id="CVE-2024-99999",
            payload={"cve_id": "CVE-2024-99999", "summary": "stale", "fetched_at": expired},
            sources_used="osv",
            fetched_at=expired,
            expires_at=expired,
            fetch_error=None,
            schema_version=1,
        )
    )
    db.commit()

    detail = await svc.get("CVE-2024-99999")
    assert detail.summary == "fresh"
    assert osv.calls == 1


# ------------------------------------------------------------- TTL bucketing


@pytest.mark.asyncio
async def test_kev_listed_cve_uses_short_ttl(db):
    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={"summary": "x", "published": "2010-01-01T00:00:00Z", "fix_versions": [], "references": []},
        ),
    )
    kev = _FakeSource(
        "kev",
        FetchResult(source="kev", outcome=FetchOutcome.OK, data={"listed": True, "due_date": None}),
    )
    svc = _service(db, osv=osv, kev=kev)
    await svc.get("CVE-2010-1111")
    row = db.get(CveCache, "CVE-2010-1111")
    assert row is not None
    expires = datetime.fromisoformat(row.expires_at)
    fetched = datetime.fromisoformat(row.fetched_at)
    assert (expires - fetched).total_seconds() == pytest.approx(6 * 60 * 60, abs=5)


@pytest.mark.asyncio
async def test_old_cve_uses_long_ttl(db):
    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={"summary": "x", "published": "2010-01-01T00:00:00Z", "fix_versions": [], "references": []},
        ),
    )
    svc = _service(db, osv=osv)
    await svc.get("CVE-2010-2222")
    row = db.get(CveCache, "CVE-2010-2222")
    assert row is not None
    expires = datetime.fromisoformat(row.expires_at)
    fetched = datetime.fromisoformat(row.fetched_at)
    # Default stable TTL = 7 days.
    assert (expires - fetched).total_seconds() == pytest.approx(7 * 24 * 60 * 60, abs=5)


# ----------------------------------------------------------- resilience


@pytest.mark.asyncio
async def test_source_raising_exception_is_captured_as_error(db):
    boom = _FakeSource(
        "ghsa",
        FetchResult(source="ghsa", outcome=FetchOutcome.OK),
        raises=RuntimeError("upstream blew up"),
    )
    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={"summary": "still works", "fix_versions": [], "references": []},
        ),
    )
    svc = _service(db, osv=osv, ghsa=boom)
    detail = await svc.get("CVE-2024-12345")
    assert detail.summary == "still works"
    assert detail.is_partial is True
    assert "ghsa" not in detail.sources_used


@pytest.mark.asyncio
async def test_all_sources_fail_still_returns_payload(db):
    fail = lambda name: _FakeSource(name, FetchResult(source=name, outcome=FetchOutcome.ERROR, error="x"))  # noqa: E731
    svc = _service(
        db,
        osv=fail("osv"),
        ghsa=fail("ghsa"),
        nvd=fail("nvd"),
        kev=fail("kev"),
        epss=fail("epss"),
    )
    detail = await svc.get("CVE-2024-12345")
    assert detail.cve_id == "CVE-2024-12345"
    assert detail.is_partial is True
    assert detail.sources_used == []


# ----------------------------------------------------------- scan-aware


@pytest.mark.asyncio
async def test_get_with_scan_context_recommends_upgrade(db):
    proj = Projects(id=1, project_name="p", project_status=1)
    sbom = SBOMSource(id=1, sbom_name="s", projectid=1)
    component = SBOMComponent(id=1, sbom_id=1, name="left-pad", version="1.2.0", purl="pkg:npm/left-pad@1.2.0")
    run = AnalysisRun(
        id=1,
        sbom_id=1,
        project_id=1,
        run_status="OK",
        source="OSV",
        started_on="2024-01-01",
        completed_on="2024-01-01",
    )
    finding = AnalysisFinding(
        id=1,
        analysis_run_id=1,
        component_id=1,
        vuln_id="CVE-2024-12345",
        severity="HIGH",
        component_name="left-pad",
        component_version="1.2.0",
    )
    db.add_all([proj, sbom, component, run, finding])
    db.commit()

    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={
                "summary": "x",
                "fix_versions": [
                    {
                        "ecosystem": "npm",
                        "package": "left-pad",
                        "fixed_in": "1.3.1",
                        "introduced_in": "0.0.1",
                        "range": None,
                    }
                ],
                "references": [],
            },
        ),
    )
    svc = _service(db, osv=osv)
    out = await svc.get_with_scan_context("CVE-2024-12345", scan_id=1)
    assert out.component is not None
    assert out.component.name == "left-pad"
    assert out.component.ecosystem == "npm"
    assert out.current_version_status == "vulnerable"
    assert out.recommended_upgrade == "1.3.1"


@pytest.mark.asyncio
async def test_get_with_scan_context_status_fixed_when_already_above(db):
    proj = Projects(id=1, project_name="p", project_status=1)
    sbom = SBOMSource(id=1, sbom_name="s", projectid=1)
    component = SBOMComponent(id=1, sbom_id=1, name="left-pad", version="2.0.0", purl="pkg:npm/left-pad@2.0.0")
    run = AnalysisRun(
        id=1,
        sbom_id=1,
        project_id=1,
        run_status="OK",
        source="OSV",
        started_on="2024-01-01",
        completed_on="2024-01-01",
    )
    finding = AnalysisFinding(
        id=1,
        analysis_run_id=1,
        component_id=1,
        vuln_id="CVE-2024-12345",
        severity="LOW",
        component_name="left-pad",
        component_version="2.0.0",
    )
    db.add_all([proj, sbom, component, run, finding])
    db.commit()

    osv = _FakeSource(
        "osv",
        FetchResult(
            source="osv",
            outcome=FetchOutcome.OK,
            data={
                "summary": "x",
                "fix_versions": [
                    {"ecosystem": "npm", "package": "left-pad", "fixed_in": "1.3.1", "introduced_in": None, "range": None}
                ],
                "references": [],
            },
        ),
    )
    svc = _service(db, osv=osv)
    out = await svc.get_with_scan_context("CVE-2024-12345", scan_id=1)
    assert out.current_version_status == "fixed"
    assert out.recommended_upgrade is None


@pytest.mark.asyncio
async def test_get_with_scan_context_unknown_when_no_fix_data(db):
    proj = Projects(id=1, project_name="p", project_status=1)
    sbom = SBOMSource(id=1, sbom_name="s", projectid=1)
    run = AnalysisRun(
        id=1,
        sbom_id=1,
        project_id=1,
        run_status="OK",
        source="OSV",
        started_on="2024-01-01",
        completed_on="2024-01-01",
    )
    finding = AnalysisFinding(
        id=1,
        analysis_run_id=1,
        vuln_id="CVE-2024-12345",
        component_name="left-pad",
        component_version="1.2.0",
    )
    db.add_all([proj, sbom, run, finding])
    db.commit()

    svc = _service(db)
    out = await svc.get_with_scan_context("CVE-2024-12345", scan_id=1)
    assert out.current_version_status == "unknown"
    assert out.recommended_upgrade is None


# ----------------------------------------------------------- get_many


@pytest.mark.asyncio
async def test_get_many_dedupes_and_caches(db):
    counter = {"calls": 0}

    class _Counting:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            counter["calls"] += 1
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={"summary": cve_id, "fix_versions": [], "references": []},
            )

    svc = _service(db, osv=_Counting())  # type: ignore[arg-type]
    out = await svc.get_many(["CVE-2024-1111", "cve-2024-2222", "CVE-2024-1111"])
    assert set(out.keys()) == {"CVE-2024-1111", "CVE-2024-2222"}
    # First call: 2 unique IDs → 2 fetches.
    assert counter["calls"] == 2
    # Second batch: cached.
    out2 = await svc.get_many(["CVE-2024-1111", "CVE-2024-2222"])
    assert counter["calls"] == 2
    assert set(out2.keys()) == {"CVE-2024-1111", "CVE-2024-2222"}


# ------------------------------------------------------ GHSA-input second pass


@pytest.mark.asyncio
async def test_ghsa_input_resolves_cve_alias_and_fetches_kev(db):
    """GHSA-formatted input → first pass returns OSV with a CVE alias →
    second pass fetches KEV for that CVE → KEV signal lands in the merged
    payload. This is the ``GHSA-X2FM-93WW-GGVX`` regression that motivated
    Phase 5.1."""
    osv_calls: list[str] = []
    kev_calls: list[str] = []

    class _Osv:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            osv_calls.append(cve_id)
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={
                    "summary": "x",
                    "aliases": ["CVE-2024-44444", "GHSA-X2FM-93WW-GGVX"],
                    "fix_versions": [],
                    "references": [],
                },
            )

    class _Kev:
        name = "kev"
        accepted_kinds = _KINDS_BY_SOURCE["kev"]

        async def fetch(self, cve_id: str) -> FetchResult:
            kev_calls.append(cve_id)
            return FetchResult(
                source="kev",
                outcome=FetchOutcome.OK,
                data={"listed": True, "due_date": "2024-02-15"},
            )

    svc = _service(db, osv=_Osv(), kev=_Kev())  # type: ignore[arg-type]
    detail = await svc.get("GHSA-X2FM-93WW-GGVX")

    # The orchestrator filters sources by ``accepted_kinds`` BEFORE fan-out:
    # OSV accepts GHSA so it's called once with the canonical GHSA id; KEV
    # only accepts CVE so it's deferred to the alias-resolution pass and
    # called exactly once with the resolved CVE.
    assert osv_calls == ["GHSA-x2fm-93ww-ggvx"]
    assert kev_calls == ["CVE-2024-44444"]

    # The KEV second-pass result is the one that lands in the merged payload.
    assert detail.exploitation.cisa_kev_listed is True
    assert "kev" in detail.sources_used


@pytest.mark.asyncio
async def test_ghsa_input_without_cve_alias_skips_second_pass(db):
    """If OSV / GHSA never surface a CVE alias (rare but possible for
    pre-CVE-assignment GHSA records), no second pass is fired and the
    CVE-only sources stay at NOT_FOUND."""
    kev_calls: list[str] = []

    class _Osv:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={"summary": "x", "aliases": [], "fix_versions": [], "references": []},
            )

    class _Kev:
        name = "kev"
        accepted_kinds = _KINDS_BY_SOURCE["kev"]

        async def fetch(self, cve_id: str) -> FetchResult:
            kev_calls.append(cve_id)
            return FetchResult(source="kev", outcome=FetchOutcome.NOT_FOUND)

    svc = _service(db, osv=_Osv(), kev=_Kev())  # type: ignore[arg-type]
    detail = await svc.get("GHSA-X2FM-93WW-GGVX")

    # KEV is filtered out of the first pass (accepts only CVE) and the
    # alias-resolution pass never fires because OSV returned no aliases.
    # Net effect: KEV is never called.
    assert kev_calls == []
    assert detail.exploitation.cisa_kev_listed is False
