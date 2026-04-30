"""
Phase-4 targeted regression tests — the four scenarios from the spec's §4
that, if they had existed, would have prevented the screenshot bug
(``GHSA-JFH8-C2JP-5V3Q`` → "Couldn't reach the CVE database").

  1. Service accepts a GHSA id and returns ``status == ok`` with at least
     OSV in ``sources_used``, plus a CVE alias.
  2. Aggregator fires the alias-resolution pass: NVD/EPSS/KEV are called
     with the resolved CVE when OSV returned one.
  3. Aggregator does NOT call NVD with a GHSA — when OSV returns no CVE
     alias, NVD's call count stays at zero.
  4. Unrecognised ids (``FOOBAR-123``) yield HTTP 400 with the structured
     envelope ``CVE_VAL_E001_UNRECOGNIZED_ID``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.integrations.cve.aggregator import aggregate
from app.integrations.cve.base import FetchOutcome, FetchResult
from app.integrations.cve.identifiers import IdKind, classify
from app.services.cve_service import CveDetailService

_KINDS_BY_SOURCE = {
    "osv": frozenset({IdKind.CVE, IdKind.GHSA, IdKind.PYSEC, IdKind.RUSTSEC, IdKind.GO, IdKind.OSV_GENERIC}),
    "ghsa": frozenset({IdKind.CVE, IdKind.GHSA}),
    "nvd": frozenset({IdKind.CVE}),
    "kev": frozenset({IdKind.CVE}),
    "epss": frozenset({IdKind.CVE}),
}


@pytest.fixture()
def db() -> Session:
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


# --------------------------------------------------------------------------
# 1 — service accepts GHSA id end-to-end with status=ok
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_accepts_ghsa_id(db):
    """End-to-end against an in-process OSV stub for the log4j-core advisory."""

    class _StubOsv:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={
                    "summary": "log4j-core RCE follow-up",
                    "aliases": ["CVE-2021-44832"],
                    "published": "2021-12-28T00:00:00Z",
                    "fix_versions": [
                        {"ecosystem": "Maven", "package": "org.apache.logging.log4j:log4j-core",
                         "fixed_in": "2.17.1", "introduced_in": None, "range": None}
                    ],
                    "references": [],
                },
            )

    class _Down:
        accepted_kinds = _KINDS_BY_SOURCE["ghsa"]

        def __init__(self, name: str) -> None:
            self.name = name
            self.accepted_kinds = _KINDS_BY_SOURCE[name]

        async def fetch(self, cve_id: str) -> FetchResult:
            return FetchResult(source=self.name, outcome=FetchOutcome.NOT_FOUND)

    svc = CveDetailService(
        db,
        osv=_StubOsv(),  # type: ignore[arg-type]
        ghsa=_Down("ghsa"),  # type: ignore[arg-type]
        nvd=_Down("nvd"),  # type: ignore[arg-type]
        kev=_Down("kev"),  # type: ignore[arg-type]
        epss=_Down("epss"),  # type: ignore[arg-type]
    )
    detail = await svc.get("GHSA-jfh8-c2jp-5v3q")

    assert detail.status.value == "ok"
    assert "osv" in detail.sources_used
    assert "CVE-2021-44832" in detail.aliases
    assert detail.cve_id == "GHSA-jfh8-c2jp-5v3q"  # primary id stays as user clicked


# --------------------------------------------------------------------------
# 2 — aggregator alias resolution: NVD/EPSS/KEV called with resolved CVE
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregator_alias_resolution():
    nvd_calls: list[str] = []
    epss_calls: list[str] = []
    kev_calls: list[str] = []

    class _Osv:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={
                    "summary": "x",
                    "aliases": ["CVE-2021-44832"],
                    "fix_versions": [],
                    "references": [],
                },
            )

    def _cve_only(name: str, calls: list[str]):
        class _Src:
            pass

        _Src.name = name
        _Src.accepted_kinds = _KINDS_BY_SOURCE[name]

        async def fetch(self, cve_id: str) -> FetchResult:
            calls.append(cve_id)
            return FetchResult(source=name, outcome=FetchOutcome.OK, data={"score": 0.5} if name == "epss" else {"listed": True})

        _Src.fetch = fetch
        return _Src()

    sources = [_Osv(), _cve_only("nvd", nvd_calls), _cve_only("epss", epss_calls), _cve_only("kev", kev_calls)]
    detail = await aggregate(classify("GHSA-jfh8-c2jp-5v3q"), sources)

    # Each CVE-only source was called exactly once, with the resolved CVE.
    assert nvd_calls == ["CVE-2021-44832"]
    assert epss_calls == ["CVE-2021-44832"]
    assert kev_calls == ["CVE-2021-44832"]
    # All four sources contributed to the result.
    assert set(detail.sources_used) == {"osv", "nvd", "epss", "kev"}


# --------------------------------------------------------------------------
# 3 — aggregator does NOT call NVD with a GHSA when no CVE alias is found
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregator_does_not_call_nvd_with_ghsa():
    nvd_calls: list[str] = []

    class _Osv:
        name = "osv"
        accepted_kinds = _KINDS_BY_SOURCE["osv"]

        async def fetch(self, cve_id: str) -> FetchResult:
            return FetchResult(
                source="osv",
                outcome=FetchOutcome.OK,
                data={"summary": "x", "aliases": [], "fix_versions": [], "references": []},
            )

    class _Nvd:
        name = "nvd"
        accepted_kinds = _KINDS_BY_SOURCE["nvd"]

        async def fetch(self, cve_id: str) -> FetchResult:
            nvd_calls.append(cve_id)
            return FetchResult(source="nvd", outcome=FetchOutcome.NOT_FOUND)

    detail = await aggregate(classify("GHSA-jfh8-c2jp-5v3q"), [_Osv(), _Nvd()])

    # Critical assertion: NVD was never invoked with a non-CVE id.
    assert nvd_calls == []
    # NVD shows up in the per-source bookkeeping as DISABLED — never tried.
    assert "nvd" not in detail.sources_used


# --------------------------------------------------------------------------
# 4 — API-level: unrecognized id → 400 with the structured envelope
# --------------------------------------------------------------------------


def test_unrecognized_id_returns_400(client):
    resp = client.get("/api/v1/cves/FOOBAR-123")
    assert resp.status_code == 400, resp.text

    body = resp.json()
    detail = body["detail"]
    assert detail["error_code"] == "CVE_VAL_E001_UNRECOGNIZED_ID"
    assert detail["raw_id"] == "FOOBAR-123"
    assert detail["retryable"] is False
    # supported_formats is the user-facing list — must include CVE + GHSA at minimum.
    fmts = detail["supported_formats"]
    assert any("CVE" in f for f in fmts)
    assert any("GHSA" in f for f in fmts)
