"""Phase 5 — NvdLookupService 5-branch decision tests.

Each test wires the port-based facade with in-memory fakes (see
``_fakes.py``). The live callable is a plain Python function that
records its calls — that's enough to assert "live path was used".
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.nvd_mirror.application.facade import NvdLookupService
from app.nvd_mirror.domain.models import CpeCriterion

from ._fakes import (
    FakeCveRepository,
    FakeSettingsRepository,
    FixedClock,
    make_record,
    make_snapshot,
)


UTC = timezone.utc
NOW = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


class _LiveSpy:
    """Records every call and returns a configurable result.

    Matches the signature of ``app.analysis.nvd_query_by_cpe``:
        (cpe23, api_key, settings) -> list[dict]
    """

    def __init__(self, *, returns: list[dict] | None = None) -> None:
        self._returns = returns or []
        self.calls: list[tuple[str, str | None, Any]] = []

    def __call__(self, cpe23: str, api_key: str | None, settings: Any) -> list[dict]:
        self.calls.append((cpe23, api_key, settings))
        return list(self._returns)


def _facade(
    *,
    snapshot,
    cve_repo: FakeCveRepository | None = None,
    live: _LiveSpy | None = None,
    now: datetime = NOW,
) -> tuple[NvdLookupService, _LiveSpy, FakeCveRepository]:
    cve_repo = cve_repo or FakeCveRepository()
    live = live or _LiveSpy()
    fac = NvdLookupService(
        settings_repo=FakeSettingsRepository(snapshot),
        cve_repo=cve_repo,
        clock=FixedClock(now),
        live_query=live,
    )
    return fac, live, cve_repo


# --- Branch 1: mirror disabled → live (no warning) ------------------------


def test_branch1_mirror_disabled_uses_live(caplog: pytest.LogCaptureFixture) -> None:
    snap = make_snapshot(enabled=False)
    fac, live, _ = _facade(snapshot=snap, live=_LiveSpy(returns=[{"id": "CVE-LIVE"}]))

    with caplog.at_level(logging.WARNING, logger="app.nvd_mirror.application.facade"):
        out = fac.query_legacy(
            "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
            api_key="k",
            settings=object(),
        )

    assert out == [{"id": "CVE-LIVE"}]
    assert len(live.calls) == 1
    # No stale/error warnings logged when mirror is just disabled.
    assert "nvd_mirror_stale_falling_back" not in caplog.text
    assert "nvd_mirror_query_failed_falling_back" not in caplog.text


# --- Branch 2: mirror enabled but stale → live + WARNING ------------------


def test_branch2_stale_mirror_uses_live_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=NOW - timedelta(hours=48),
    )
    fac, live, _ = _facade(snapshot=snap, live=_LiveSpy(returns=[{"id": "CVE-LIVE"}]))

    with caplog.at_level(logging.WARNING, logger="app.nvd_mirror.application.facade"):
        out = fac.query_legacy(
            "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
            api_key="k",
            settings=object(),
        )

    assert out == [{"id": "CVE-LIVE"}]
    assert len(live.calls) == 1
    assert "nvd_mirror_stale_falling_back" in caplog.text


def test_branch2_never_synced_treated_as_stale(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``last_successful_sync_at=None`` → freshness=False → live + warning."""
    snap = make_snapshot(enabled=True, last_successful_sync_at=None)
    fac, live, _ = _facade(snapshot=snap, live=_LiveSpy(returns=[]))

    with caplog.at_level(logging.WARNING, logger="app.nvd_mirror.application.facade"):
        fac.query_legacy(
            "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
            api_key=None,
            settings=object(),
        )

    assert len(live.calls) == 1
    assert "nvd_mirror_stale_falling_back" in caplog.text


# --- Branch 3: mirror enabled + fresh + hit → mirror ----------------------


def test_branch3_fresh_mirror_with_hit_returns_mirror_data(
    caplog: pytest.LogCaptureFixture,
) -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=NOW - timedelta(hours=1),
    )
    cve_repo = FakeCveRepository()
    cpe = "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
    crit = CpeCriterion(criteria=cpe, criteria_stem="apache:log4j", vulnerable=True)
    raw = {
        "id": "CVE-2021-44228",
        "lastModified": "2024-04-16T01:23:45.000",
    }
    cve_repo.upsert_batch(
        [
            make_record(
                "CVE-2021-44228",
                last_modified=NOW - timedelta(days=1),
                cpe_criteria=(crit,),
            ).__class__(  # rebuild with raw set
                cve_id="CVE-2021-44228",
                last_modified=NOW - timedelta(days=1),
                published=NOW - timedelta(days=10),
                vuln_status="Analyzed",
                description_en=None,
                score_v40=None,
                score_v31=None,
                score_v2=None,
                severity_text=None,
                vector_string=None,
                aliases=(),
                cpe_criteria=(crit,),
                references=(),
                raw=raw,
            )
        ]
    )

    fac, live, _ = _facade(snapshot=snap, cve_repo=cve_repo)

    with caplog.at_level(logging.WARNING, logger="app.nvd_mirror.application.facade"):
        out = fac.query_legacy(cpe, api_key="k", settings=object())

    # Mirror served the data — live was NOT called.
    assert out == [raw]
    assert live.calls == []
    # No warnings/errors.
    assert "nvd_mirror_stale_falling_back" not in caplog.text
    assert "nvd_mirror_query_failed_falling_back" not in caplog.text


# --- Branch 4: mirror enabled + fresh + no hit → live (double-check) ------


def test_branch4_fresh_mirror_with_empty_result_falls_back_to_live(
    caplog: pytest.LogCaptureFixture,
) -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=NOW - timedelta(hours=1),
    )
    fac, live, _ = _facade(
        snapshot=snap,
        cve_repo=FakeCveRepository(),  # empty
        live=_LiveSpy(returns=[{"id": "CVE-LIVE-DOUBLECHECK"}]),
    )

    with caplog.at_level(logging.INFO, logger="app.nvd_mirror.application.facade"):
        out = fac.query_legacy(
            "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
            api_key="k",
            settings=object(),
        )

    assert out == [{"id": "CVE-LIVE-DOUBLECHECK"}]
    assert len(live.calls) == 1
    assert "nvd_mirror_empty_double_checking_live" in caplog.text


# --- Branch 5: mirror raises → live + ERROR + circuit hint ----------------


class _ExplodingRepo:
    """Always raises on find_by_cpe."""

    def upsert_batch(self, records):
        return 0

    def find_by_cve_id(self, cve_id):
        return None

    def find_by_cpe(self, cpe23):
        raise RuntimeError("DB exploded")

    def soft_mark_rejected(self, cve_ids):
        return 0


def test_branch5_mirror_raises_falls_back_to_live_with_error_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=NOW - timedelta(hours=1),
    )
    live = _LiveSpy(returns=[{"id": "CVE-LIVE-FALLBACK"}])
    fac = NvdLookupService(
        settings_repo=FakeSettingsRepository(snap),
        cve_repo=_ExplodingRepo(),  # type: ignore[arg-type]
        clock=FixedClock(NOW),
        live_query=live,
    )

    with caplog.at_level(logging.ERROR, logger="app.nvd_mirror.application.facade"):
        out = fac.query_legacy(
            "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
            api_key="k",
            settings=object(),
        )

    assert out == [{"id": "CVE-LIVE-FALLBACK"}]
    assert len(live.calls) == 1
    assert "nvd_mirror_query_failed_falling_back" in caplog.text
    # The "circuit hint" lives on extra={"hint": ...}; caplog.text shows
    # only the message string, so inspect the record directly.
    error_records = [
        r for r in caplog.records if r.message == "nvd_mirror_query_failed_falling_back"
    ]
    assert error_records, "expected an error record for the failed mirror query"
    assert "consider disabling mirror" in getattr(error_records[0], "hint", "")


# --- Argument plumbing ---------------------------------------------------


def test_live_call_receives_original_cpe_api_key_and_settings() -> None:
    """When falling back, all three args must be passed through unchanged."""
    snap = make_snapshot(enabled=False)
    live = _LiveSpy()
    fac, _, _ = _facade(snapshot=snap, live=live)

    sentinel_settings = object()
    fac.query_legacy(
        "cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*",
        api_key="my-key",
        settings=sentinel_settings,
    )
    cpe, api_key, settings = live.calls[0]
    assert cpe == "cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*"
    assert api_key == "my-key"
    assert settings is sentinel_settings


def test_mirror_data_returns_raw_dicts_not_records() -> None:
    """The facade output must be plain dicts so _finding_from_raw works."""
    snap = make_snapshot(
        enabled=True,
        min_freshness_hours=24,
        last_successful_sync_at=NOW - timedelta(hours=1),
    )
    cpe = "cpe:2.3:a:x:y:1.0.0:*:*:*:*:*:*:*"
    crit = CpeCriterion(criteria=cpe, criteria_stem="x:y", vulnerable=True)
    cve_repo = FakeCveRepository()
    raw = {"id": "CVE-X", "lastModified": "2024-04-15T00:00:00.000", "marker": "yes"}

    from app.nvd_mirror.domain.models import CveRecord as _R

    cve_repo.upsert_batch(
        [
            _R(
                cve_id="CVE-X",
                last_modified=NOW - timedelta(hours=2),
                published=NOW - timedelta(days=1),
                vuln_status="Analyzed",
                description_en=None,
                score_v40=None,
                score_v31=None,
                score_v2=None,
                severity_text=None,
                vector_string=None,
                aliases=(),
                cpe_criteria=(crit,),
                references=(),
                raw=raw,
            )
        ]
    )

    fac, _, _ = _facade(snapshot=snap, cve_repo=cve_repo)
    out = fac.query_legacy(cpe, api_key=None, settings=object())
    assert out == [raw]
    assert isinstance(out[0], dict)
