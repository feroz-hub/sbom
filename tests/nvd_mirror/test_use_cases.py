"""Phase 3.3/3.4 — BootstrapMirror, IncrementalMirror, QueryMirror tests.

All tests use in-memory fakes (see ``_fakes.py``); none touch the real DB
or the live NVD API. Resumability and error-handling are exercised by
configuring the fake remote to raise on a chosen call.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.nvd_mirror.application import (
    BootstrapMirror,
    IncrementalMirror,
    QueryMirror,
    compute_freshness,
)
from app.nvd_mirror.application._window_walker import HISTORICAL_FLOOR
from app.nvd_mirror.domain.models import CpeCriterion, MirrorWindow

from ._fakes import (
    FakeCveRepository,
    FakeNvdRemote,
    FakeSettingsRepository,
    FakeSyncRunRepository,
    FixedClock,
    batch,
    make_record,
    make_snapshot,
)


UTC = timezone.utc


# Minimal commit no-op since the fakes are in-memory.
def _no_commit() -> None:
    return None


# --- compute_freshness ----------------------------------------------------


def test_freshness_is_false_when_never_synced() -> None:
    snap = make_snapshot(last_successful_sync_at=None)
    v = compute_freshness(snap, datetime(2024, 6, 1, tzinfo=UTC))
    assert v.is_fresh is False
    assert v.age_hours is None


def test_freshness_is_true_when_inside_window() -> None:
    last = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
    snap = make_snapshot(
        min_freshness_hours=24, last_successful_sync_at=last
    )
    v = compute_freshness(snap, last + timedelta(hours=23))
    assert v.is_fresh is True
    assert v.age_hours is not None and v.age_hours == pytest.approx(23.0)


def test_freshness_is_false_when_outside_window() -> None:
    last = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
    snap = make_snapshot(
        min_freshness_hours=24, last_successful_sync_at=last
    )
    v = compute_freshness(snap, last + timedelta(hours=25))
    assert v.is_fresh is False
    assert v.age_hours == pytest.approx(25.0)


# --- BootstrapMirror ------------------------------------------------------


@pytest.mark.asyncio
async def test_bootstrap_no_op_when_already_caught_up() -> None:
    """Bootstrap with watermark == target does nothing."""
    target = datetime(2024, 6, 1, tzinfo=UTC)
    snap = make_snapshot(window_days=30, last_modified_utc=target)
    remote = FakeNvdRemote()
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.windows_completed == 0
    assert report.upserts == 0
    assert remote.call_count == 0


@pytest.mark.asyncio
async def test_bootstrap_walks_windows_from_floor_when_no_watermark() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    rec = make_record("CVE-1", last_modified=target - timedelta(days=1))
    remote = FakeNvdRemote(
        {(HISTORICAL_FLOOR, target): [batch([rec])]}
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.windows_completed == 1
    assert report.upserts == 1
    assert cve_repo.find_by_cve_id("CVE-1") is not None
    assert settings_repo.load().last_modified_utc == target


@pytest.mark.asyncio
async def test_bootstrap_walks_multiple_windows() -> None:
    """Span > window_days produces multiple sequential windows."""
    target = HISTORICAL_FLOOR + timedelta(days=70)  # 3 windows of 30 days
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    w1 = (HISTORICAL_FLOOR, HISTORICAL_FLOOR + timedelta(days=30))
    w2 = (HISTORICAL_FLOOR + timedelta(days=30), HISTORICAL_FLOOR + timedelta(days=60))
    w3 = (HISTORICAL_FLOOR + timedelta(days=60), target)

    rec1 = make_record("CVE-1", last_modified=w1[1] - timedelta(seconds=1))
    rec2 = make_record("CVE-2", last_modified=w2[1] - timedelta(seconds=1))
    rec3 = make_record("CVE-3", last_modified=w3[1] - timedelta(seconds=1))

    remote = FakeNvdRemote(
        {w1: [batch([rec1])], w2: [batch([rec2])], w3: [batch([rec3])]}
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.windows_completed == 3
    assert report.upserts == 3
    assert {cid for cid in cve_repo.rows} == {"CVE-1", "CVE-2", "CVE-3"}
    assert len(sync_run_repo.runs) == 3
    assert all(r["status"] == "success" for r in sync_run_repo.runs)


@pytest.mark.asyncio
async def test_bootstrap_resumes_from_existing_watermark() -> None:
    """A prior run set a watermark — bootstrap must NOT restart at the floor."""
    target = HISTORICAL_FLOOR + timedelta(days=70)
    waterline = HISTORICAL_FLOOR + timedelta(days=30)
    snap = make_snapshot(window_days=30, last_modified_utc=waterline)

    w2 = (waterline, waterline + timedelta(days=30))
    w3 = (waterline + timedelta(days=30), target)

    remote = FakeNvdRemote(
        {
            w2: [batch([make_record("CVE-2", last_modified=w2[1] - timedelta(seconds=1))])],
            w3: [batch([make_record("CVE-3", last_modified=w3[1] - timedelta(seconds=1))])],
        }
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.windows_completed == 2
    # Critically: the floor-to-waterline window must NOT have been called.
    starts = [w.start for w in remote.calls]
    assert HISTORICAL_FLOOR not in starts
    assert waterline in starts


@pytest.mark.asyncio
async def test_bootstrap_records_sync_run_failure_and_stops() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=70)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    w1 = (HISTORICAL_FLOOR, HISTORICAL_FLOOR + timedelta(days=30))
    rec1 = make_record("CVE-1", last_modified=w1[1] - timedelta(seconds=1))
    remote = FakeNvdRemote(
        {w1: [batch([rec1])]},
        raise_on_nth_call=2,  # 2nd window fails
        raise_exc=RuntimeError("network down"),
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.windows_completed == 1
    assert report.errors  # non-empty
    assert any("network down" in e for e in report.errors)
    # The first window's run is success; the second is failed.
    statuses = [r["status"] for r in sync_run_repo.runs]
    assert statuses == ["success", "failed"]
    # The watermark advanced ONLY for the successful first window.
    assert settings_repo.load().last_modified_utc == w1[1]


@pytest.mark.asyncio
async def test_bootstrap_resumes_idempotently_after_failure() -> None:
    """Failure in window 2 → next run continues from watermark = end-of-window-1."""
    target = HISTORICAL_FLOOR + timedelta(days=70)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    w1 = (HISTORICAL_FLOOR, HISTORICAL_FLOOR + timedelta(days=30))
    w2 = (HISTORICAL_FLOOR + timedelta(days=30), HISTORICAL_FLOOR + timedelta(days=60))
    w3 = (HISTORICAL_FLOOR + timedelta(days=60), target)

    rec1 = make_record("CVE-1", last_modified=w1[1] - timedelta(seconds=1))
    rec2 = make_record("CVE-2", last_modified=w2[1] - timedelta(seconds=1))
    rec3 = make_record("CVE-3", last_modified=w3[1] - timedelta(seconds=1))

    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    # First attempt: fails on window 2.
    failing_remote = FakeNvdRemote(
        {w1: [batch([rec1])], w2: [batch([rec2])], w3: [batch([rec3])]},
        raise_on_nth_call=2,
        raise_exc=RuntimeError("transient"),
    )
    await BootstrapMirror(
        remote=failing_remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    assert cve_repo.find_by_cve_id("CVE-1") is not None
    assert cve_repo.find_by_cve_id("CVE-2") is None
    assert cve_repo.find_by_cve_id("CVE-3") is None

    # Second attempt: clean remote, resume from watermark.
    healthy_remote = FakeNvdRemote(
        {w2: [batch([rec2])], w3: [batch([rec3])]}
    )
    report = await BootstrapMirror(
        remote=healthy_remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    assert report.windows_completed == 2
    assert {c for c in cve_repo.rows} == {"CVE-1", "CVE-2", "CVE-3"}
    starts = [w.start for w in healthy_remote.calls]
    assert HISTORICAL_FLOOR not in starts  # didn't restart from floor


@pytest.mark.asyncio
async def test_bootstrap_soft_marks_rejected_cves() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    rejected = make_record(
        "CVE-REJ", last_modified=target - timedelta(seconds=1), vuln_status="Rejected"
    )
    good = make_record(
        "CVE-GOOD", last_modified=target - timedelta(seconds=2), vuln_status="Analyzed"
    )
    remote = FakeNvdRemote(
        {(HISTORICAL_FLOOR, target): [batch([good, rejected])]}
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    report = await BootstrapMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    # A freshly-inserted record that's already 'Rejected' was upserted
    # as such — no separate state transition counted, but soft_mark
    # was still called (defence-in-depth for state transitions on replay).
    assert cve_repo.soft_mark_calls >= 1
    assert cve_repo.rows["CVE-REJ"].vuln_status == "Rejected"
    assert cve_repo.rows["CVE-GOOD"].vuln_status == "Analyzed"
    # The walker reports rejected_marked = state transitions only.
    assert report.rejected_marked == 0


@pytest.mark.asyncio
async def test_replay_with_newer_rejected_status_overwrites_via_upsert() -> None:
    """A newer Rejected record overwrites an older Analyzed one through upsert_batch."""
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    pass1 = make_record(
        "CVE-X", last_modified=target - timedelta(days=2), vuln_status="Analyzed"
    )
    pass2 = make_record(
        "CVE-X", last_modified=target - timedelta(days=1), vuln_status="Rejected"
    )
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    await BootstrapMirror(
        remote=FakeNvdRemote({(HISTORICAL_FLOOR, target): [batch([pass1])]}),
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    assert cve_repo.rows["CVE-X"].vuln_status == "Analyzed"

    # Reset watermark so we re-run the same window with the newer record.
    settings_repo.advance_watermark(
        last_modified_utc=HISTORICAL_FLOOR,
        last_successful_sync_at=target,
    )
    await BootstrapMirror(
        remote=FakeNvdRemote({(HISTORICAL_FLOOR, target): [batch([pass2])]}),
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    # Status flipped via upsert_batch (newer last_modified wins).
    assert cve_repo.rows["CVE-X"].vuln_status == "Rejected"


# --- Out-of-order modifications ------------------------------------------


@pytest.mark.asyncio
async def test_out_of_order_modifications_do_not_overwrite_fresher_row() -> None:
    """Repeating a window with an OLDER record must NOT clobber the fresher one."""
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)

    fresh = make_record(
        "CVE-A", last_modified=target - timedelta(days=1), vuln_status="Analyzed"
    )
    stale = make_record(
        "CVE-A", last_modified=target - timedelta(days=10), vuln_status="Modified"
    )

    cve_repo = FakeCveRepository()
    cve_repo.upsert_batch([fresh])  # write fresh first

    # Now write stale; idempotency contract drops it.
    n = cve_repo.upsert_batch([stale])
    assert n == 0
    assert cve_repo.rows["CVE-A"].vuln_status == "Analyzed"


# --- IncrementalMirror ----------------------------------------------------


@pytest.mark.asyncio
async def test_incremental_delegates_to_bootstrap_when_no_watermark() -> None:
    target = HISTORICAL_FLOOR + timedelta(days=15)
    snap = make_snapshot(window_days=30, last_modified_utc=None)
    rec = make_record("CVE-1", last_modified=target - timedelta(seconds=1))

    remote = FakeNvdRemote({(HISTORICAL_FLOOR, target): [batch([rec])]})
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = IncrementalMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    # Reported as bootstrap because that's what was actually run.
    assert report.run_kind == "bootstrap"
    assert report.windows_completed == 1


@pytest.mark.asyncio
async def test_incremental_walks_only_delta_when_watermark_present() -> None:
    target = datetime(2024, 6, 30, tzinfo=UTC)
    waterline = target - timedelta(days=10)
    snap = make_snapshot(window_days=30, last_modified_utc=waterline)
    rec = make_record("CVE-NEW", last_modified=target - timedelta(seconds=1))

    remote = FakeNvdRemote({(waterline, target): [batch([rec])]})
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    uc = IncrementalMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    )
    report = await uc.execute(now=target)
    assert report.run_kind == "incremental"
    assert report.windows_completed == 1
    assert remote.calls[0].start == waterline


@pytest.mark.asyncio
async def test_incremental_no_op_when_watermark_at_target() -> None:
    target = datetime(2024, 6, 30, tzinfo=UTC)
    snap = make_snapshot(window_days=30, last_modified_utc=target)
    remote = FakeNvdRemote()
    cve_repo = FakeCveRepository()
    settings_repo = FakeSettingsRepository(snap)
    sync_run_repo = FakeSyncRunRepository()

    report = await IncrementalMirror(
        remote=remote,
        cve_repo=cve_repo,
        settings_repo=settings_repo,
        sync_run_repo=sync_run_repo,
        clock=FixedClock(target),
        commit=_no_commit,
    ).execute(now=target)
    assert report.windows_completed == 0
    assert remote.call_count == 0


# --- QueryMirror ----------------------------------------------------------


def test_query_returns_records_for_known_cpe() -> None:
    repo = FakeCveRepository()
    crit = CpeCriterion(
        criteria="cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
        criteria_stem="apache:log4j",
        vulnerable=True,
    )
    rec = make_record(
        "CVE-2021-44228", last_modified=datetime(2024, 6, 1, tzinfo=UTC), cpe_criteria=(crit,)
    )
    repo.upsert_batch([rec])
    out = QueryMirror(cve_repo=repo).execute(
        "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
    )
    assert [r.cve_id for r in out] == ["CVE-2021-44228"]


def test_query_empty_input_returns_empty() -> None:
    assert QueryMirror(cve_repo=FakeCveRepository()).execute("") == []


# --- 120-day window enforcement (defense-in-depth) ------------------------


def test_walker_window_construction_enforces_119_day_cap() -> None:
    """Constructing a wider MirrorWindow must raise even via the use case."""
    with pytest.raises(ValueError, match="exceeds NVD ceiling"):
        MirrorWindow(
            start=datetime(2024, 1, 1, tzinfo=UTC),
            end=datetime(2024, 5, 1, tzinfo=UTC),
        )
