"""Phase 2.3 — domain dataclass invariants."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.nvd_mirror.domain.models import (
    CpeCriterion,
    CveBatch,
    CveRecord,
    MirrorWatermark,
    MirrorWindow,
    NvdSettingsSnapshot,
    SyncReport,
    utc_now,
)


UTC = timezone.utc
T0 = datetime(2024, 1, 1, tzinfo=UTC)
T1 = datetime(2024, 4, 1, tzinfo=UTC)


def _record(cve_id: str = "CVE-2024-0001") -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        last_modified=T1,
        published=T0,
        vuln_status="Analyzed",
        description_en="example",
        score_v40=None,
        score_v31=9.8,
        score_v2=None,
        severity_text="CRITICAL",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        aliases=("GHSA-xxxx-yyyy-zzzz",),
        cpe_criteria=(
            CpeCriterion(
                criteria="cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
                criteria_stem="apache:log4j",
                vulnerable=True,
            ),
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-0001",),
        raw={"id": cve_id},
    )


# --- MirrorWindow ---------------------------------------------------------


def test_mirror_window_accepts_valid_119_day_span() -> None:
    end = T0 + timedelta(days=119)
    w = MirrorWindow(start=T0, end=end)
    assert w.end - w.start == timedelta(days=119)


def test_mirror_window_rejects_120_day_span() -> None:
    end = T0 + timedelta(days=120)
    with pytest.raises(ValueError, match="exceeds NVD ceiling"):
        MirrorWindow(start=T0, end=end)


def test_mirror_window_rejects_naive_datetime() -> None:
    naive = datetime(2024, 1, 1)
    with pytest.raises(ValueError, match="tz-aware UTC"):
        MirrorWindow(start=naive, end=T1)


def test_mirror_window_rejects_non_utc_tz() -> None:
    eastern = timezone(timedelta(hours=-5))
    with pytest.raises(ValueError, match="UTC"):
        MirrorWindow(start=datetime(2024, 1, 1, tzinfo=eastern), end=T1)


def test_mirror_window_rejects_zero_or_negative_span() -> None:
    with pytest.raises(ValueError, match="must be > start"):
        MirrorWindow(start=T0, end=T0)
    with pytest.raises(ValueError, match="must be > start"):
        MirrorWindow(start=T1, end=T0)


# --- CveRecord ------------------------------------------------------------


def test_cve_record_requires_cve_id() -> None:
    with pytest.raises(ValueError, match="cve_id must be non-empty"):
        CveRecord(
            cve_id="",
            last_modified=T1,
            published=T0,
            vuln_status="Analyzed",
            description_en=None,
            score_v40=None,
            score_v31=None,
            score_v2=None,
            severity_text=None,
            vector_string=None,
            aliases=(),
            cpe_criteria=(),
            references=(),
            raw={},
        )


def test_cve_record_rejects_naive_last_modified() -> None:
    with pytest.raises(ValueError, match="last_modified must be tz-aware UTC"):
        CveRecord(
            cve_id="CVE-2024-0001",
            last_modified=datetime(2024, 1, 1),
            published=T0,
            vuln_status="Analyzed",
            description_en=None,
            score_v40=None,
            score_v31=None,
            score_v2=None,
            severity_text=None,
            vector_string=None,
            aliases=(),
            cpe_criteria=(),
            references=(),
            raw={},
        )


def test_cve_record_is_frozen() -> None:
    r = _record()
    with pytest.raises((AttributeError, Exception)):
        r.cve_id = "CVE-9999-0000"  # type: ignore[misc]


# --- MirrorWatermark / NvdSettingsSnapshot / SyncReport -------------------


def test_watermark_accepts_none() -> None:
    w = MirrorWatermark(last_modified_utc=None, last_sync_run_id=None)
    assert w.last_modified_utc is None


def test_watermark_rejects_naive_value() -> None:
    with pytest.raises(ValueError):
        MirrorWatermark(
            last_modified_utc=datetime(2024, 1, 1), last_sync_run_id=42
        )


def test_settings_snapshot_round_trip_fields() -> None:
    snap = NvdSettingsSnapshot(
        enabled=True,
        api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key_plaintext="secret",
        download_feeds_enabled=False,
        page_size=2000,
        window_days=119,
        min_freshness_hours=24,
        last_modified_utc=T1,
        last_successful_sync_at=T1,
        updated_at=T1,
    )
    assert snap.api_key_plaintext == "secret"


def test_sync_report_carries_errors_and_watermark() -> None:
    sr = SyncReport(
        run_kind="bootstrap",
        started_at=T0,
        finished_at=T1,
        windows_completed=2,
        upserts=10,
        rejected_marked=1,
        errors=("oops",),
        final_watermark=T1,
    )
    assert sr.errors == ("oops",)


# --- utc_now --------------------------------------------------------------


def test_utc_now_is_tz_aware() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


# --- CveBatch --------------------------------------------------------------


def test_cve_batch_holds_records_and_paging() -> None:
    b = CveBatch(records=(_record(),), start_index=0, results_per_page=2000, total_results=1)
    assert b.total_results == 1
    assert len(b.records) == 1
