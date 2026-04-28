"""In-memory fakes for the NVD-mirror ports.

Reused across use-case tests. Each fake satisfies its Protocol
structurally (no inheritance) — ``test_satisfies_secrets_port_protocol``
in ``test_secrets_fernet.py`` shows the structural-typing convention.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Iterable

from app.nvd_mirror.domain.models import (
    CveBatch,
    CveRecord,
    MirrorWindow,
    NvdSettingsSnapshot,
)


# ---------------- Clock ----------------------------------------------------


class FixedClock:
    """Returns a fixed time, optionally advancing on each call."""

    def __init__(self, now: datetime, *, advance: timedelta | None = None) -> None:
        self._now = now
        self._advance = advance

    def now(self) -> datetime:
        result = self._now
        if self._advance:
            self._now = self._now + self._advance
        return result


# ---------------- NvdRemote ------------------------------------------------


class FakeNvdRemote:
    """Returns canned batches per (window_start, window_end) tuple.

    If a window isn't in the dict, yields empty.
    Optionally raises a configured exception on the Nth fetch_window call
    to simulate transient failures.
    """

    def __init__(
        self,
        windows: Mapping[tuple[datetime, datetime], list[CveBatch]] | None = None,
        *,
        raise_on_nth_call: int | None = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self._windows = dict(windows or {})
        self._raise_on_nth_call = raise_on_nth_call
        self._raise_exc = raise_exc or RuntimeError("simulated remote failure")
        self.call_count = 0
        self.calls: list[MirrorWindow] = []

    async def fetch_window(
        self, window: MirrorWindow, *, page_size: int  # noqa: ARG002
    ) -> AsyncIterator[CveBatch]:
        self.call_count += 1
        self.calls.append(window)
        if (
            self._raise_on_nth_call is not None
            and self.call_count == self._raise_on_nth_call
        ):
            raise self._raise_exc
        batches = self._windows.get((window.start, window.end), [])
        for b in batches:
            yield b


# ---------------- CveRepository --------------------------------------------


class FakeCveRepository:
    """In-memory dict keyed by cve_id with the same idempotency contract as PG."""

    def __init__(self) -> None:
        self.rows: dict[str, CveRecord] = {}
        self.upsert_calls = 0
        self.soft_mark_calls = 0

    def upsert_batch(self, records: Sequence[CveRecord]) -> int:
        self.upsert_calls += 1
        n = 0
        for rec in records:
            existing = self.rows.get(rec.cve_id)
            if existing is None or rec.last_modified > existing.last_modified:
                self.rows[rec.cve_id] = rec
                n += 1
        return n

    def find_by_cve_id(self, cve_id: str) -> CveRecord | None:
        return self.rows.get(cve_id)

    def find_by_cpe(self, cpe23: str) -> Sequence[CveRecord]:
        # Simplified: exact-criteria match only for tests.
        out: list[CveRecord] = []
        for r in self.rows.values():
            if r.vuln_status == "Rejected":
                continue
            for c in r.cpe_criteria:
                if c.criteria == cpe23:
                    out.append(r)
                    break
        return out

    def soft_mark_rejected(self, cve_ids: Sequence[str]) -> int:
        self.soft_mark_calls += 1
        n = 0
        for cid in cve_ids:
            existing = self.rows.get(cid)
            if existing is not None and existing.vuln_status != "Rejected":
                self.rows[cid] = _replace_status(existing, "Rejected")
                n += 1
        return n


def _replace_status(record: CveRecord, status: str) -> CveRecord:
    return CveRecord(
        cve_id=record.cve_id,
        last_modified=record.last_modified,
        published=record.published,
        vuln_status=status,
        description_en=record.description_en,
        score_v40=record.score_v40,
        score_v31=record.score_v31,
        score_v2=record.score_v2,
        severity_text=record.severity_text,
        vector_string=record.vector_string,
        aliases=record.aliases,
        cpe_criteria=record.cpe_criteria,
        references=record.references,
        raw=record.raw,
    )


# ---------------- SettingsRepository --------------------------------------


class FakeSettingsRepository:
    """Holds a single mutable snapshot."""

    def __init__(self, snapshot: NvdSettingsSnapshot) -> None:
        self._snapshot = snapshot

    def load(self) -> NvdSettingsSnapshot:
        return self._snapshot

    def save(self, snapshot: NvdSettingsSnapshot) -> NvdSettingsSnapshot:
        self._snapshot = snapshot
        return snapshot

    def advance_watermark(
        self,
        *,
        last_modified_utc: datetime,
        last_successful_sync_at: datetime,
    ) -> None:
        s = self._snapshot
        self._snapshot = NvdSettingsSnapshot(
            enabled=s.enabled,
            api_endpoint=s.api_endpoint,
            api_key_plaintext=s.api_key_plaintext,
            download_feeds_enabled=s.download_feeds_enabled,
            page_size=s.page_size,
            window_days=s.window_days,
            min_freshness_hours=s.min_freshness_hours,
            last_modified_utc=last_modified_utc,
            last_successful_sync_at=last_successful_sync_at,
            updated_at=last_successful_sync_at,
        )

    def reset_watermark(self) -> None:
        self.advance_watermark(
            last_modified_utc=None,  # type: ignore[arg-type]
            last_successful_sync_at=self._snapshot.last_successful_sync_at
            or self._snapshot.updated_at,
        )


# ---------------- SyncRunRepository ---------------------------------------


class FakeSyncRunRepository:
    """Append-only audit list."""

    def __init__(self) -> None:
        self.runs: list[dict] = []

    def begin(self, *, run_kind: str, window: MirrorWindow) -> int:
        run_id = len(self.runs) + 1
        self.runs.append(
            {
                "id": run_id,
                "run_kind": run_kind,
                "window_start": window.start,
                "window_end": window.end,
                "started_at": datetime.now(tz=timezone.utc),
                "finished_at": None,
                "status": "running",
                "upserted_count": 0,
                "error_message": None,
            }
        )
        return run_id

    def finish(
        self,
        run_id: int,
        *,
        status: str,
        upserts: int,
        error: str | None,
    ) -> None:
        for run in self.runs:
            if run["id"] == run_id:
                run["status"] = status
                run["upserted_count"] = upserts
                run["error_message"] = error
                run["finished_at"] = datetime.now(tz=timezone.utc)
                return
        raise LookupError(f"sync_run id={run_id} not found")

    def latest(self, limit: int = 10) -> Sequence[Mapping[str, object]]:
        return list(reversed(self.runs))[:limit]


# ---------------- helpers --------------------------------------------------


def make_snapshot(
    *,
    enabled: bool = True,
    page_size: int = 2000,
    window_days: int = 30,
    min_freshness_hours: int = 24,
    last_modified_utc: datetime | None = None,
    last_successful_sync_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> NvdSettingsSnapshot:
    now = datetime.now(tz=timezone.utc)
    return NvdSettingsSnapshot(
        enabled=enabled,
        api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key_plaintext="test-key",
        download_feeds_enabled=False,
        page_size=page_size,
        window_days=window_days,
        min_freshness_hours=min_freshness_hours,
        last_modified_utc=last_modified_utc,
        last_successful_sync_at=last_successful_sync_at,
        updated_at=updated_at or now,
    )


def make_record(
    cve_id: str,
    *,
    last_modified: datetime,
    published: datetime | None = None,
    vuln_status: str = "Analyzed",
    cpe_criteria: Iterable = (),
) -> CveRecord:
    from app.nvd_mirror.domain.models import CveRecord as _R

    return _R(
        cve_id=cve_id,
        last_modified=last_modified,
        published=published or last_modified,
        vuln_status=vuln_status,
        description_en="",
        score_v40=None,
        score_v31=None,
        score_v2=None,
        severity_text=None,
        vector_string=None,
        aliases=(),
        cpe_criteria=tuple(cpe_criteria),
        references=(),
        raw={"id": cve_id},
    )


def batch(records: Sequence[CveRecord], *, total: int | None = None) -> CveBatch:
    return CveBatch(
        records=tuple(records),
        start_index=0,
        results_per_page=2000,
        total_results=total if total is not None else len(records),
    )
