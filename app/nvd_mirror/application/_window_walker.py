"""Shared window-walking primitive used by Bootstrap and Incremental.

Both use cases differ only in their *starting* watermark; the walking
loop is identical. Extracting it here keeps both flows in a single
audited place.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Callable

from ..domain.models import (
    CveRecord,
    MirrorWindow,
    NvdSettingsSnapshot,
    SyncReport,
)
from ..observability import increment as _metric
from ..ports import (
    ClockPort,
    CveRepositoryPort,
    NvdRemotePort,
    SettingsRepositoryPort,
    SyncRunRepositoryPort,
)

log = logging.getLogger(__name__)

# Sentinel — the historical floor for NVD records. Bootstrap walks
# forward from here when no watermark is set.
HISTORICAL_FLOOR: datetime = datetime.fromisoformat("2002-01-01T00:00:00+00:00")


CommitFn = Callable[[], None]


async def walk_windows(
    *,
    run_kind: str,
    cursor: datetime,
    target: datetime,
    snapshot: NvdSettingsSnapshot,
    remote: NvdRemotePort,
    cve_repo: CveRepositoryPort,
    settings_repo: SettingsRepositoryPort,
    sync_run_repo: SyncRunRepositoryPort,
    clock: ClockPort,
    commit: CommitFn,
) -> SyncReport:
    """Walk ``cursor`` -> ``target`` in ``window_days``-wide windows.

    Per-window contract:
      1. ``sync_run_repo.begin`` records a 'running' row.
      2. For each NVD page: ``cve_repo.upsert_batch`` + commit (small tx).
      3. Soft-mark rejected CVEs.
      4. End-of-window: ``advance_watermark`` + ``finish('success')`` +
         commit (single transaction — caller owns the commit fn).
      5. On exception: ``finish('failed')`` + commit (rolling back the
         in-flight upserts is NOT done — they are idempotent and a future
         replay overwrites them safely).

    The ``commit`` callable is the caller's session.commit (or a stub
    in tests). All DB calls go through the repository ports; this
    function never touches a Session directly.
    """
    started_at = clock.now()
    upserts_total = 0
    rejected_total = 0
    windows_completed = 0
    errors: list[str] = []
    final_watermark = snapshot.last_modified_utc

    window_delta = timedelta(days=snapshot.window_days)

    while cursor < target:
        end = min(cursor + window_delta, target)
        try:
            window = MirrorWindow(start=cursor, end=end)
        except ValueError as exc:
            # Width violation. Should never happen — defensive.
            errors.append(f"invalid window {cursor!r}->{end!r}: {exc}")
            break

        run_id = sync_run_repo.begin(run_kind=run_kind, window=window)
        commit()

        window_upserts = 0
        window_rejected = 0
        try:
            async for batch in remote.fetch_window(window, page_size=snapshot.page_size):
                if not batch.records:
                    continue
                upserted = cve_repo.upsert_batch(batch.records)
                window_upserts += upserted
                _metric("nvd.cves.upserted", upserted)
                rejected_ids = _collect_rejected(batch.records)
                if rejected_ids:
                    window_rejected += cve_repo.soft_mark_rejected(rejected_ids)
                commit()  # per-page small transaction
        except Exception as exc:  # noqa: BLE001 — record + bail out cleanly
            log.error(
                "nvd_mirror_window_failed",
                extra={
                    "window_start": cursor.isoformat(),
                    "window_end": end.isoformat(),
                    "error": str(exc),
                    "exc_type": type(exc).__name__,
                },
            )
            errors.append(f"{type(exc).__name__}: {exc}")
            _metric("nvd.windows.failure")
            sync_run_repo.finish(
                run_id, status="failed", upserts=window_upserts, error=str(exc)
            )
            commit()
            break

        # End-of-window single transaction: advance watermark + finish run.
        success_at = clock.now()
        settings_repo.advance_watermark(
            last_modified_utc=end,
            last_successful_sync_at=success_at,
        )
        sync_run_repo.finish(
            run_id, status="success", upserts=window_upserts, error=None
        )
        commit()
        _metric("nvd.windows.success")

        upserts_total += window_upserts
        rejected_total += window_rejected
        windows_completed += 1
        final_watermark = end
        log.info(
            "nvd_window_complete",
            extra={
                "start": cursor.isoformat(),
                "end": end.isoformat(),
                "upserts": window_upserts,
                "rejected": window_rejected,
            },
        )
        cursor = end

    return SyncReport(
        run_kind="bootstrap" if run_kind == "bootstrap" else "incremental",
        started_at=started_at,
        finished_at=clock.now(),
        windows_completed=windows_completed,
        upserts=upserts_total,
        rejected_marked=rejected_total,
        errors=tuple(errors),
        final_watermark=final_watermark,
    )


def _collect_rejected(records: tuple[CveRecord, ...]) -> list[str]:
    return [r.cve_id for r in records if r.vuln_status == "Rejected"]
