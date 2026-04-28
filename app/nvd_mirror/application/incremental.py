"""IncrementalMirror — walks watermark -> now."""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from ..domain.models import SyncReport
from ..ports import (
    ClockPort,
    CveRepositoryPort,
    NvdRemotePort,
    SettingsRepositoryPort,
    SyncRunRepositoryPort,
)
from ._window_walker import HISTORICAL_FLOOR, walk_windows
from .bootstrap import BootstrapMirror


class IncrementalMirror:
    """Walks ``last_modified_utc`` watermark forward to ``now``.

    If the watermark is ``None`` (first ever run), delegates to
    ``BootstrapMirror`` so we never accidentally produce a partial
    mirror that thinks it is fully bootstrapped.
    """

    def __init__(
        self,
        *,
        remote: NvdRemotePort,
        cve_repo: CveRepositoryPort,
        settings_repo: SettingsRepositoryPort,
        sync_run_repo: SyncRunRepositoryPort,
        clock: ClockPort,
        commit: Callable[[], None],
    ) -> None:
        self._remote = remote
        self._cve_repo = cve_repo
        self._settings_repo = settings_repo
        self._sync_run_repo = sync_run_repo
        self._clock = clock
        self._commit = commit

    async def execute(self, *, now: datetime | None = None) -> SyncReport:
        target = now or self._clock.now()
        snapshot = self._settings_repo.load()

        if snapshot.last_modified_utc is None:
            # No prior bootstrap. Delegate so we don't half-mirror.
            return await BootstrapMirror(
                remote=self._remote,
                cve_repo=self._cve_repo,
                settings_repo=self._settings_repo,
                sync_run_repo=self._sync_run_repo,
                clock=self._clock,
                commit=self._commit,
            ).execute(now=target)

        cursor = snapshot.last_modified_utc
        if cursor >= target:
            # Already caught up. No-op run.
            from ..domain.models import SyncReport as _SR

            now_clock = self._clock.now()
            return _SR(
                run_kind="incremental",
                started_at=now_clock,
                finished_at=now_clock,
                windows_completed=0,
                upserts=0,
                rejected_marked=0,
                errors=(),
                final_watermark=cursor,
            )

        return await walk_windows(
            run_kind="incremental",
            cursor=cursor,
            target=target,
            snapshot=snapshot,
            remote=self._remote,
            cve_repo=self._cve_repo,
            settings_repo=self._settings_repo,
            sync_run_repo=self._sync_run_repo,
            clock=self._clock,
            commit=self._commit,
        )


# Re-export so importers don't have to know about the helper module.
__all__ = ["IncrementalMirror", "HISTORICAL_FLOOR"]
