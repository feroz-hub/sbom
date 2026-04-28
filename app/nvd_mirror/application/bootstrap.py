"""BootstrapMirror — full historical walk from 2002-01-01 to now."""

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


class BootstrapMirror:
    """Walks the full NVD lastModified history from the historical floor.

    Resumability: starts from ``snapshot.last_modified_utc`` if set
    (the watermark from a prior interrupted bootstrap), else from
    ``2002-01-01T00:00:00Z``.
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
        cursor = snapshot.last_modified_utc or HISTORICAL_FLOOR

        return await walk_windows(
            run_kind="bootstrap",
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
