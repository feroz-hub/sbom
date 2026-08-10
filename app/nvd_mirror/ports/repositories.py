"""Repository ports.

Three small Protocols, one per persistence concern. Splitting them lets
the Phase 5 facade depend only on ``CveRepositoryPort`` without dragging
in the audit-log surface.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Protocol

from ..domain.models import (
    CveRecord,
    MirrorWindow,
    NvdSettingsSnapshot,
)


class CveRepositoryPort(Protocol):
    """Persistence for the mirrored CVE corpus.

    Idempotency contract: ``upsert_batch`` MUST be safe to replay. The
    PostgreSQL implementation enforces this with
    ``ON CONFLICT (cve_id) DO UPDATE WHERE excluded.last_modified > cves.last_modified``.
    """

    def upsert_batch(self, records: Sequence[CveRecord]) -> int: ...

    def find_by_cpe(self, cpe23: str) -> Sequence[CveRecord]: ...

    def find_by_cve_id(self, cve_id: str) -> CveRecord | None: ...

    def soft_mark_rejected(self, cve_ids: Sequence[str]) -> int: ...


class SettingsRepositoryPort(Protocol):
    """Persistence for the singleton ``nvd_settings`` row."""

    def load(self) -> NvdSettingsSnapshot: ...

    def save(self, snapshot: NvdSettingsSnapshot) -> NvdSettingsSnapshot: ...

    def advance_watermark(
        self,
        *,
        last_modified_utc: datetime,
        last_successful_sync_at: datetime,
    ) -> None: ...

    def reset_watermark(self) -> None: ...


class SyncRunRepositoryPort(Protocol):
    """Persistence for ``nvd_sync_runs`` audit log."""

    def begin(self, *, run_kind: str, window: MirrorWindow) -> int: ...

    def finish(
        self,
        run_id: int,
        *,
        status: str,
        upserts: int,
        error: str | None,
    ) -> None: ...

    def latest(self, limit: int = 10) -> Sequence[Mapping[str, object]]: ...
