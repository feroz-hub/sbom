"""Celery task and orchestration helper for the NVD mirror.

The Celery task body (``mirror_nvd``) is intentionally thin — it builds
adapters from the application context and delegates to ``run_mirror_sync``.
``run_mirror_sync`` is plain async/sync Python with no Celery imports,
which makes it testable without a broker or worker process.

Single-run guard: if any ``nvd_sync_runs`` row is in ``status='running'``
when the task starts, this run is a no-op. Beat fires hourly; long
bootstraps must not pile up.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from .adapters.clock import SystemClockAdapter
from .adapters.cve_repository import SqlAlchemyCveRepository
from .adapters.nvd_http import NvdHttpAdapter, NvdRemoteError
from .adapters.secrets import FernetSecretsAdapter, MissingFernetKeyError
from .adapters.settings_repository import SqlAlchemySettingsRepository
from .adapters.sync_run_repository import SqlAlchemySyncRunRepository
from .application import BootstrapMirror, IncrementalMirror
from .db.models import NvdSyncRunRow
from .domain.models import NvdSettingsSnapshot, SyncReport
from .ports import (
    ClockPort,
    CveRepositoryPort,
    NvdRemotePort,
    SettingsRepositoryPort,
    SyncRunRepositoryPort,
)
from .settings import load_mirror_settings_from_env

log = logging.getLogger(__name__)


class MirrorAlreadyRunningError(RuntimeError):
    """A prior bootstrap or incremental run is still ``status='running'``."""


# ---------------------------------------------------------------------------
# Pure orchestration — testable without Celery or live HTTP.
# ---------------------------------------------------------------------------


async def run_mirror_sync(
    *,
    settings_repo: SettingsRepositoryPort,
    cve_repo: CveRepositoryPort,
    sync_run_repo: SyncRunRepositoryPort,
    remote: NvdRemotePort,
    clock: ClockPort,
    commit: "Any",
    now: datetime | None = None,
) -> SyncReport:
    """Decide bootstrap vs incremental, run the chosen use case.

    The disabled-mirror path returns an empty SyncReport rather than
    raising — beat firing hourly while ``enabled=False`` is normal.
    """
    snapshot = settings_repo.load()
    target = now or clock.now()

    if not snapshot.enabled:
        log.info("nvd_mirror_disabled_skip")
        return _empty_report(clock, run_kind="incremental")

    use_case_kind: str
    if snapshot.last_modified_utc is None:
        use_case_kind = "bootstrap"
        uc: BootstrapMirror | IncrementalMirror = BootstrapMirror(
            remote=remote,
            cve_repo=cve_repo,
            settings_repo=settings_repo,
            sync_run_repo=sync_run_repo,
            clock=clock,
            commit=commit,
        )
    else:
        use_case_kind = "incremental"
        uc = IncrementalMirror(
            remote=remote,
            cve_repo=cve_repo,
            settings_repo=settings_repo,
            sync_run_repo=sync_run_repo,
            clock=clock,
            commit=commit,
        )

    log.info(
        "nvd_mirror_run_starting",
        extra={"kind": use_case_kind, "watermark": str(snapshot.last_modified_utc)},
    )
    report = await uc.execute(now=target)
    log.info(
        "nvd_mirror_run_complete",
        extra={
            "kind": report.run_kind,
            "windows": report.windows_completed,
            "upserts": report.upserts,
            "errors": len(report.errors),
        },
    )
    return report


def assert_no_run_in_flight(session: Session) -> None:
    """Single-run guard. Raises if any nvd_sync_runs row is still running.

    Future enhancement (Phase 6 §9-2): age-out 'running' rows older than
    6× window-time so a worker that died with `kill -9` doesn't block
    future scheduled runs forever.
    """
    stmt = (
        select(NvdSyncRunRow.id)
        .where(NvdSyncRunRow.status == "running")
        .limit(1)
    )
    existing = session.execute(stmt).scalar_one_or_none()
    if existing is not None:
        raise MirrorAlreadyRunningError(
            f"sync_run id={existing} is still 'running'; skip this firing"
        )


# ---------------------------------------------------------------------------
# Celery task — wires real adapters and delegates.
# ---------------------------------------------------------------------------


@shared_task(
    name="nvd_mirror.mirror_nvd",
    bind=True,
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(NvdRemoteError,),
    retry_backoff=True,
    retry_backoff_max=900,
)
def mirror_nvd(self) -> dict[str, Any]:
    """Hourly entry point. Pure orchestration; business logic in use cases."""
    from app.db import SessionLocal

    env_defaults = load_mirror_settings_from_env()
    secrets = _build_secrets(env_defaults.fernet_key_env_var)

    session: Session = SessionLocal()
    try:
        try:
            assert_no_run_in_flight(session)
        except MirrorAlreadyRunningError as exc:
            log.warning("nvd_mirror_skip_concurrent_run", extra={"error": str(exc)})
            return {
                "status": "skipped",
                "reason": "concurrent_run_in_progress",
            }

        settings_repo = SqlAlchemySettingsRepository(
            session, secrets, env_defaults=env_defaults
        )
        cve_repo = SqlAlchemyCveRepository(session)
        sync_run_repo = SqlAlchemySyncRunRepository(session)
        clock = SystemClockAdapter()

        snapshot = settings_repo.load()
        api_key = snapshot.api_key_plaintext  # may be None — adapter handles it

        # Resolve the live API key with env-var fallback if the DB row's
        # encrypted key is unset. The env-var path lets operators rotate
        # without touching the DB.
        if not api_key:
            import os
            env_key = os.getenv(env_defaults.api_key_env_var, "").strip()
            api_key = env_key or None

        async def _run() -> SyncReport:
            adapter = NvdHttpAdapter(
                api_endpoint=snapshot.api_endpoint, api_key=api_key
            )
            try:
                return await run_mirror_sync(
                    settings_repo=settings_repo,
                    cve_repo=cve_repo,
                    sync_run_repo=sync_run_repo,
                    remote=adapter,
                    clock=clock,
                    commit=session.commit,
                )
            finally:
                await adapter.aclose()

        report = asyncio.run(_run())
        # Final commit covers any tail state the use case may not have committed.
        session.commit()
        return _report_to_dict(report)
    except Exception as exc:
        session.rollback()
        log.error(
            "nvd_mirror_task_failed",
            extra={"exc_type": type(exc).__name__, "error": str(exc)},
        )
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _build_secrets(fernet_env_var: str) -> "object":
    """Return a SecretsPort impl. If the Fernet key is missing, return a
    stub that fails closed: decrypt yields a plaintext-None outcome via
    the settings repo's defensive bypass; encrypt raises so we never
    silently lose an API key on save.
    """
    try:
        return FernetSecretsAdapter.from_env(env_var=fernet_env_var)
    except MissingFernetKeyError:
        log.warning(
            "nvd_mirror_no_fernet_key",
            extra={"env_var": fernet_env_var},
        )
        return _StubSecrets(fernet_env_var)


class _StubSecrets:
    """Fail-closed secrets impl used when the Fernet key isn't configured.

    ``decrypt`` raises ``ValueError`` so the settings repo's existing
    defensive bypass returns ``api_key_plaintext=None``.
    ``encrypt`` raises so a save with a non-empty key fails fast.
    """

    def __init__(self, env_var: str) -> None:
        self._env_var = env_var

    def encrypt(self, plaintext: str) -> bytes:  # noqa: ARG002
        raise MissingFernetKeyError(
            f"Cannot persist API key: env var {self._env_var!r} is not set"
        )

    def decrypt(self, ciphertext: bytes) -> str:  # noqa: ARG002
        raise ValueError("Fernet key not configured — cannot decrypt")


def _empty_report(clock: ClockPort, *, run_kind: str) -> SyncReport:
    now = clock.now()
    return SyncReport(
        run_kind="bootstrap" if run_kind == "bootstrap" else "incremental",
        started_at=now,
        finished_at=now,
        windows_completed=0,
        upserts=0,
        rejected_marked=0,
        errors=(),
        final_watermark=None,
    )


def _report_to_dict(report: SyncReport) -> dict[str, Any]:
    return {
        "run_kind": report.run_kind,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat(),
        "windows_completed": report.windows_completed,
        "upserts": report.upserts,
        "rejected_marked": report.rejected_marked,
        "errors": list(report.errors),
        "final_watermark": (
            report.final_watermark.isoformat() if report.final_watermark else None
        ),
    }


# Re-export so ``app.nvd_mirror.tasks.mirror_nvd`` is the canonical path.
__all__ = [
    "MirrorAlreadyRunningError",
    "assert_no_run_in_flight",
    "mirror_nvd",
    "run_mirror_sync",
]
