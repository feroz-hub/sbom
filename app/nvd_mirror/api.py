"""FastAPI admin router for the NVD mirror.

Endpoints (all under ``/admin/nvd-mirror``):

  * ``GET    /settings``         current snapshot, API key masked
  * ``PUT    /settings``         partial update (PATCH-like semantics)
  * ``POST   /sync``             enqueue ``mirror_nvd`` Celery task
  * ``GET    /sync/status``      last 10 sync_run rows
  * ``POST   /watermark/reset``  set ``last_modified_utc=NULL`` to force re-bootstrap

Auth: every route is protected by the existing ``require_auth`` dependency.

  ⚠ TODO (Phase 0 §F.17): the project has no admin-role tier — every
  authenticated caller can hit these endpoints. When a role split is
  introduced, replace ``require_auth`` here with an admin-only dependency.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import require_auth
from ..db import get_db
from .adapters.secrets import FernetSecretsAdapter, MissingFernetKeyError
from .adapters.settings_repository import SqlAlchemySettingsRepository
from .adapters.sync_run_repository import SqlAlchemySyncRunRepository
from .domain.models import NvdSettingsSnapshot
from .ports import SecretsPort, SettingsRepositoryPort, SyncRunRepositoryPort
from .schemas import (
    NvdSettingsResponse,
    NvdSettingsUpdate,
    SyncRunResponse,
    SyncTriggerResponse,
)
from .settings import load_mirror_settings_from_env
from .tasks import _StubSecrets

log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/nvd-mirror",
    tags=["admin", "nvd-mirror"],
    # TODO (Phase 0 §F.17): introduce an admin-role guard here once the
    # auth module supports role-based dependencies. Until then, the basic
    # require_auth dependency lives at app/main.py registration time.
)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_secrets() -> SecretsPort:
    """Return a SecretsPort. Falls back to a fail-closed stub if Fernet key absent.

    The stub still allows GET /settings to work (encrypted ciphertext can't
    be decrypted; settings repo returns ``api_key_plaintext=None``).
    A PUT that sets a non-empty ``api_key`` will fail-fast in the stub's
    ``encrypt``.
    """
    env_defaults = load_mirror_settings_from_env()
    try:
        return FernetSecretsAdapter.from_env(env_var=env_defaults.fernet_key_env_var)
    except MissingFernetKeyError:
        return _StubSecrets(env_defaults.fernet_key_env_var)


def get_settings_repo(
    db: Session = Depends(get_db),
    secrets: SecretsPort = Depends(get_secrets),
) -> SettingsRepositoryPort:
    return SqlAlchemySettingsRepository(
        db, secrets, env_defaults=load_mirror_settings_from_env()
    )


def get_sync_run_repo(db: Session = Depends(get_db)) -> SyncRunRepositoryPort:
    return SqlAlchemySyncRunRepository(db)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@router.get("/settings", response_model=NvdSettingsResponse)
def get_settings(
    repo: SettingsRepositoryPort = Depends(get_settings_repo),
    db: Session = Depends(get_db),
) -> NvdSettingsResponse:
    snap = repo.load()
    db.commit()  # commit if load() seeded the singleton row
    return NvdSettingsResponse.from_snapshot(snap)


@router.put("/settings", response_model=NvdSettingsResponse)
def put_settings(
    payload: NvdSettingsUpdate,
    repo: SettingsRepositoryPort = Depends(get_settings_repo),
    db: Session = Depends(get_db),
) -> NvdSettingsResponse:
    current = repo.load()
    fields_set = payload.model_fields_set

    new_api_key: str | None
    if payload.clear_api_key:
        new_api_key = ""
    elif "api_key" in fields_set and payload.api_key is not None:
        new_api_key = payload.api_key
    else:
        new_api_key = current.api_key_plaintext  # preserve

    new_endpoint = (
        str(payload.api_endpoint)
        if "api_endpoint" in fields_set and payload.api_endpoint is not None
        else current.api_endpoint
    )

    next_snap = NvdSettingsSnapshot(
        enabled=_pick(payload.enabled, current.enabled, "enabled" in fields_set),
        api_endpoint=new_endpoint,
        api_key_plaintext=new_api_key,
        download_feeds_enabled=_pick(
            payload.download_feeds_enabled,
            current.download_feeds_enabled,
            "download_feeds_enabled" in fields_set,
        ),
        page_size=_pick(payload.page_size, current.page_size, "page_size" in fields_set),
        window_days=_pick(
            payload.window_days, current.window_days, "window_days" in fields_set
        ),
        min_freshness_hours=_pick(
            payload.min_freshness_hours,
            current.min_freshness_hours,
            "min_freshness_hours" in fields_set,
        ),
        last_modified_utc=current.last_modified_utc,
        last_successful_sync_at=current.last_successful_sync_at,
        updated_at=current.updated_at,
    )

    try:
        saved = repo.save(next_snap)
    except MissingFernetKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Fernet key not configured — cannot persist API key. {exc}",
        ) from exc

    db.commit()
    return NvdSettingsResponse.from_snapshot(saved)


# ---------------------------------------------------------------------------
# Sync trigger / status
# ---------------------------------------------------------------------------


@router.post(
    "/sync",
    response_model=SyncTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_sync() -> SyncTriggerResponse:
    """Enqueue ``mirror_nvd`` for immediate execution.

    Beat fires it hourly already; this is for operator-initiated runs
    (typically the first bootstrap).
    """
    # Imported here so an unrelated test that doesn't hit /sync isn't
    # forced to import Celery.
    from .tasks import mirror_nvd

    try:
        async_result = mirror_nvd.delay()
    except Exception as exc:
        # If Redis is down we surface 503 and let the caller retry; the
        # mirror is intentionally NOT a hard dependency for analysis.
        log.error("nvd_mirror_enqueue_failed", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to enqueue mirror task: {exc}",
        ) from exc

    return SyncTriggerResponse(task_id=str(async_result.id), status="queued")


@router.get("/sync/status", response_model=list[SyncRunResponse])
def get_sync_status(
    repo: SyncRunRepositoryPort = Depends(get_sync_run_repo),
) -> list[SyncRunResponse]:
    rows = repo.latest(limit=10)
    return [SyncRunResponse(**dict(row)) for row in rows]


# ---------------------------------------------------------------------------
# Watermark reset
# ---------------------------------------------------------------------------


@router.post("/watermark/reset", response_model=NvdSettingsResponse)
def reset_watermark(
    repo: SettingsRepositoryPort = Depends(get_settings_repo),
    db: Session = Depends(get_db),
) -> NvdSettingsResponse:
    """Set ``last_modified_utc=NULL`` so the next ``mirror_nvd`` run re-bootstraps."""
    repo.reset_watermark()
    db.commit()
    snap = repo.load()
    return NvdSettingsResponse.from_snapshot(snap)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _pick(new, current, was_set: bool):
    return new if was_set and new is not None else current
