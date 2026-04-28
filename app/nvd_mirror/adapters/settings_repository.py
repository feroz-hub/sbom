"""``SettingsRepositoryPort`` implementation backed by SQLAlchemy + Fernet.

The persisted ``nvd_settings`` row holds the API key as opaque ciphertext.
``load`` decrypts via ``SecretsPort``; ``save`` re-encrypts. Plaintext is
NEVER written to a log line, never persisted in any other column.

Seeding rule: ``load`` materialises a default row from
``NvdMirrorSettings`` defaults the first time it is called. After that
the DB row is the source of truth.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..db.models import NvdSettingsRow
from ..domain.models import NvdSettingsSnapshot
from ..ports.secrets import SecretsPort
from ..settings import NvdMirrorSettings

log = logging.getLogger(__name__)

_SINGLETON_ID = 1


class SqlAlchemySettingsRepository:
    """Reads / writes the singleton ``nvd_settings`` row."""

    def __init__(
        self,
        session: Session,
        secrets: SecretsPort,
        *,
        env_defaults: NvdMirrorSettings | None = None,
    ) -> None:
        self._session = session
        self._secrets = secrets
        self._env_defaults = env_defaults or NvdMirrorSettings()

    # ---- reads ----------------------------------------------------------

    def load(self) -> NvdSettingsSnapshot:
        row = self._session.get(NvdSettingsRow, _SINGLETON_ID)
        if row is None:
            row = self._seed_default_row()
        return self._row_to_snapshot(row)

    # ---- writes ---------------------------------------------------------

    def save(self, snapshot: NvdSettingsSnapshot) -> NvdSettingsSnapshot:
        row = self._session.get(NvdSettingsRow, _SINGLETON_ID)
        if row is None:
            row = self._seed_default_row()

        row.enabled = snapshot.enabled
        row.api_endpoint = snapshot.api_endpoint
        row.download_feeds_enabled = snapshot.download_feeds_enabled
        row.page_size = snapshot.page_size
        row.window_days = snapshot.window_days
        row.min_freshness_hours = snapshot.min_freshness_hours

        if snapshot.api_key_plaintext is None or snapshot.api_key_plaintext == "":
            row.api_key_ciphertext = None
        else:
            row.api_key_ciphertext = self._secrets.encrypt(snapshot.api_key_plaintext)

        # last_modified_utc / last_successful_sync_at are advanced by
        # ``advance_watermark`` exclusively. ``save`` never moves them
        # backward — the admin UI's "save settings" must not rewind a
        # successful sync's progress.
        row.updated_at = _utc_now()
        self._session.flush()
        return self._row_to_snapshot(row)

    def advance_watermark(
        self,
        *,
        last_modified_utc: datetime,
        last_successful_sync_at: datetime,
    ) -> None:
        row = self._session.get(NvdSettingsRow, _SINGLETON_ID)
        if row is None:
            row = self._seed_default_row()
        row.last_modified_utc = last_modified_utc
        row.last_successful_sync_at = last_successful_sync_at
        row.updated_at = _utc_now()
        self._session.flush()

    def reset_watermark(self) -> None:
        row = self._session.get(NvdSettingsRow, _SINGLETON_ID)
        if row is None:
            row = self._seed_default_row()
        row.last_modified_utc = None
        row.updated_at = _utc_now()
        self._session.flush()

    # ---- internals ------------------------------------------------------

    def _seed_default_row(self) -> NvdSettingsRow:
        """Insert the singleton row using env-driven defaults."""
        defaults = self._env_defaults
        row = NvdSettingsRow(
            id=_SINGLETON_ID,
            enabled=defaults.enabled,
            api_endpoint=defaults.api_endpoint,
            api_key_ciphertext=None,
            download_feeds_enabled=defaults.download_feeds_enabled,
            page_size=defaults.page_size,
            window_days=defaults.window_days,
            min_freshness_hours=defaults.min_freshness_hours,
            last_modified_utc=None,
            last_successful_sync_at=None,
            updated_at=_utc_now(),
        )
        self._session.add(row)
        self._session.flush()
        return row

    def _row_to_snapshot(self, row: NvdSettingsRow) -> NvdSettingsSnapshot:
        api_key_plaintext: str | None = None
        if row.api_key_ciphertext:
            try:
                api_key_plaintext = self._secrets.decrypt(row.api_key_ciphertext)
            except ValueError:
                # Ciphertext present but decrypt failed — most likely a
                # rotated Fernet key. Return None so the caller sees
                # "no key" rather than crashing every request.
                log.error(
                    "nvd_mirror_api_key_decrypt_failed",
                    extra={"hint": "Fernet key may have been rotated"},
                )
                api_key_plaintext = None

        return NvdSettingsSnapshot(
            enabled=row.enabled,
            api_endpoint=row.api_endpoint,
            api_key_plaintext=api_key_plaintext,
            download_feeds_enabled=row.download_feeds_enabled,
            page_size=row.page_size,
            window_days=row.window_days,
            min_freshness_hours=row.min_freshness_hours,
            last_modified_utc=_ensure_utc(row.last_modified_utc),
            last_successful_sync_at=_ensure_utc(row.last_successful_sync_at),
            updated_at=_ensure_utc(row.updated_at),
        )


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on round-trip; re-attach UTC defensively."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
