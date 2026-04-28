"""Phase 2.7 — SqlAlchemySettingsRepository."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.nvd_mirror.adapters.secrets import FernetSecretsAdapter
from app.nvd_mirror.adapters.settings_repository import SqlAlchemySettingsRepository
from app.nvd_mirror.domain.models import NvdSettingsSnapshot
from app.nvd_mirror.settings import NvdMirrorSettings


UTC = timezone.utc


@pytest.fixture()
def session() -> Session:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Path(path).unlink(missing_ok=True)

    from app.db import Base
    import app.nvd_mirror.db.models  # noqa: F401

    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()
        Path(path).unlink(missing_ok=True)


@pytest.fixture()
def secrets() -> FernetSecretsAdapter:
    return FernetSecretsAdapter(Fernet.generate_key())


def _snap(
    *,
    enabled: bool = True,
    api_key: str | None = "secret-key-12345",
) -> NvdSettingsSnapshot:
    return NvdSettingsSnapshot(
        enabled=enabled,
        api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key_plaintext=api_key,
        download_feeds_enabled=False,
        page_size=2000,
        window_days=119,
        min_freshness_hours=24,
        last_modified_utc=None,
        last_successful_sync_at=None,
        updated_at=datetime.now(tz=UTC),
    )


# --- load -----------------------------------------------------------------


def test_load_seeds_defaults_on_first_call(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    snap = repo.load()
    session.commit()
    assert snap.enabled is False
    assert snap.api_endpoint.startswith("https://services.nvd.nist.gov")
    assert snap.api_key_plaintext is None
    assert snap.window_days == 119


def test_load_uses_env_defaults_when_provided(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    defaults = NvdMirrorSettings(enabled=True, page_size=500, window_days=30)
    repo = SqlAlchemySettingsRepository(session, secrets, env_defaults=defaults)
    snap = repo.load()
    session.commit()
    assert snap.enabled is True
    assert snap.page_size == 500
    assert snap.window_days == 30


def test_load_returns_existing_row_unchanged(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.save(_snap())
    session.commit()
    snap = repo.load()
    assert snap.enabled is True
    assert snap.api_key_plaintext == "secret-key-12345"


# --- save -----------------------------------------------------------------


def test_save_round_trip_preserves_api_key(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.save(_snap(api_key="my-nvd-secret"))
    session.commit()

    # Verify ciphertext was actually written and is non-trivial
    from app.nvd_mirror.db.models import NvdSettingsRow

    row = session.get(NvdSettingsRow, 1)
    assert row is not None
    assert row.api_key_ciphertext is not None
    assert b"my-nvd-secret" not in row.api_key_ciphertext  # encrypted, not plaintext

    snap = repo.load()
    assert snap.api_key_plaintext == "my-nvd-secret"


def test_save_with_empty_api_key_clears_ciphertext(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.save(_snap(api_key="x"))
    repo.save(_snap(api_key=""))
    session.commit()
    snap = repo.load()
    assert snap.api_key_plaintext is None


def test_save_does_not_advance_watermark(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    """save() may move enabled/api_endpoint but never the watermark."""
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.advance_watermark(
        last_modified_utc=datetime(2024, 6, 1, tzinfo=UTC),
        last_successful_sync_at=datetime(2024, 6, 1, tzinfo=UTC),
    )
    session.commit()

    repo.save(_snap(enabled=False, api_key="y"))
    session.commit()
    snap = repo.load()
    assert snap.last_modified_utc == datetime(2024, 6, 1, tzinfo=UTC)


# --- watermark ------------------------------------------------------------


def test_advance_watermark_seeds_row_if_missing(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    target = datetime(2024, 6, 1, tzinfo=UTC)
    repo.advance_watermark(last_modified_utc=target, last_successful_sync_at=target)
    session.commit()
    snap = repo.load()
    assert snap.last_modified_utc == target
    assert snap.last_successful_sync_at == target


def test_reset_watermark_clears_last_modified(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    target = datetime(2024, 6, 1, tzinfo=UTC)
    repo.advance_watermark(last_modified_utc=target, last_successful_sync_at=target)
    session.commit()
    repo.reset_watermark()
    session.commit()
    snap = repo.load()
    assert snap.last_modified_utc is None
    # Reset only clears last_modified_utc; last_successful_sync_at preserved
    # so the freshness check can still distinguish "never" from "stale".
    assert snap.last_successful_sync_at == target


# --- decrypt failures (rotated Fernet key) --------------------------------


def test_load_with_undecryptable_ciphertext_returns_none_key(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.save(_snap(api_key="x"))
    session.commit()
    # Rotate the Fernet key. The existing ciphertext is no longer
    # decryptable. Repository should NOT crash — return None plaintext.
    new_secrets = FernetSecretsAdapter(Fernet.generate_key())
    repo2 = SqlAlchemySettingsRepository(session, new_secrets)
    snap = repo2.load()
    assert snap.api_key_plaintext is None
    assert snap.enabled is True  # other fields still load


# --- singleton constraint -------------------------------------------------


def test_load_always_returns_id_1_singleton(
    session: Session, secrets: FernetSecretsAdapter
) -> None:
    repo = SqlAlchemySettingsRepository(session, secrets)
    repo.load()
    repo.load()
    repo.load()
    session.commit()
    from app.nvd_mirror.db.models import NvdSettingsRow
    rows = session.query(NvdSettingsRow).all()
    assert len(rows) == 1
    assert rows[0].id == 1
