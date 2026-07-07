"""Encrypted lifecycle provider secret storage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import LifecycleProviderSecret
from ...security.secrets import SecretCipher

SECRET_ENV_CANDIDATES = (
    "APP_SECRET_KEY",
    "SETTINGS_SECRET_KEY",
    "AI_CONFIG_ENCRYPTION_KEY",
    "JWT_SECRET_KEY",
)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def preview_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return f"{value[:2]}****{value[-2:]}"
    return f"{value[:6]}****{value[-4:]}"


def _cipher_from_environment() -> SecretCipher:
    for env_name in SECRET_ENV_CANDIDATES:
        raw = (os.getenv(env_name) or "").strip()
        if not raw:
            continue
        try:
            key = base64.b64decode(raw.encode("ascii"), validate=True)
            if len(key) == 32:
                return SecretCipher(key)
        except (binascii.Error, ValueError):
            pass
        return SecretCipher(hashlib.sha256(raw.encode("utf-8")).digest())
    raise RuntimeError(
        "Lifecycle provider secret encryption key is not configured. "
        "Set APP_SECRET_KEY, SETTINGS_SECRET_KEY, or AI_CONFIG_ENCRYPTION_KEY."
    )


class LifecycleProviderSecretService:
    """Store provider secrets encrypted at rest and expose preview-only metadata."""

    def __init__(self, cipher: SecretCipher | None = None) -> None:
        self._cipher = cipher

    @property
    def cipher(self) -> SecretCipher:
        if self._cipher is None:
            self._cipher = _cipher_from_environment()
        return self._cipher

    def get_row(self, db: Session, provider_key: str, secret_name: str) -> LifecycleProviderSecret | None:
        return db.execute(
            select(LifecycleProviderSecret).where(
                LifecycleProviderSecret.provider_key == provider_key,
                LifecycleProviderSecret.secret_name == secret_name,
            )
        ).scalar_one_or_none()

    def get_secret(self, db: Session, provider_key: str, secret_name: str = "api_key") -> str | None:  # nosec B107: secret field name, not a credential value
        row = self.get_row(db, provider_key, secret_name)
        if row is None:
            return None
        return self.cipher.decrypt(row.encrypted_value)

    def upsert_secret(
        self,
        db: Session,
        provider_key: str,
        secret_name: str,
        secret_value: str,
        *,
        updated_by_user_id: int | None,
    ) -> LifecycleProviderSecret:
        now = now_iso()
        row = self.get_row(db, provider_key, secret_name)
        encrypted = self.cipher.encrypt(secret_value)
        if row is None:
            row = LifecycleProviderSecret(
                provider_key=provider_key,
                secret_name=secret_name,
                encrypted_value=encrypted,
                value_preview=preview_secret(secret_value),
                created_at=now,
                updated_at=now,
                updated_by_user_id=updated_by_user_id,
            )
            db.add(row)
        else:
            row.encrypted_value = encrypted
            row.value_preview = preview_secret(secret_value)
            row.updated_at = now
            row.updated_by_user_id = updated_by_user_id
        return row

    def delete_secret(self, db: Session, provider_key: str, secret_name: str) -> bool:
        row = self.get_row(db, provider_key, secret_name)
        if row is None:
            return False
        db.delete(row)
        return True

    def metadata_for_provider(self, db: Session, provider_key: str) -> tuple[bool, str | None]:
        row = db.execute(
            select(LifecycleProviderSecret)
            .where(LifecycleProviderSecret.provider_key == provider_key)
            .order_by(LifecycleProviderSecret.secret_name.asc())
        ).scalars().first()
        return (row is not None, row.value_preview if row else None)


__all__ = ["LifecycleProviderSecretService", "preview_secret"]
