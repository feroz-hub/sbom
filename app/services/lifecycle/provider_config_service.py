"""Lifecycle provider configuration service."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...core.context import CurrentContext
from ...models import LifecycleProviderConfig, LifecycleProviderSecret, LifecycleVendorRecord
from ...services.audit_service import write_audit_log
from .secret_service import LifecycleProviderSecretService
from .types import ALLOWED_CONFIDENCE_VALUES, ALLOWED_LIFECYCLE_STATUSES, canonical_confidence, canonical_status
from .xeol_db_provider import clear_xeol_db_cache

DEFAULT_PROVIDER_CONFIGS: tuple[dict[str, Any], ...] = (
    {
        "provider_key": "redhat_lifecycle",
        "display_name": "Red Hat Lifecycle",
        "provider_type": "official_vendor",
        "enabled": True,
        "priority": 10,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "official_vendor_lifecycle",
        "display_name": "Official Vendor Lifecycle",
        "provider_type": "official_vendor",
        "enabled": True,
        "priority": 10,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "endoflife_date",
        "display_name": "endoflife.date",
        "provider_type": "endoflife_date",
        "enabled": True,
        "priority": 30,
        "base_url": "https://endoflife.date/api",
        "timeout_seconds": 5,
    },
    {
        "provider_key": "package_registry",
        "display_name": "Package Registry",
        "provider_type": "package_registry",
        "enabled": True,
        "priority": 50,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "deps_dev",
        "display_name": "deps.dev",
        "provider_type": "deps_dev",
        "enabled": True,
        "priority": 60,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "osv",
        "display_name": "OSV",
        "provider_type": "osv",
        "enabled": True,
        "priority": 70,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "repository_health",
        "display_name": "Repository Health",
        "provider_type": "repository_health",
        "enabled": True,
        "priority": 80,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "custom_vendor_records",
        "display_name": "Custom Vendor Records",
        "provider_type": "custom_vendor",
        "enabled": False,
        "priority": 5,
        "timeout_seconds": 5,
    },
    {
        "provider_key": "openeox",
        "display_name": "OpenEoX",
        "provider_type": "openeox",
        "enabled": False,
        "priority": 20,
        "feed_urls_json": [],
        "timeout_seconds": 10,
    },
    {
        "provider_key": "xeol_api",
        "display_name": "Xeol API",
        "provider_type": "xeol_api",
        "enabled": False,
        "priority": 40,
        "base_url": "https://edb-prod.xeol.io/eol/check",
        "timeout_seconds": 5,
    },
    {
        "provider_key": "xeol_db",
        "display_name": "Local Xeol DB",
        "provider_type": "xeol_db",
        "enabled": False,
        "priority": 40,
        "config_json": {"db_path": None},
        "timeout_seconds": 5,
    },
)

PROVIDER_KEYS = frozenset(row["provider_key"] for row in DEFAULT_PROVIDER_CONFIGS)
URL_PROVIDER_TYPES = {"endoflife_date", "openeox", "xeol_api"}
HEALTH_VALUES = {"healthy", "degraded", "disabled", "unknown"}


@dataclass(slots=True)
class ProviderConfigSnapshot:
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    priority: int
    base_url: str | None
    feed_urls: list[str]
    config: dict[str, Any]
    timeout_seconds: int
    max_retries: int
    circuit_breaker_enabled: bool
    cache_ttl_known_days: int | None
    cache_ttl_unknown_hours: int | None
    cache_ttl_failure_minutes: int | None
    cache_ttl_deprecated_days: int | None
    last_success_at: str | None
    last_failure_at: str | None
    last_failure_message: str | None
    health_status: str


_CACHE: tuple[float, list[ProviderConfigSnapshot]] | None = None
_CACHE_TTL_SECONDS = 60.0


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def invalidate_provider_config_cache() -> None:
    global _CACHE
    _CACHE = None


def _json_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [line.strip() for line in value.splitlines() if line.strip()]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _json_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _row_snapshot(row: LifecycleProviderConfig) -> ProviderConfigSnapshot:
    return ProviderConfigSnapshot(
        provider_key=row.provider_key,
        display_name=row.display_name,
        provider_type=row.provider_type,
        enabled=bool(row.enabled),
        priority=int(row.priority or 100),
        base_url=row.base_url,
        feed_urls=_json_list(row.feed_urls_json),
        config=_json_dict(row.config_json),
        timeout_seconds=int(row.timeout_seconds or 5),
        max_retries=int(row.max_retries or 0),
        circuit_breaker_enabled=bool(row.circuit_breaker_enabled),
        cache_ttl_known_days=row.cache_ttl_known_days,
        cache_ttl_unknown_hours=row.cache_ttl_unknown_hours,
        cache_ttl_failure_minutes=row.cache_ttl_failure_minutes,
        cache_ttl_deprecated_days=row.cache_ttl_deprecated_days,
        last_success_at=row.last_success_at,
        last_failure_at=row.last_failure_at,
        last_failure_message=row.last_failure_message,
        health_status=row.health_status or ("disabled" if not row.enabled else "unknown"),
    )


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _validate_optional_url(value: str | None, field_name: str) -> None:
    if value and not _is_http_url(value):
        raise HTTPException(status_code=422, detail=f"{field_name} must be an http(s) URL")


class LifecycleProviderConfigService:
    """CRUD, validation, and health helpers for lifecycle provider configs."""

    def bootstrap_defaults(self, db: Session) -> None:
        now = now_iso()
        existing = {
            row.provider_key
            for row in db.execute(select(LifecycleProviderConfig.provider_key)).all()
        }
        for defaults in DEFAULT_PROVIDER_CONFIGS:
            if defaults["provider_key"] in existing:
                continue
            db.add(
                LifecycleProviderConfig(
                    provider_key=defaults["provider_key"],
                    display_name=defaults["display_name"],
                    provider_type=defaults["provider_type"],
                    enabled=bool(defaults.get("enabled", True)),
                    priority=int(defaults.get("priority", 100)),
                    base_url=defaults.get("base_url"),
                    feed_urls_json=defaults.get("feed_urls_json"),
                    config_json=defaults.get("config_json"),
                    timeout_seconds=int(defaults.get("timeout_seconds", 5)),
                    max_retries=0,
                    circuit_breaker_enabled=True,
                    health_status="unknown" if defaults.get("enabled", True) else "disabled",
                    created_at=now,
                    updated_at=now,
                )
            )
        db.flush()
        invalidate_provider_config_cache()

    def list_configs(self, db: Session, *, include_disabled: bool = True) -> list[LifecycleProviderConfig]:
        self.bootstrap_defaults(db)
        stmt = select(LifecycleProviderConfig)
        if not include_disabled:
            stmt = stmt.where(LifecycleProviderConfig.enabled.is_(True))
        return list(db.execute(stmt.order_by(LifecycleProviderConfig.priority, LifecycleProviderConfig.display_name)).scalars())

    def get_config(self, db: Session, provider_key: str) -> LifecycleProviderConfig:
        self.bootstrap_defaults(db)
        row = db.execute(
            select(LifecycleProviderConfig).where(LifecycleProviderConfig.provider_key == provider_key)
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Lifecycle provider not found")
        return row

    def list_snapshots(self, db: Session, *, use_cache: bool = True) -> list[ProviderConfigSnapshot]:
        global _CACHE
        if use_cache and _CACHE is not None:
            cached_at, cached_rows = _CACHE
            if time.monotonic() - cached_at < _CACHE_TTL_SECONDS:
                return cached_rows
        try:
            rows = self.list_configs(db)
            snapshots = [_row_snapshot(row) for row in rows]
            _CACHE = (time.monotonic(), snapshots)
            return snapshots
        except Exception:
            raise

    def update_config(
        self,
        db: Session,
        provider_key: str,
        payload: dict[str, Any],
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> LifecycleProviderConfig:
        row = self.get_config(db, provider_key)
        old = self.safe_config_dict(db, row)
        self._validate_update(row, payload)
        editable = {
            "enabled",
            "priority",
            "base_url",
            "feed_urls_json",
            "config_json",
            "timeout_seconds",
            "max_retries",
            "circuit_breaker_enabled",
            "cache_ttl_known_days",
            "cache_ttl_unknown_hours",
            "cache_ttl_failure_minutes",
            "cache_ttl_deprecated_days",
        }
        for key, value in payload.items():
            if key in editable:
                setattr(row, key, value)
        row.health_status = "disabled" if not row.enabled else (row.health_status if row.health_status in HEALTH_VALUES else "unknown")
        row.updated_at = now_iso()
        row.updated_by_user_id = context.user_id if context else None
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(
            db,
            context,
            "lifecycle.provider_config.update",
            entity_type="lifecycle_provider_config",
            entity_id=row.provider_key,
            old_value=old,
            new_value=self.safe_config_dict(db, row),
            request=request,
        )
        return row

    def safe_config_dict(self, db: Session, row: LifecycleProviderConfig) -> dict[str, Any]:
        has_secret, preview = LifecycleProviderSecretService().metadata_for_provider(db, row.provider_key)
        return {
            "provider_key": row.provider_key,
            "display_name": row.display_name,
            "provider_type": row.provider_type,
            "enabled": bool(row.enabled),
            "priority": row.priority,
            "base_url": row.base_url,
            "feed_urls": _json_list(row.feed_urls_json),
            "config": _json_dict(row.config_json),
            "timeout_seconds": row.timeout_seconds,
            "max_retries": row.max_retries,
            "circuit_breaker_enabled": bool(row.circuit_breaker_enabled),
            "cache_ttl": {
                "known_days": row.cache_ttl_known_days,
                "unknown_hours": row.cache_ttl_unknown_hours,
                "failure_minutes": row.cache_ttl_failure_minutes,
                "deprecated_days": row.cache_ttl_deprecated_days,
            },
            "health_status": row.health_status or ("disabled" if not row.enabled else "unknown"),
            "last_success_at": row.last_success_at,
            "last_failure_at": row.last_failure_at,
            "last_failure_message": row.last_failure_message,
            "has_secret": has_secret,
            "secret_preview": preview,
            "updated_at": row.updated_at,
        }

    def set_secret(
        self,
        db: Session,
        provider_key: str,
        secret_name: str,
        secret_value: str,
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> LifecycleProviderSecret:
        self.get_config(db, provider_key)
        row = LifecycleProviderSecretService().upsert_secret(
            db,
            provider_key,
            secret_name,
            secret_value,
            updated_by_user_id=context.user_id if context else None,
        )
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(
            db,
            context,
            "lifecycle.provider_secret.upsert",
            entity_type="lifecycle_provider_secret",
            entity_id=f"{provider_key}:{secret_name}",
            new_value={"provider_key": provider_key, "secret_name": secret_name, "value_preview": row.value_preview},
            request=request,
        )
        return row

    def delete_secret(
        self,
        db: Session,
        provider_key: str,
        secret_name: str,
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> bool:
        self.get_config(db, provider_key)
        deleted = LifecycleProviderSecretService().delete_secret(db, provider_key, secret_name)
        if deleted:
            invalidate_provider_config_cache()
            write_audit_log(
                db,
                context,
                "lifecycle.provider_secret.delete",
                entity_type="lifecycle_provider_secret",
                entity_id=f"{provider_key}:{secret_name}",
                old_value={"provider_key": provider_key, "secret_name": secret_name},
                request=request,
            )
        return deleted

    def test_provider(
        self,
        db: Session,
        provider_key: str,
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> dict[str, Any]:
        row = self.get_config(db, provider_key)
        started = time.perf_counter()
        success = False
        status_value = "degraded"
        message = "Provider test did not complete."
        sample_result: dict[str, Any] | None = None
        try:
            if not row.enabled:
                status_value = "disabled"
                message = "Provider is disabled."
            else:
                snapshot = _row_snapshot(row)
                success, message, sample_result = self._run_provider_probe(snapshot)
                status_value = "healthy" if success else "degraded"
        except Exception as exc:  # noqa: BLE001
            message = str(exc)[:500]
            status_value = "degraded"
        latency_ms = int((time.perf_counter() - started) * 1000)
        checked_at = now_iso()
        row.health_status = status_value
        if success:
            row.last_success_at = checked_at
            row.last_failure_message = None
        else:
            row.last_failure_at = checked_at
            row.last_failure_message = message[:1000]
        row.updated_at = checked_at
        db.flush()
        invalidate_provider_config_cache()
        result = {
            "success": success,
            "status": status_value,
            "latency_ms": latency_ms,
            "message": message,
            "sample_result": sample_result,
            "checked_at": checked_at,
        }
        write_audit_log(
            db,
            context,
            "lifecycle.provider.test",
            entity_type="lifecycle_provider_config",
            entity_id=provider_key,
            new_value={k: v for k, v in result.items() if k != "sample_result"},
            request=request,
        )
        return result

    def sync_provider(
        self,
        db: Session,
        provider_key: str,
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> dict[str, Any]:
        row = self.get_config(db, provider_key)
        if row.provider_type == "xeol_db":
            clear_xeol_db_cache()
            message = "Local Xeol DB cache cleared; next lifecycle refresh will reload it."
        elif row.provider_type == "openeox":
            message = "OpenEoX feeds are loaded during lifecycle refresh/test with configured timeout."
        elif row.provider_type == "custom_vendor":
            message = "Custom vendor records are database-backed and available immediately."
        else:
            message = "Provider does not require a sync action."
        result = {"job_id": None, "status": "completed", "message": message, "triggered_at": now_iso()}
        write_audit_log(
            db,
            context,
            "lifecycle.provider.sync",
            entity_type="lifecycle_provider_config",
            entity_id=provider_key,
            new_value=result,
            request=request,
        )
        return result

    def _validate_update(self, row: LifecycleProviderConfig, payload: dict[str, Any]) -> None:
        if "provider_key" in payload and payload["provider_key"] != row.provider_key:
            raise HTTPException(status_code=422, detail="provider_key cannot be changed")
        priority = payload.get("priority", row.priority)
        if priority is not None and not (1 <= int(priority) <= 1000):
            raise HTTPException(status_code=422, detail="priority must be between 1 and 1000")
        timeout = payload.get("timeout_seconds", row.timeout_seconds)
        if timeout is not None and not (1 <= int(timeout) <= 60):
            raise HTTPException(status_code=422, detail="timeout_seconds must be between 1 and 60")
        retries = payload.get("max_retries", row.max_retries)
        if retries is not None and not (0 <= int(retries) <= 10):
            raise HTTPException(status_code=422, detail="max_retries must be between 0 and 10")
        base_url = payload.get("base_url", row.base_url)
        if row.provider_type in URL_PROVIDER_TYPES:
            _validate_optional_url(base_url, "base_url")
        enabled = bool(payload.get("enabled", row.enabled))
        feed_urls = _json_list(payload.get("feed_urls_json", row.feed_urls_json))
        if row.provider_type == "openeox":
            for url in feed_urls:
                _validate_optional_url(url, "feed_urls")
            if enabled and not feed_urls:
                raise HTTPException(status_code=422, detail="OpenEoX requires at least one feed URL when enabled")
        if row.provider_type == "xeol_api" and enabled and not base_url:
            raise HTTPException(status_code=422, detail="Xeol API requires base_url when enabled")
        config = _json_dict(payload.get("config_json", row.config_json))
        if row.provider_type == "xeol_db" and enabled:
            db_path = str(config.get("db_path") or "").strip()
            if not db_path:
                raise HTTPException(status_code=422, detail="Xeol DB requires config.db_path when enabled")
            if not Path(db_path).is_file():
                raise HTTPException(status_code=422, detail="Xeol DB path does not exist")

    def _run_provider_probe(self, snapshot: ProviderConfigSnapshot) -> tuple[bool, str, dict[str, Any] | None]:
        if snapshot.provider_type in {"official_vendor", "package_registry", "deps_dev", "osv", "repository_health", "custom_vendor"}:
            return True, "Provider configuration is valid and will be exercised during lifecycle refresh.", {
                "provider": snapshot.display_name
            }
        if snapshot.provider_type == "xeol_db":
            db_path = str(snapshot.config.get("db_path") or "")
            if not db_path or not Path(db_path).is_file():
                return False, "Configured Xeol DB path does not exist.", None
            return True, "Local Xeol DB path is readable.", {"db_path": db_path}
        urls = snapshot.feed_urls if snapshot.provider_type == "openeox" else [snapshot.base_url] if snapshot.base_url else []
        if not urls:
            return False, "No URL configured for provider.", None
        url = urls[0]
        with httpx.Client(timeout=max(1, snapshot.timeout_seconds), follow_redirects=True) as client:
            response = client.get(url)
            if response.status_code >= 400:
                return False, f"HTTP {response.status_code} from provider.", {"url": url}
            return True, f"Provider responded with HTTP {response.status_code}.", {"url": url, "status_code": response.status_code}


class LifecycleVendorRecordService:
    """CRUD helpers for UI-managed vendor lifecycle records."""

    def list_records(
        self,
        db: Session,
        *,
        search: str | None = None,
        status: str | None = None,
        ecosystem: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[LifecycleVendorRecord], int]:
        stmt = select(LifecycleVendorRecord)
        count_stmt = select(LifecycleVendorRecord.id)
        filters = []
        if search:
            needle = f"%{search.strip()}%"
            filters.append(or_(LifecycleVendorRecord.vendor_name.ilike(needle), LifecycleVendorRecord.product_name.ilike(needle)))
        if status:
            filters.append(LifecycleVendorRecord.lifecycle_status == canonical_status(status))
        if ecosystem:
            filters.append(LifecycleVendorRecord.ecosystem == ecosystem)
        for item in filters:
            stmt = stmt.where(item)
            count_stmt = count_stmt.where(item)
        rows = list(db.execute(stmt.order_by(LifecycleVendorRecord.vendor_name, LifecycleVendorRecord.product_name).offset(offset).limit(limit)).scalars())
        total = len(db.execute(count_stmt).all())
        return rows, total

    def create_record(self, db: Session, payload: dict[str, Any], *, context: CurrentContext | None, request: Request | None = None) -> LifecycleVendorRecord:
        row = LifecycleVendorRecord(**self._validated_payload(payload), created_at=now_iso(), updated_at=now_iso(), updated_by_user_id=context.user_id if context else None)
        db.add(row)
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(db, context, "lifecycle.vendor_record.create", entity_type="lifecycle_vendor_record", entity_id=row.id, new_value=self.to_dict(row), request=request)
        return row

    def update_record(self, db: Session, record_id: int, payload: dict[str, Any], *, context: CurrentContext | None, request: Request | None = None) -> LifecycleVendorRecord:
        row = db.get(LifecycleVendorRecord, record_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Vendor record not found")
        old = self.to_dict(row)
        for key, value in self._validated_payload(payload, partial=True).items():
            setattr(row, key, value)
        row.updated_at = now_iso()
        row.updated_by_user_id = context.user_id if context else None
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(db, context, "lifecycle.vendor_record.update", entity_type="lifecycle_vendor_record", entity_id=row.id, old_value=old, new_value=self.to_dict(row), request=request)
        return row

    def disable_record(self, db: Session, record_id: int, *, context: CurrentContext | None, request: Request | None = None) -> bool:
        row = db.get(LifecycleVendorRecord, record_id)
        if row is None:
            return False
        old = self.to_dict(row)
        row.enabled = False
        row.updated_at = now_iso()
        row.updated_by_user_id = context.user_id if context else None
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(db, context, "lifecycle.vendor_record.delete", entity_type="lifecycle_vendor_record", entity_id=row.id, old_value=old, new_value=self.to_dict(row), request=request)
        return True

    def export_records(self, db: Session) -> list[dict[str, Any]]:
        rows = db.execute(select(LifecycleVendorRecord).order_by(LifecycleVendorRecord.vendor_name, LifecycleVendorRecord.product_name)).scalars()
        return [self.to_vendor_provider_record(row) for row in rows if row.enabled]

    def import_records(self, db: Session, records: list[dict[str, Any]], *, context: CurrentContext | None, request: Request | None = None) -> dict[str, Any]:
        created = 0
        errors: list[str] = []
        for index, record in enumerate(records):
            try:
                self.create_record(db, record, context=context, request=None)
                created += 1
            except HTTPException as exc:
                errors.append(f"{index}: {exc.detail}")
        write_audit_log(db, context, "lifecycle.vendor_record.import", entity_type="lifecycle_vendor_record", new_value={"created": created, "errors": errors}, request=request)
        return {"created": created, "errors": errors}

    def active_provider_records(self, db: Session) -> list[dict[str, Any]]:
        rows = db.execute(select(LifecycleVendorRecord).where(LifecycleVendorRecord.enabled.is_(True))).scalars()
        return [self.to_vendor_provider_record(row) for row in rows]

    def to_dict(self, row: LifecycleVendorRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "vendor_name": row.vendor_name,
            "product_name": row.product_name,
            "product_aliases": _json_list(row.product_aliases_json),
            "ecosystem": row.ecosystem,
            "version_pattern": row.version_pattern,
            "version_start": row.version_start,
            "version_end": row.version_end,
            "lifecycle_status": row.lifecycle_status,
            "maintenance_status": row.maintenance_status,
            "eol_date": row.eol_date,
            "eos_date": row.eos_date,
            "eof_date": row.eof_date,
            "deprecated": bool(row.deprecated),
            "unsupported": bool(row.unsupported),
            "latest_supported_version": row.latest_supported_version,
            "recommended_version": row.recommended_version,
            "evidence_url": row.evidence_url,
            "evidence": _json_dict(row.evidence_json),
            "confidence": row.confidence,
            "enabled": bool(row.enabled),
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def to_vendor_provider_record(self, row: LifecycleVendorRecord) -> dict[str, Any]:
        return {
            "vendor_name": row.vendor_name,
            "name": row.product_name,
            "product_name": row.product_name,
            "aliases": _json_list(row.product_aliases_json),
            "ecosystem": row.ecosystem or "generic",
            "version": row.version_pattern or row.version_start,
            "lifecycle_status": row.lifecycle_status,
            "maintenance_status": row.maintenance_status,
            "eol_date": row.eol_date,
            "eos_date": row.eos_date,
            "eof_date": row.eof_date,
            "deprecated": bool(row.deprecated),
            "unsupported": bool(row.unsupported),
            "latest_supported_version": row.latest_supported_version,
            "recommended_version": row.recommended_version,
            "source_url": row.evidence_url,
            "source_name": f"{row.vendor_name} Lifecycle",
            "evidence": _json_dict(row.evidence_json),
            "confidence": row.confidence,
        }

    def _validated_payload(self, payload: dict[str, Any], *, partial: bool = False) -> dict[str, Any]:
        required = ("vendor_name", "product_name", "lifecycle_status")
        if not partial:
            for key in required:
                if not str(payload.get(key) or "").strip():
                    raise HTTPException(status_code=422, detail=f"{key} is required")
        out: dict[str, Any] = {}
        for key in (
            "vendor_name",
            "product_name",
            "ecosystem",
            "version_pattern",
            "version_start",
            "version_end",
            "maintenance_status",
            "eol_date",
            "eos_date",
            "eof_date",
            "latest_supported_version",
            "recommended_version",
            "evidence_url",
        ):
            if key in payload:
                out[key] = str(payload.get(key) or "").strip() or None
        if "product_aliases" in payload:
            out["product_aliases_json"] = _json_list(payload.get("product_aliases"))
        if "product_aliases_json" in payload:
            out["product_aliases_json"] = _json_list(payload.get("product_aliases_json"))
        if "evidence" in payload:
            out["evidence_json"] = _json_dict(payload.get("evidence"))
        if "evidence_json" in payload:
            out["evidence_json"] = _json_dict(payload.get("evidence_json"))
        if "lifecycle_status" in payload:
            status = canonical_status(payload.get("lifecycle_status"))
            if status not in ALLOWED_LIFECYCLE_STATUSES:
                raise HTTPException(status_code=422, detail="Invalid lifecycle_status")
            out["lifecycle_status"] = status
        if "confidence" in payload:
            confidence = canonical_confidence(payload.get("confidence"))
            if confidence not in ALLOWED_CONFIDENCE_VALUES:
                raise HTTPException(status_code=422, detail="Invalid confidence")
            out["confidence"] = confidence
        elif not partial:
            out["confidence"] = "High"
        for key in ("deprecated", "unsupported", "enabled"):
            if key in payload:
                out[key] = bool(payload[key])
            elif key == "enabled" and not partial:
                out[key] = True
        _validate_optional_url(out.get("evidence_url"), "evidence_url")
        return out


__all__ = [
    "DEFAULT_PROVIDER_CONFIGS",
    "LifecycleProviderConfigService",
    "LifecycleVendorRecordService",
    "ProviderConfigSnapshot",
    "invalidate_provider_config_cache",
]
