"""Lifecycle provider configuration service."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...core.context import CurrentContext
from ...models import LifecycleProviderConfig, LifecycleProviderSecret, LifecycleVendorRecord
from ...services.audit_service import write_authorization_audit
from ...services.configuration_scope import current_configuration_tenant, require_active_configuration_tenant
from .endoflife_date_provider import END_OF_LIFE_API_V1, END_OF_LIFE_LEGACY_API
from .provider_capabilities import provider_capabilities
from .secret_service import LifecycleProviderSecretService
from .types import ALLOWED_CONFIDENCE_VALUES, ALLOWED_LIFECYCLE_STATUSES, canonical_confidence, canonical_status
from .xeol_db_provider import clear_xeol_db_cache, validate_xeol_db_path

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
    tenant_id: int | None = None


_CACHE: tuple[float, list[ProviderConfigSnapshot]] | None = None
_CACHE_TTL_SECONDS = 60.0


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def configuration_cache_namespace(db):
    import hashlib

    tenant_id = current_configuration_tenant()
    rows = LifecycleProviderConfigService().list_configs(db)
    values = [{"policy_version": 2}] + [
        {
            column.name: getattr(row, column.name)
            for column in row.__table__.columns
            if column.name
            not in {
                "last_success_at",
                "last_failure_at",
                "last_failure_message",
                "health_status",
                "last_probe_json",
                "last_lookup_at",
                "updated_at",
                "updated_by_user_id",
            }
        }
        for row in rows
    ]
    owners = {row.provider_key: row.tenant_id for row in rows}
    secrets = db.scalars(
        select(LifecycleProviderSecret).where(
            or_(LifecycleProviderSecret.tenant_id == tenant_id, LifecycleProviderSecret.tenant_id.is_(None))
        )
    )
    # Hash ciphertext only to invalidate results on key rotation; never expose it.
    values.extend(
        {"key": row.provider_key, "owner": row.tenant_id, "version": row.encrypted_value}
        for row in secrets
        if row.tenant_id == owners.get(row.provider_key)
    )
    values.extend(LifecycleVendorRecordService().active_provider_records(db))
    from ...settings import get_settings

    settings = get_settings()
    values.append(
        {
            key: getattr(settings, key)
            for key in (
                "lifecycle_vendor_records_json",
                "lifecycle_xeol_api_key",
                "lifecycle_egress_allowed_hosts",
                "lifecycle_cache_ttl_known_days",
                "lifecycle_cache_ttl_unknown_hours",
                "lifecycle_cache_ttl_provider_failure_minutes",
                "lifecycle_cache_ttl_deprecated_days",
            )
        }
    )
    digest = hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()
    return f"tenant:{tenant_id}:{digest}"


def resolve_effective_lifecycle_provider(db, tenant_id: int, provider_key: str):
    from ...core.context import minimal_background_context, tenant_scope

    with tenant_scope(minimal_background_context(tenant_id)):
        return LifecycleProviderConfigService().get_config(db, provider_key)


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


def _effective_health_status(enabled: bool, health_status: str | None) -> str:
    if not enabled:
        return "disabled"
    if health_status in {"healthy", "degraded", "unknown"}:
        return str(health_status)
    return "unknown"


def _row_snapshot(row: LifecycleProviderConfig) -> ProviderConfigSnapshot:
    return ProviderConfigSnapshot(
        tenant_id=row.tenant_id,
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
        health_status=_effective_health_status(bool(row.enabled), row.health_status),
    )


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _validate_optional_url(value: str | None, field_name: str) -> None:
    if value:
        parsed = urlparse(value)
        if (
            parsed.username
            or parsed.password
            or any(word in parsed.query.lower() for word in ("token=", "key=", "secret=", "password="))
        ):
            raise HTTPException(422, "Store endpoint credentials in encrypted secret storage")
    if value and not _is_http_url(value):
        raise HTTPException(status_code=422, detail=f"{field_name} must be an http(s) URL")


def _safe_metadata(value):
    """Legacy settings may predate encrypted secret storage; never serialize them."""
    if isinstance(value, dict):
        return {
            key: _safe_metadata(item)
            for key, item in value.items()
            if not any(
                word in key.lower().replace("-", "").replace("_", "")
                for word in ("password", "secret", "token", "apikey", "authorization", "privatekey")
            )
        }
    if isinstance(value, list):
        return [_safe_metadata(item) for item in value]
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        # Remove userinfo and all query/fragment values from safe metadata.
        return parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()
    return value


def _endoflife_probe_urls(base_url: str | None) -> tuple[str, ...]:
    base = (base_url or END_OF_LIFE_LEGACY_API).rstrip("/")
    if base == END_OF_LIFE_LEGACY_API.rstrip("/"):
        return (f"{END_OF_LIFE_API_V1}/debian/", f"{base}/debian.json")
    if base == END_OF_LIFE_API_V1.rstrip("/"):
        return (f"{base}/debian/",)
    return (f"{base}/debian.json",)


def write_audit_log(db, context, action, *, old_value=None, new_value=None, request=None, **_metadata):
    """Scope-safe structured audit, never attributed to synthetic tenant 1."""
    tenant_id = context.tenant_id if context else None
    if action.startswith("lifecycle.provider"):
        event = (
            "PLATFORM_LIFECYCLE_PROVIDER_UPDATED" if tenant_id is None else "TENANT_LIFECYCLE_PROVIDER_OVERRIDE_UPDATED"
        )
        if tenant_id is not None and old_value and old_value.get("source") == "PLATFORM_DEFAULT":
            event = "TENANT_LIFECYCLE_PROVIDER_OVERRIDE_CREATED"
        if action.endswith("test"):
            event = "PLATFORM_LIFECYCLE_PROVIDER_TESTED" if tenant_id is None else "TENANT_LIFECYCLE_PROVIDER_TESTED"
        elif action.endswith("sync"):
            event = "PLATFORM_LIFECYCLE_PROVIDER_SYNCED" if tenant_id is None else "TENANT_LIFECYCLE_PROVIDER_SYNCED"
    else:
        event = action
    write_authorization_audit(
        db,
        action=event,
        outcome="FAILED" if action.endswith("test") and new_value and new_value.get("success") is False else "SUCCESS",
        context=context,
        tenant_id=tenant_id,
        old_value=old_value,
        new_value=new_value,
        request=request,
    )


class LifecycleProviderConfigService:
    """CRUD, validation, and health helpers for lifecycle provider configs."""

    def bootstrap_defaults(self, db: Session) -> None:
        now = now_iso()
        existing = {
            row.provider_key
            for row in db.execute(
                select(LifecycleProviderConfig.provider_key).where(LifecycleProviderConfig.tenant_id.is_(None))
            ).all()
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
        tenant_id = current_configuration_tenant()
        require_active_configuration_tenant(db, tenant_id)
        self.bootstrap_defaults(db)
        platform = db.scalars(select(LifecycleProviderConfig).where(LifecycleProviderConfig.tenant_id.is_(None)))
        rows = {row.provider_key: row for row in platform}
        if tenant_id is not None:
            rows.update(
                {
                    row.provider_key: row
                    for row in db.scalars(
                        select(LifecycleProviderConfig).where(LifecycleProviderConfig.tenant_id == tenant_id)
                    )
                }
            )
        return sorted(
            (row for row in rows.values() if include_disabled or row.enabled),
            key=lambda row: (row.priority, row.display_name),
        )

    def get_config(self, db: Session, provider_key: str) -> LifecycleProviderConfig:
        row = next((row for row in self.list_configs(db) if row.provider_key == provider_key), None)
        if row is None:
            raise HTTPException(status_code=404, detail="Lifecycle provider not found")
        return row

    def list_snapshots(self, db: Session, *, use_cache: bool = True) -> list[ProviderConfigSnapshot]:
        # Resolve dynamically from SQL: no process-global tenant snapshot and
        # platform changes are visible to inheriting workers immediately.
        return [_row_snapshot(row) for row in self.list_configs(db)]

    def writable_config(self, db: Session, provider_key: str) -> LifecycleProviderConfig:
        row = self.get_config(db, provider_key)
        tenant_id = current_configuration_tenant()
        if row.tenant_id != tenant_id:
            values = {
                column.name: getattr(row, column.name)
                for column in row.__table__.columns
                if column.name not in {"id", "tenant_id", "updated_by_user_id"}
            }
            row = LifecycleProviderConfig(**values, tenant_id=tenant_id)
            db.add(row)
            db.flush()
        return row

    def reset_override(self, db: Session, provider_key: str, *, context, request=None):
        tenant_id = current_configuration_tenant()
        if tenant_id is None:
            raise HTTPException(403, "Tenant context is required to reset an override")
        old_metadata = self.safe_config_dict(db, self.get_config(db, provider_key))
        for model in (LifecycleProviderConfig, LifecycleProviderSecret):
            for row in db.scalars(
                select(model).where(model.tenant_id == tenant_id, model.provider_key == provider_key)
            ):
                db.delete(row)
        from ...services.audit_service import write_authorization_audit

        write_authorization_audit(
            db,
            action="TENANT_LIFECYCLE_PROVIDER_OVERRIDE_REMOVED",
            context=context,
            request=request,
            old_value=old_metadata,
            new_value={"provider": provider_key, "source": "PLATFORM_DEFAULT"},
        )
        db.flush()

    def update_config(
        self,
        db: Session,
        provider_key: str,
        payload: dict[str, Any],
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> LifecycleProviderConfig:
        old = self.safe_config_dict(db, self.get_config(db, provider_key))
        row = self.writable_config(db, provider_key)
        was_enabled = bool(row.enabled)
        old_health_status = row.health_status
        self._validate_update(row, payload)
        health_affecting_update = any(
            key in payload
            for key in (
                "base_url",
                "feed_urls_json",
                "config_json",
                "timeout_seconds",
                "max_retries",
                "circuit_breaker_enabled",
            )
        )
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
        if not bool(row.enabled):
            row.health_status = "disabled"
        elif not was_enabled or old_health_status == "disabled" or health_affecting_update:
            row.health_status = "unknown"
        elif row.health_status not in HEALTH_VALUES:
            row.health_status = "unknown"
        row.last_probe_json = None
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
        has_secret, preview = LifecycleProviderSecretService(tenant_id=row.tenant_id).metadata_for_provider(
            db, row.provider_key
        )
        caps = provider_capabilities(row.provider_key)
        if row.provider_key == "xeol_api" and row.tenant_id is None:
            from ...settings import get_settings

            has_secret = has_secret or bool(get_settings().lifecycle_xeol_api_key)
        from .provider_status import get_provider_status_tracker

        tracker = get_provider_status_tracker(configuration_cache_namespace(db))
        runtime = next(
            (item for item in tracker.list_sources() if item["name"] == (caps["runtime_name"] or row.display_name)),
            None,
        )
        configuration_status = "unsupported" if not caps["implemented"] else "configured"
        if (row.provider_key == "openeox" and not _json_list(row.feed_urls_json)) or (
            row.provider_key == "xeol_db" and not _json_dict(row.config_json).get("db_path")
        ):
            configuration_status = "missing_source"
        health = _effective_health_status(bool(row.enabled), row.health_status)
        if health == "healthy" and not (row.last_probe_json or {}).get("success"):
            health = "unknown"
        return {
            "source": "TENANT_OVERRIDE" if row.tenant_id is not None else "PLATFORM_DEFAULT",
            "override_enabled": row.tenant_id is not None,
            "provider_key": row.provider_key,
            "capabilities": caps,
            "configuration_status": configuration_status,
            "runtime_status": {"state_scope": "process-local", **(runtime or {})},
            "display_name": row.display_name,
            "provider_type": row.provider_type,
            "enabled": bool(row.enabled),
            "priority": row.priority,
            "base_url": _safe_metadata(row.base_url),
            "feed_urls": _safe_metadata(_json_list(row.feed_urls_json)),
            "config": _safe_metadata(_json_dict(row.config_json)),
            "timeout_seconds": row.timeout_seconds,
            "max_retries": row.max_retries,
            "circuit_breaker_enabled": bool(row.circuit_breaker_enabled),
            "cache_ttl": {
                "known_days": row.cache_ttl_known_days,
                "unknown_hours": row.cache_ttl_unknown_hours,
                "failure_minutes": row.cache_ttl_failure_minutes,
                "deprecated_days": row.cache_ttl_deprecated_days,
            },
            "health_status": health,
            "last_success_at": (row.last_probe_json or {}).get("checked_at")
            if (row.last_probe_json or {}).get("connection_verified") and (row.last_probe_json or {}).get("success")
            else None,
            "last_verification_at": (row.last_probe_json or {}).get("checked_at"),
            "last_lookup_at": row.last_lookup_at
            or max(
                [v for v in ((runtime or {}).get("last_success"), (runtime or {}).get("last_failure")) if v],
                default=None,
            ),
            "last_probe": _safe_metadata(row.last_probe_json),
            "last_failure_at": row.last_failure_at,
            "last_failure_message": "Provider connection failed." if row.last_failure_message else None,
            "has_secret": has_secret,
            "secret_preview": None,
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
        if secret_name != provider_capabilities(provider_key)["secret_name"]:
            raise HTTPException(422, "Unsupported credential field for this provider")
        old_metadata = self.safe_config_dict(db, self.get_config(db, provider_key))
        config_row = self.writable_config(db, provider_key)
        config_row.health_status = "unknown" if config_row.enabled else "disabled"
        config_row.last_probe_json = None
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
            old_value=old_metadata,
            entity_type="lifecycle_provider_secret",
            entity_id=f"{provider_key}:{secret_name}",
            new_value={"provider_key": provider_key, "secret_name": secret_name, "credential_configured": True},
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
            config_row = self.get_config(db, provider_key)
            config_row.health_status = "unknown" if config_row.enabled else "disabled"
            config_row.last_probe_json = None
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
                success, message, sample_result = self._run_provider_probe(snapshot, db=db)
                status_value = (
                    "unknown"
                    if sample_result and sample_result.get("probe_type") == "unsupported"
                    else "healthy"
                    if success
                    else "degraded"
                )
        except Exception as exc:  # noqa: BLE001
            message = f"Provider connection failed ({type(exc).__name__})."
            status_value = "degraded"
        latency_ms = int((time.perf_counter() - started) * 1000)
        checked_at = now_iso()
        if row.tenant_id == current_configuration_tenant():
            row.health_status = status_value
            if success:
                row.last_success_at = checked_at
                row.last_failure_message = None
            elif status_value != "disabled":
                row.last_failure_at = checked_at
                row.last_failure_message = message[:1000]
            row.updated_at = checked_at
        db.flush()
        invalidate_provider_config_cache()
        result = {
            **(sample_result or {}),
            "provider_key": provider_key,
            "success": success,
            "status": "unknown" if sample_result and sample_result.get("probe_type") == "unsupported" else status_value,
            "latency_ms": latency_ms,
            "message": message,
            "sample_result": _safe_metadata(sample_result),
            "checked_at": checked_at,
        }
        if row.tenant_id == current_configuration_tenant():
            row.last_probe_json = _safe_metadata(result)
            db.flush()
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
        result_status = "completed"
        triggered_at = now_iso()
        if row.provider_type == "xeol_db":
            if row.tenant_id != current_configuration_tenant():
                if not row.enabled:
                    return {
                        "job_id": None,
                        "status": "completed",
                        "message": "Provider is disabled; no synchronization performed.",
                        "triggered_at": triggered_at,
                    }
                clear_xeol_db_cache()
                success, message, _sample = self._run_provider_probe(_row_snapshot(row))
                return {
                    "job_id": None,
                    "status": "completed" if success else "failed",
                    "message": "Current process local DB cache reloaded. " + message,
                    "triggered_at": triggered_at,
                }
            clear_xeol_db_cache()
            if row.enabled:
                success, probe_message, _sample = self._run_provider_probe(_row_snapshot(row))
                row.health_status = "healthy" if success else "degraded"
                row.last_probe_json = _safe_metadata(
                    {
                        **(_sample or {}),
                        "success": success,
                        "checked_at": triggered_at,
                        "status": row.health_status,
                        "message": probe_message,
                        "latency_ms": 0,
                    }
                )
                if success:
                    row.last_success_at = triggered_at
                    row.last_failure_message = None
                else:
                    result_status = "failed"
                    row.last_failure_at = triggered_at
                    row.last_failure_message = probe_message[:1000]
                row.updated_at = triggered_at
                db.flush()
                invalidate_provider_config_cache()
                message = f"Local Xeol DB cache cleared. {probe_message}"
            else:
                row.health_status = "disabled"
                row.updated_at = triggered_at
                db.flush()
                invalidate_provider_config_cache()
                message = "Local Xeol DB cache cleared; provider is disabled."
        else:
            result_status = "unsupported"
            message = "Provider does not support synchronization."
        result = {"job_id": None, "status": result_status, "message": message, "triggered_at": triggered_at}
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
        def reject_secrets(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if any(
                        word in key.lower().replace("-", "").replace("_", "")
                        for word in ("password", "secret", "token", "apikey", "authorization", "privatekey")
                    ):
                        raise HTTPException(
                            422, "Store credentials in the encrypted secret field, not provider settings"
                        )
                    reject_secrets(item)
            elif isinstance(value, list):
                for item in value:
                    reject_secrets(item)

        from .provider_capabilities import provider_capabilities
        from .provider_http import ProviderRequestError, validate_url

        caps = provider_capabilities(row.provider_key)
        if not caps["network"] and any(
            key in payload and payload[key] != getattr(row, key)
            for key in ("timeout_seconds", "max_retries", "circuit_breaker_enabled")
        ):
            raise HTTPException(422, "Network policy settings do not apply to this local provider")
        if payload.get("base_url") and not caps["editable_endpoint"]:
            raise HTTPException(422, "This provider uses built-in endpoints")
        if payload.get("feed_urls_json") and not caps["feed_urls"]:
            raise HTTPException(422, "This provider does not consume feed URLs")
        if "config_json" in payload and set(payload["config_json"] or {}) - set(caps["config_fields"]):
            raise HTTPException(422, "Unsupported provider configuration fields")
        for endpoint in [payload.get("base_url"), *(payload.get("feed_urls_json") or [])]:
            if endpoint:
                try:
                    validate_url(endpoint)
                except ProviderRequestError:
                    raise HTTPException(
                        422,
                        "Endpoint must be HTTPS and use an approved destination without credentials or query parameters",
                    ) from None
        reject_secrets(payload.get("config_json", {}))
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
            valid, message, _sample = validate_xeol_db_path(db_path)
            if not valid:
                raise HTTPException(status_code=422, detail=message)

    def _run_provider_probe(
        self, snapshot: ProviderConfigSnapshot, *, db: Session | None = None
    ) -> tuple[bool, str, dict[str, Any] | None]:
        from .provider_probe import run_probe

        return run_probe(snapshot, db)


class LifecycleVendorRecordService:
    """CRUD helpers for UI-managed vendor lifecycle records."""

    @staticmethod
    def _require_platform_mutation(context: CurrentContext | None) -> None:
        if context is None or not context.is_platform_admin or not context.has_permission("platform:admin"):
            raise HTTPException(status_code=403, detail="Platform permission is required for this action")

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
        count_stmt = select(func.count(LifecycleVendorRecord.id))
        filters = []
        if search:
            needle = f"%{search.strip()}%"
            filters.append(
                or_(LifecycleVendorRecord.vendor_name.ilike(needle), LifecycleVendorRecord.product_name.ilike(needle))
            )
        if status:
            filters.append(LifecycleVendorRecord.lifecycle_status == canonical_status(status))
        if ecosystem:
            filters.append(LifecycleVendorRecord.ecosystem == ecosystem)
        for item in filters:
            stmt = stmt.where(item)
            count_stmt = count_stmt.where(item)
        rows = list(
            db.execute(
                stmt.order_by(LifecycleVendorRecord.vendor_name, LifecycleVendorRecord.product_name)
                .offset(offset)
                .limit(limit)
            ).scalars()
        )
        total = int(db.execute(count_stmt).scalar_one())
        return rows, total

    def create_record(
        self, db: Session, payload: dict[str, Any], *, context: CurrentContext | None, request: Request | None = None
    ) -> LifecycleVendorRecord:
        self._require_platform_mutation(context)
        row = LifecycleVendorRecord(
            **self._validated_payload(payload),
            created_at=now_iso(),
            updated_at=now_iso(),
            updated_by_user_id=context.user_id if context else None,
        )
        db.add(row)
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(
            db,
            context,
            "lifecycle.vendor_record.create",
            entity_type="lifecycle_vendor_record",
            entity_id=row.id,
            new_value=self.to_dict(row),
            request=request,
        )
        return row

    def update_record(
        self,
        db: Session,
        record_id: int,
        payload: dict[str, Any],
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> LifecycleVendorRecord:
        self._require_platform_mutation(context)
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
        write_audit_log(
            db,
            context,
            "lifecycle.vendor_record.update",
            entity_type="lifecycle_vendor_record",
            entity_id=row.id,
            old_value=old,
            new_value=self.to_dict(row),
            request=request,
        )
        return row

    def disable_record(
        self, db: Session, record_id: int, *, context: CurrentContext | None, request: Request | None = None
    ) -> bool:
        self._require_platform_mutation(context)
        row = db.get(LifecycleVendorRecord, record_id)
        if row is None:
            return False
        old = self.to_dict(row)
        row.enabled = False
        row.updated_at = now_iso()
        row.updated_by_user_id = context.user_id if context else None
        db.flush()
        invalidate_provider_config_cache()
        write_audit_log(
            db,
            context,
            "lifecycle.vendor_record.delete",
            entity_type="lifecycle_vendor_record",
            entity_id=row.id,
            old_value=old,
            new_value=self.to_dict(row),
            request=request,
        )
        return True

    def export_records(self, db: Session) -> list[dict[str, Any]]:
        rows = db.execute(
            select(LifecycleVendorRecord).order_by(
                LifecycleVendorRecord.vendor_name, LifecycleVendorRecord.product_name
            )
        ).scalars()
        return [self.to_vendor_provider_record(row) for row in rows if row.enabled]

    def import_records(
        self,
        db: Session,
        records: list[dict[str, Any]],
        *,
        context: CurrentContext | None,
        request: Request | None = None,
    ) -> dict[str, Any]:
        self._require_platform_mutation(context)
        created = 0
        errors: list[str] = []
        for index, record in enumerate(records):
            try:
                self.create_record(db, record, context=context, request=None)
                created += 1
            except HTTPException as exc:
                errors.append(f"{index}: {exc.detail}")
        write_audit_log(
            db,
            context,
            "lifecycle.vendor_record.import",
            entity_type="lifecycle_vendor_record",
            new_value={"created": created, "errors": errors},
            request=request,
        )
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
