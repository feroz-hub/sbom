"""Runtime lifecycle provider registry backed by admin configuration."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from ...settings import get_settings
from .deps_dev_provider import DepsDevProvider
from .endoflife_date_provider import EndOfLifeDateProvider
from .official_vendor_providers import OfficialVendorLifecycleProvider, RedHatLifecycleProvider
from .openeox_provider import OpenEoXProvider
from .osv_provider import OSVProvider
from .package_registry_provider import PackageRegistryProvider
from .provider_base import LifecycleProvider
from .provider_config_service import LifecycleProviderConfigService, ProviderConfigSnapshot
from .repository_health_provider import RepositoryHealthProvider
from .secret_service import LifecycleProviderSecretService
from .vendor_lifecycle_provider import VendorLifecycleProvider
from .xeol_db_provider import XeolDbProvider
from .xeol_provider import XeolProvider

log = logging.getLogger("sbom.lifecycle.provider_registry")


def _set_priority(provider: LifecycleProvider, priority: int) -> LifecycleProvider:
    provider.priority = priority
    return provider


def _env_vendor_records(settings: Any) -> list[dict[str, Any]]:
    raw = getattr(settings, "lifecycle_vendor_records_json", "[]")
    try:
        parsed = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


class LifecycleProviderRegistry:
    """Build enabled providers from DB config, with static fallback on DB failure."""

    def __init__(
        self,
        *,
        config_service: LifecycleProviderConfigService | None = None,
        secret_service: LifecycleProviderSecretService | None = None,
    ) -> None:
        self.config_service = config_service or LifecycleProviderConfigService()
        self.secret_service = secret_service or LifecycleProviderSecretService()

    def build_provider_chain(self, db: Session | None, *, fallback_timeout_seconds: float = 5.0) -> list[LifecycleProvider]:
        settings = get_settings()
        if db is None:
            return self.default_static_providers(settings, timeout_seconds=fallback_timeout_seconds)
        try:
            snapshots = self.config_service.list_snapshots(db)
            providers = self._providers_from_snapshots(db, settings, snapshots)
            return sorted(providers, key=lambda provider: (provider.priority, provider.name))
        except Exception as exc:  # noqa: BLE001
            log.warning("lifecycle.provider_config_fallback: %s", exc)
            return self.default_static_providers(settings, timeout_seconds=fallback_timeout_seconds)

    def default_static_providers(self, settings: Any | None = None, *, timeout_seconds: float = 5.0) -> list[LifecycleProvider]:
        settings = settings or get_settings()
        providers: list[LifecycleProvider] = []
        vendor = VendorLifecycleProvider.from_json(getattr(settings, "lifecycle_vendor_records_json", "[]"))
        if vendor.records:
            providers.append(vendor)
        providers.extend([RedHatLifecycleProvider(timeout_seconds=timeout_seconds), OfficialVendorLifecycleProvider()])
        if bool(getattr(settings, "openeox_enabled", False)):
            feed_urls = [
                url.strip()
                for url in str(getattr(settings, "openeox_feed_urls", "") or "").split(",")
                if url.strip()
            ]
            providers.append(OpenEoXProvider(feed_urls=feed_urls, timeout_seconds=timeout_seconds))
        providers.append(EndOfLifeDateProvider(timeout_seconds=timeout_seconds))
        xeol_key = getattr(settings, "lifecycle_xeol_api_key", None)
        if bool(getattr(settings, "lifecycle_xeol_enabled", False) or xeol_key):
            providers.append(
                XeolProvider(
                    api_url=getattr(settings, "lifecycle_xeol_api_url", "https://edb-prod.xeol.io/eol/check"),
                    api_key=xeol_key,
                    timeout_seconds=timeout_seconds,
                )
            )
        xeol_db_path = getattr(settings, "xeol_db_path", None)
        if bool(getattr(settings, "xeol_enabled", False) or xeol_db_path):
            providers.append(XeolDbProvider(db_path=xeol_db_path))
        providers.extend(
            [
                PackageRegistryProvider(timeout_seconds=timeout_seconds),
                DepsDevProvider(timeout_seconds=timeout_seconds),
                OSVProvider(timeout_seconds=timeout_seconds),
                RepositoryHealthProvider(timeout_seconds=timeout_seconds),
            ]
        )
        return sorted(providers, key=lambda provider: (provider.priority, provider.name))

    def _providers_from_snapshots(
        self,
        db: Session,
        settings: Any,
        snapshots: list[ProviderConfigSnapshot],
    ) -> list[LifecycleProvider]:
        providers: list[LifecycleProvider] = []
        for config in snapshots:
            if not config.enabled:
                continue
            provider = self._provider_from_snapshot(db, settings, config)
            if provider is not None:
                providers.append(_set_priority(provider, config.priority))
        return providers

    def _provider_from_snapshot(
        self,
        db: Session,
        settings: Any,
        config: ProviderConfigSnapshot,
    ) -> LifecycleProvider | None:
        timeout = float(config.timeout_seconds or getattr(settings, "lifecycle_provider_timeout_seconds", 5.0))
        if config.provider_key == "custom_vendor_records":
            records = self._custom_vendor_records(db, settings)
            if not records:
                return None
            return VendorLifecycleProvider(records)
        if config.provider_key == "redhat_lifecycle":
            return RedHatLifecycleProvider(timeout_seconds=timeout)
        if config.provider_key == "official_vendor_lifecycle":
            return OfficialVendorLifecycleProvider()
        if config.provider_key == "endoflife_date":
            return EndOfLifeDateProvider(base_url=config.base_url, timeout_seconds=timeout)
        if config.provider_key == "openeox":
            if not config.feed_urls:
                return None
            return OpenEoXProvider(feed_urls=config.feed_urls, timeout_seconds=timeout)
        if config.provider_key == "xeol_api":
            api_key = self.secret_service.get_secret(db, config.provider_key, "api_key") or getattr(
                settings, "lifecycle_xeol_api_key", None
            )
            return XeolProvider(
                api_url=config.base_url or getattr(settings, "lifecycle_xeol_api_url", "https://edb-prod.xeol.io/eol/check"),
                api_key=api_key,
                timeout_seconds=timeout,
            )
        if config.provider_key == "xeol_db":
            db_path = str(config.config.get("db_path") or getattr(settings, "xeol_db_path", "") or "") or None
            return XeolDbProvider(db_path=db_path)
        if config.provider_key == "package_registry":
            return PackageRegistryProvider(timeout_seconds=timeout)
        if config.provider_key == "deps_dev":
            return DepsDevProvider(timeout_seconds=timeout)
        if config.provider_key == "osv":
            return OSVProvider(timeout_seconds=timeout)
        if config.provider_key == "repository_health":
            return RepositoryHealthProvider(timeout_seconds=timeout)
        return None

    def _custom_vendor_records(self, db: Session, settings: Any) -> list[dict[str, Any]]:
        from .provider_config_service import LifecycleVendorRecordService

        records = LifecycleVendorRecordService().active_provider_records(db)
        env_records = _env_vendor_records(settings)
        return [*records, *env_records]


__all__ = ["LifecycleProviderRegistry"]
