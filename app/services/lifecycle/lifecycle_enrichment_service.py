"""Provider-based component lifecycle enrichment orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import UTC, datetime
from math import ceil
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import AuditLog, ComponentLifecycleCache, ComponentLifecycleOverrideAudit, SBOMComponent, SBOMSource
from ...settings import get_settings
from .decision_engine import choose_lifecycle_result
from .deps_dev_provider import DepsDevProvider
from .endoflife_date_provider import EndOfLifeDateProvider
from .lifecycle_cache_repository import lifecycle_cache_row_from_result, upsert_lifecycle_cache_entries
from .manual_override_provider import ManualOverrideProvider
from .normalizer import build_lifecycle_lookup_key, normalize_component
from .osv_provider import OSVProvider
from .package_registry_provider import PackageRegistryProvider
from .provider_base import LifecycleProvider
from .repository_health_provider import RepositoryHealthProvider
from .types import (
    ALLOWED_LIFECYCLE_STATUSES,
    DEPRECATED,
    EOF,
    EOL,
    EOL_SOON,
    EOS,
    HIGH,
    MEDIUM,
    POSSIBLY_UNMAINTAINED,
    STATUS_ALIASES,
    UNKNOWN,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    canonical_status,
    now_iso,
    unknown_result,
)
from .vendor_lifecycle_provider import VendorLifecycleProvider
from .xeol_provider import XeolProvider

DEFAULT_CACHE_TTL_DAYS = 7


class LifecycleEnrichmentService:
    """Normalize components, query providers, cache, and persist results."""

    def __init__(
        self,
        *,
        providers: list[LifecycleProvider] | None = None,
        cache_ttl_days: int = DEFAULT_CACHE_TTL_DAYS,
        provider_timeout_seconds: float | None = None,
        provider_max_concurrent: int | None = None,
    ) -> None:
        settings = get_settings()
        self.provider_timeout_seconds = max(
            0.1,
            float(provider_timeout_seconds or getattr(settings, "lifecycle_provider_timeout_seconds", 5.0)),
        )
        self.provider_max_concurrent = max(
            1,
            int(provider_max_concurrent or getattr(settings, "lifecycle_provider_max_concurrent", 3)),
        )
        self.providers = providers if providers is not None else self._default_providers(settings)
        self.cache_ttl_days = cache_ttl_days

    def _default_providers(self, settings: Any) -> list[LifecycleProvider]:
        providers: list[LifecycleProvider] = []
        vendor = VendorLifecycleProvider.from_json(getattr(settings, "lifecycle_vendor_records_json", "[]"))
        if vendor.records:
            providers.append(vendor)
        xeol_key = getattr(settings, "lifecycle_xeol_api_key", None)
        if bool(getattr(settings, "lifecycle_xeol_enabled", False) or xeol_key):
            providers.append(
                XeolProvider(
                    api_url=getattr(settings, "lifecycle_xeol_api_url", "https://edb-prod.xeol.io/eol/check"),
                    api_key=xeol_key,
                    timeout_seconds=self.provider_timeout_seconds,
                )
            )
        providers.extend(
            [
                EndOfLifeDateProvider(timeout_seconds=self.provider_timeout_seconds),
                DepsDevProvider(timeout_seconds=self.provider_timeout_seconds),
                PackageRegistryProvider(timeout_seconds=self.provider_timeout_seconds),
                RepositoryHealthProvider(timeout_seconds=self.provider_timeout_seconds),
                OSVProvider(timeout_seconds=self.provider_timeout_seconds),
            ]
        )
        return providers

    def enrich_sbom(self, db: Session, sbom_id: int, *, force_refresh: bool = False) -> dict[str, Any]:
        sbom = db.get(SBOMSource, sbom_id)
        if sbom is None:
            raise HTTPException(status_code=404, detail="SBOM not found")
        components = (
            db.execute(
                select(SBOMComponent).where(
                    SBOMComponent.sbom_id == sbom_id,
                    (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
                )
            )
            .scalars()
            .all()
        )
        enriched = 0
        stale = 0
        for component in components:
            result = self.enrich_component(db, component, force_refresh=force_refresh)
            enriched += 1
            stale += 1 if result.stale else 0
        db.commit()
        return {"sbom_id": sbom_id, "components_enriched": enriched, "stale_components": stale}

    def enrich_component(
        self,
        db: Session,
        component: SBOMComponent,
        *,
        force_refresh: bool = False,
    ) -> LifecycleResult:
        normalized = normalize_component(component)
        component.ecosystem = normalized.ecosystem

        manual = ManualOverrideProvider(component).lookup(normalized)
        if manual.manual_override:
            self._apply_result(component, manual, normalized)
            return manual

        cache_entry = self._read_cache(db, normalized)
        if cache_entry is not None and not force_refresh and not self._cache_expired(cache_entry):
            result = self._result_from_cache(cache_entry, normalized, stale=False)
            self._apply_result(component, result, normalized)
            return result

        result = self._lookup_providers(normalized)

        # Rule: Do not overwrite High/Medium confidence lifecycle evidence with Unknown
        if cache_entry is not None:
            cache_confidence = cache_entry.confidence or "Unknown"
            cache_status = cache_entry.lifecycle_status or UNKNOWN
            if cache_status != UNKNOWN and cache_confidence in {HIGH, MEDIUM} and result.lifecycle_status == UNKNOWN:
                stale = self._cache_expired(cache_entry)
                result = self._result_from_cache(cache_entry, normalized, stale=stale)
                self._apply_result(component, result, normalized)
                return result

        self._write_cache(db, normalized, result)
        self._apply_result(component, result, normalized)
        return result

    def apply_manual_override(
        self,
        db: Session,
        component_id: int,
        payload: dict[str, Any],
        *,
        updated_by: str | None = None,
    ) -> SBOMComponent:
        component = db.get(SBOMComponent, component_id)
        if component is None:
            raise HTTPException(status_code=404, detail="Component not found")

        raw_status = payload.get("lifecycle_status")
        status = canonical_status(raw_status)
        raw_status_key = " ".join(str(raw_status or "").strip().replace("_", " ").replace("-", " ").split()).lower()
        if status not in ALLOWED_LIFECYCLE_STATUSES or (
            status == UNKNOWN and raw_status_key not in {"", "unknown"} and raw_status_key not in STATUS_ALIASES
        ):
            raise HTTPException(status_code=422, detail="Invalid lifecycle_status")

        # Validate dates if provided
        for date_field in ("eos_date", "eol_date", "eof_date"):
            val = payload.get(date_field)
            if val:
                try:
                    datetime.strptime(val, "%Y-%m-%d")
                except ValueError:
                    raise HTTPException(status_code=422, detail=f"Invalid {date_field} format. Expected YYYY-MM-DD.")

        old_state = _component_lifecycle_state(component)
        evidence_url = payload.get("evidence_url") or payload.get("lifecycle_source_url")
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        reason = payload.get("reason") or payload.get("note")
        if reason:
            evidence = {**evidence, "reason": reason}
        else:
            raise HTTPException(status_code=422, detail="Manual lifecycle override requires reason")
        if evidence_url:
            evidence = {**evidence, "evidence_url": evidence_url}

        component.lifecycle_status = status
        component.eos_date = payload.get("eos_date")
        component.eol_date = payload.get("eol_date")
        component.eof_date = payload.get("eof_date")
        component.maintenance_status = payload.get("maintenance_status")
        component.latest_version = payload.get("latest_version")
        component.latest_supported_version = payload.get("latest_supported_version")
        component.recommended_version = payload.get("recommended_version")
        component.lifecycle_recommendation = payload.get("recommendation") or payload.get("lifecycle_recommendation")
        component.lifecycle_source = "Manual Override"
        component.lifecycle_source_url = evidence_url
        component.lifecycle_confidence = HIGH if evidence_url else "Medium"
        component.lifecycle_checked_at = now_iso()
        component.lifecycle_evidence_json = evidence
        component.lifecycle_is_stale = False
        component.lifecycle_manual_override = True
        component.deprecated = status == DEPRECATED or bool(payload.get("deprecated"))
        component.is_deprecated = bool(component.deprecated)
        component.unsupported = status in {EOL, EOS, EOF, UNSUPPORTED} or bool(payload.get("unsupported"))

        db.add(
            AuditLog(
                user_id=updated_by,
                action="component.lifecycle_override",
                target_kind="component",
                target_id=component.id,
                detail=f"Lifecycle override for {component.name}",
                metadata_json={"old": old_state, "new": _component_lifecycle_state(component), "reason": reason},
                created_at=now_iso(),
            )
        )
        db.add(
            ComponentLifecycleOverrideAudit(
                component_id=component.id,
                old_value_json=old_state,
                new_value_json=_component_lifecycle_state(component),
                reason=str(reason),
                evidence_url=evidence_url,
                changed_by=updated_by,
                changed_at=now_iso(),
            )
        )
        db.commit()
        db.refresh(component)
        return component

    def lifecycle_report(self, db: Session, sbom_id: int) -> dict[str, Any]:
        sbom = db.get(SBOMSource, sbom_id)
        if sbom is None:
            raise HTTPException(status_code=404, detail="SBOM not found")
        components = (
            db.execute(
                select(SBOMComponent).where(
                    SBOMComponent.sbom_id == sbom_id,
                    (SBOMComponent.is_duplicate.is_(False)) | (SBOMComponent.is_duplicate.is_(None)),
                )
            )
            .scalars()
            .all()
        )
        return {
            "sbom_id": sbom_id,
            "sbom_name": sbom.sbom_name,
            "generated_at": now_iso(),
            "summary": summarize_components(components),
            "components": [component_lifecycle_dict(component) for component in components],
        }

    def _lookup_providers(self, component: NormalizedComponent) -> LifecycleResult:
        results: list[LifecycleResult] = []
        if not self.providers:
            return unknown_result(component).canonicalized()

        max_workers = min(self.provider_max_concurrent, len(self.providers))
        timeout_budget = max(
            self.provider_timeout_seconds,
            self.provider_timeout_seconds * ceil(len(self.providers) / max_workers),
        )
        executor = ThreadPoolExecutor(max_workers=max_workers)
        future_to_provider = {
            executor.submit(self._lookup_provider_safely, provider, component): provider for provider in self.providers
        }
        completed = set()
        try:
            for future in as_completed(future_to_provider, timeout=timeout_budget):
                completed.add(future)
                result = future.result()
                results.append(result)
                repository_url = result.evidence.get("repository_url") if isinstance(result.evidence, dict) else None
                if repository_url and not component.repository_url:
                    component.repository_url = str(repository_url)

            for future, provider in future_to_provider.items():
                if future not in completed:
                    future.cancel()
                    results.append(unknown_result(component, getattr(provider, "name", None)).canonicalized())
        except FuturesTimeoutError:
            for future, provider in future_to_provider.items():
                if future in completed:
                    continue
                if future.done():
                    try:
                        result = future.result()
                    except Exception:
                        result = unknown_result(component, getattr(provider, "name", None)).canonicalized()
                else:
                    future.cancel()
                    result = unknown_result(component, getattr(provider, "name", None)).canonicalized()
                results.append(result)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        return (choose_lifecycle_result(results) or unknown_result(component)).canonicalized()

    def _lookup_provider_safely(
        self,
        provider: LifecycleProvider,
        component: NormalizedComponent,
    ) -> LifecycleResult:
        try:
            result = provider.lookup(component).canonicalized()
        except Exception:
            result = unknown_result(component, getattr(provider, "name", None)).canonicalized()
        return result

    def _read_cache(self, db: Session, component: NormalizedComponent) -> ComponentLifecycleCache | None:
        lookup_key = build_lifecycle_lookup_key(component)
        cached = (
            db.execute(select(ComponentLifecycleCache).where(ComponentLifecycleCache.lookup_key == lookup_key))
            .scalars()
            .first()
        )
        if cached is not None:
            return cached
        name, version, ecosystem, purl, _cpe = component.cache_identity
        statement = select(ComponentLifecycleCache).where(
            ComponentLifecycleCache.normalized_name == name,
            ComponentLifecycleCache.normalized_version == version,
            ComponentLifecycleCache.ecosystem == ecosystem,
            ComponentLifecycleCache.purl == purl,
        )
        return db.execute(statement).scalars().first()

    def _write_cache(self, db: Session, component: NormalizedComponent, result: LifecycleResult) -> None:
        if result.manual_override:
            return
        upsert_lifecycle_cache_entries(
            db,
            [lifecycle_cache_row_from_result(component, result, cache_ttl_days=self.cache_ttl_days)],
        )

    def _cache_expired(self, cache_entry: ComponentLifecycleCache) -> bool:
        try:
            return datetime.fromisoformat(cache_entry.expires_at.replace("Z", "+00:00")) <= datetime.now(UTC)
        except (AttributeError, ValueError):
            return True

    def _result_from_cache(
        self,
        cache_entry: ComponentLifecycleCache,
        component: NormalizedComponent,
        *,
        stale: bool,
    ) -> LifecycleResult:
        evidence = cache_entry.evidence_json if isinstance(cache_entry.evidence_json, dict) else {}
        if stale:
            evidence = {**evidence, "stale_cache": True, "cache_expires_at": cache_entry.expires_at}
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            cpe=component.cpe,
            lifecycle_status=cache_entry.lifecycle_status or UNKNOWN,
            eos_date=cache_entry.eos_date,
            eol_date=cache_entry.eol_date,
            eof_date=cache_entry.eof_date,
            deprecated=bool(cache_entry.deprecated),
            unsupported=bool(cache_entry.unsupported),
            maintenance_status=cache_entry.maintenance_status,
            latest_version=cache_entry.latest_version,
            latest_supported_version=cache_entry.latest_supported_version,
            recommended_version=cache_entry.recommended_version,
            recommendation=cache_entry.recommendation,
            source_name=cache_entry.source_name,
            source_url=cache_entry.source_url,
            evidence=evidence,
            confidence=cache_entry.confidence or "Unknown",
            checked_at=cache_entry.checked_at,
            expires_at=cache_entry.expires_at,
            stale=stale,
        ).canonicalized()

    def _apply_result(
        self,
        component: SBOMComponent,
        result: LifecycleResult,
        normalized: NormalizedComponent,
    ) -> None:
        component.ecosystem = normalized.ecosystem
        component.lifecycle_status = result.lifecycle_status
        component.eos_date = result.eos_date
        component.eol_date = result.eol_date
        component.eof_date = result.eof_date
        component.deprecated = bool(result.deprecated)
        component.is_deprecated = bool(result.deprecated)
        component.unsupported = bool(result.unsupported)
        component.maintenance_status = result.maintenance_status
        component.latest_version = result.latest_version
        component.latest_supported_version = result.latest_supported_version
        component.recommended_version = result.recommended_version
        component.lifecycle_recommendation = result.recommendation
        component.lifecycle_source = result.source_name
        component.lifecycle_source_url = result.source_url
        component.lifecycle_confidence = result.confidence
        component.lifecycle_checked_at = result.checked_at or now_iso()
        component.lifecycle_evidence_json = result.evidence
        component.lifecycle_is_stale = bool(result.stale)
        if not result.manual_override:
            component.lifecycle_manual_override = False


def summarize_components(components: list[SBOMComponent]) -> dict[str, Any]:
    summary = {
        "total_components": len(components),
        "supported_count": 0,
        "eol_count": 0,
        "eos_count": 0,
        "eof_count": 0,
        "deprecated_count": 0,
        "unsupported_count": 0,
        "unknown_count": 0,
        "eol_soon_count": 0,
        "possibly_unmaintained_count": 0,
        "stale_lifecycle_count": 0,
    }
    for component in components:
        status = canonical_status(component.lifecycle_status)
        if status == "Supported":
            summary["supported_count"] += 1
        elif status == EOL:
            summary["eol_count"] += 1
        elif status == EOS:
            summary["eos_count"] += 1
        elif status == EOF:
            summary["eof_count"] += 1
        elif status == DEPRECATED:
            summary["deprecated_count"] += 1
        elif status == UNSUPPORTED or bool(component.unsupported):
            summary["unsupported_count"] += 1
        elif status == EOL_SOON:
            summary["eol_soon_count"] += 1
        elif status == POSSIBLY_UNMAINTAINED or component.maintenance_status == POSSIBLY_UNMAINTAINED:
            summary["possibly_unmaintained_count"] += 1
        else:
            summary["unknown_count"] += 1
        if bool(component.lifecycle_is_stale):
            summary["stale_lifecycle_count"] += 1
    summary["top_risky_components"] = [
        component_lifecycle_dict(component)
        for component in sorted(components, key=_risk_sort_key, reverse=True)
        if canonical_status(component.lifecycle_status)
        in {EOL, EOS, EOF, DEPRECATED, UNSUPPORTED, EOL_SOON, POSSIBLY_UNMAINTAINED}
        or component.maintenance_status == POSSIBLY_UNMAINTAINED
    ][:10]
    summary["recommended_upgrades"] = [
        component_lifecycle_dict(component)
        for component in components
        if component.recommended_version or component.lifecycle_recommendation
    ][:10]
    return summary


def component_lifecycle_dict(component: SBOMComponent) -> dict[str, Any]:
    return {
        "id": component.id,
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "purl": component.purl,
        "cpe": component.cpe,
        "supplier": component.supplier,
        "license": component.license,
        "lifecycle_status": canonical_status(component.lifecycle_status),
        "eos_date": component.eos_date,
        "eol_date": component.eol_date,
        "eof_date": component.eof_date,
        "deprecated": bool(component.deprecated or component.is_deprecated),
        "unsupported": bool(component.unsupported),
        "maintenance_status": component.maintenance_status,
        "latest_version": component.latest_version,
        "latest_supported_version": component.latest_supported_version,
        "recommended_version": component.recommended_version,
        "recommendation": component.lifecycle_recommendation,
        "source_name": component.lifecycle_source,
        "source_url": component.lifecycle_source_url,
        "confidence": component.lifecycle_confidence,
        "checked_at": component.lifecycle_checked_at,
        "evidence": component.lifecycle_evidence_json,
        "is_stale": bool(component.lifecycle_is_stale),
        "manual_override": bool(component.lifecycle_manual_override),
    }


def _risk_sort_key(component: SBOMComponent) -> int:
    status = canonical_status(component.lifecycle_status)
    weights = {EOL: 7, UNSUPPORTED: 6, EOS: 5, EOF: 4, DEPRECATED: 3, EOL_SOON: 2, POSSIBLY_UNMAINTAINED: 1}
    if status == UNKNOWN and component.maintenance_status == POSSIBLY_UNMAINTAINED:
        return 1
    return weights.get(status, 0)


def _component_lifecycle_state(component: SBOMComponent) -> dict[str, Any]:
    return {
        "lifecycle_status": component.lifecycle_status,
        "eos_date": component.eos_date,
        "eol_date": component.eol_date,
        "eof_date": component.eof_date,
        "maintenance_status": component.maintenance_status,
        "latest_version": component.latest_version,
        "recommended_version": component.recommended_version,
        "source": component.lifecycle_source,
    }


def sync_lifecycle_for_sbom(db: Session, sbom_id: int, *, force_refresh: bool = False) -> dict[str, Any]:
    return LifecycleEnrichmentService().enrich_sbom(db, sbom_id, force_refresh=force_refresh)


def lifecycle_report_csv(db: Session, sbom_id: int, *, report_type: str | None = None) -> str:
    import csv
    import io
    import json

    report = LifecycleEnrichmentService().lifecycle_report(db, sbom_id)
    components = _filter_lifecycle_components(report["components"], report_type)
    out = io.StringIO()
    writer = csv.DictWriter(
        out,
        fieldnames=[
            "component_id",
            "name",
            "version",
            "ecosystem",
            "purl",
            "supplier",
            "lifecycle_status",
            "eos_date",
            "eol_date",
            "eof_date",
            "deprecated",
            "unsupported",
            "maintenance_status",
            "latest_version",
            "recommended_version",
            "recommendation",
            "source_name",
            "source_url",
            "confidence",
            "checked_at",
            "is_stale",
            "manual_override",
            "source_authority",
            "evidence_json",
        ],
    )
    writer.writeheader()
    for component in components:
        writer.writerow(
            {
                "component_id": component.get("id"),
                "name": component.get("name"),
                "version": component.get("version"),
                "ecosystem": component.get("ecosystem"),
                "purl": component.get("purl"),
                "supplier": component.get("supplier"),
                "lifecycle_status": component.get("lifecycle_status"),
                "eos_date": component.get("eos_date"),
                "eol_date": component.get("eol_date"),
                "eof_date": component.get("eof_date"),
                "deprecated": component.get("deprecated"),
                "unsupported": component.get("unsupported"),
                "maintenance_status": component.get("maintenance_status"),
                "latest_version": component.get("latest_version"),
                "recommended_version": component.get("recommended_version"),
                "recommendation": component.get("recommendation"),
                "source_name": component.get("source_name"),
                "source_url": component.get("source_url"),
                "confidence": component.get("confidence"),
                "checked_at": component.get("checked_at"),
                "is_stale": component.get("is_stale"),
                "manual_override": component.get("manual_override"),
                "source_authority": (
                    component.get("evidence", {}).get("authority")
                    if isinstance(component.get("evidence"), dict)
                    else None
                ),
                "evidence_json": json.dumps(component.get("evidence") or {}, sort_keys=True),
            }
        )
    return out.getvalue()


def _filter_lifecycle_components(components: list[dict[str, Any]], report_type: str | None) -> list[dict[str, Any]]:
    key = (report_type or "all").strip().lower().replace("-", "_")
    if key in {"all", "json", "csv", ""}:
        return components
    if key in {"unsupported", "unsupported_component", "unsupported_components"}:
        return [
            c for c in components if c.get("unsupported") or canonical_status(c.get("lifecycle_status")) == UNSUPPORTED
        ]
    if key in {"eol", "eos", "eof", "eol_eos_eof"}:
        return [
            c
            for c in components
            if canonical_status(c.get("lifecycle_status")) in {EOL, EOS, EOF}
            or c.get("eol_date")
            or c.get("eos_date")
            or c.get("eof_date")
        ]
    if key in {"deprecated", "deprecated_component", "deprecated_components"}:
        return [
            c for c in components if c.get("deprecated") or canonical_status(c.get("lifecycle_status")) == DEPRECATED
        ]
    return components


def refresh_component_lifecycle(db: Session, component_id: int, *, force_refresh: bool = True) -> SBOMComponent:
    component = db.get(SBOMComponent, component_id)
    if component is None:
        raise HTTPException(status_code=404, detail="Component not found")
    LifecycleEnrichmentService().enrich_component(db, component, force_refresh=force_refresh)
    db.commit()
    db.refresh(component)
    return component


__all__ = [
    "LifecycleEnrichmentService",
    "component_lifecycle_dict",
    "lifecycle_report_csv",
    "refresh_component_lifecycle",
    "summarize_components",
    "sync_lifecycle_for_sbom",
]
