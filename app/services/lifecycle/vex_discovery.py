"""Vendor-hosted VEX discovery.

Discovery is deliberately best-effort and side-effect isolated from SBOM
upload. A failed provider returns an error entry; it never blocks normal SBOM
ingest or lifecycle enrichment.
"""

from __future__ import annotations

import json
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import SBOMComponent, SBOMSource, VexDocument
from ..source_response_cache import SourceResponseCacheRepository
from .vex_provider import import_vex_document

DISCOVERY_CACHE_TTL_SECONDS = 24 * 60 * 60


@dataclass(slots=True)
class DiscoveredVexDocument:
    url: str
    document: dict[str, Any]
    provider: str
    evidence: dict[str, Any] = field(default_factory=dict)


class VendorVexDiscoveryProvider:
    name = "Vendor VEX Discovery"

    def __init__(
        self,
        *,
        http_get: Callable[[str], Any] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._http_get = http_get
        self._timeout_seconds = timeout_seconds

    def candidates(self, sbom: SBOMSource, components: list[SBOMComponent]) -> list[str]:
        raw = _load_sbom_json(sbom)
        urls: list[str] = []
        if isinstance(raw, dict):
            urls.extend(_urls_from_external_references(raw.get("externalReferences") or raw.get("external_references")))
            metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
            urls.extend(_urls_from_external_references(metadata.get("externalReferences") or metadata.get("external_references")))
            for component in raw.get("components") or raw.get("packages") or []:
                if isinstance(component, dict):
                    urls.extend(_urls_from_external_references(component.get("externalReferences") or component.get("external_references")))
        for component in components:
            for value in (component.purl, component.cpe):
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    urls.append(value)
        return _dedupe_safe_urls(urls)

    def discover(self, sbom: SBOMSource, components: list[SBOMComponent]) -> list[DiscoveredVexDocument]:
        found: list[DiscoveredVexDocument] = []
        for url in self.candidates(sbom, components):
            payload = self._get_json(url)
            if _looks_like_vex(payload):
                found.append(
                    DiscoveredVexDocument(
                        url=url,
                        document=payload,
                        provider=self.name,
                        evidence={"candidate_url": url, "candidate_source": "sbom_external_reference"},
                    )
                )
        return found

    def _get_json(self, url: str) -> Any | None:
        try:
            if self._http_get is not None:
                return self._http_get(url)
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=True) as client:
                response = client.get(url, headers={"Accept": "application/json, application/vnd.csaf+json"})
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            return None


class OpenVexDiscoveryProvider(VendorVexDiscoveryProvider):
    name = "OpenVEX Discovery"

    def candidates(self, sbom: SBOMSource, components: list[SBOMComponent]) -> list[str]:
        urls = [url for url in super().candidates(sbom, components) if "openvex" in url.lower() or "vex" in url.lower()]
        return _dedupe_safe_urls(urls)


class CsafVexDiscoveryProvider(VendorVexDiscoveryProvider):
    name = "CSAF VEX Discovery"

    def candidates(self, sbom: SBOMSource, components: list[SBOMComponent]) -> list[str]:
        urls = [url for url in super().candidates(sbom, components) if "csaf" in url.lower() or "vex" in url.lower()]
        return _dedupe_safe_urls(urls)


def discover_and_import_vex_documents(
    db: Session,
    sbom_id: int,
    *,
    providers: list[VendorVexDiscoveryProvider] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)).scalars().all()
    providers = providers or [OpenVexDiscoveryProvider(), CsafVexDiscoveryProvider(), VendorVexDiscoveryProvider()]

    discovered = 0
    imported = 0
    matched = 0
    unmatched = 0
    errors: list[dict[str, Any]] = []
    cache = SourceResponseCacheRepository(db)

    for provider in providers:
        try:
            candidate_urls = provider.candidates(sbom, list(components))
        except Exception as exc:
            errors.append({"provider": provider.name, "error": str(exc)})
            continue
        for url in candidate_urls:
            cache_key = f"sbom:{sbom_id}:{url}"
            payload = None if force else cache.get("vex_discovery", cache_key)
            if payload is None:
                payload = provider._get_json(url)
                if payload is not None:
                    cache.set("vex_discovery", cache_key, payload, ttl_seconds=DISCOVERY_CACHE_TTL_SECONDS)
            if not _looks_like_vex(payload):
                continue
            discovered += 1
            if not force and _existing_discovered_document(db, sbom_id, url):
                continue
            try:
                result = import_vex_document(
                    db,
                    sbom_id,
                    payload,
                    source_type="discovered",
                    source_name=provider.name,
                    source_url=url,
                    discovery_evidence={
                        "provider": provider.name,
                        "source_url": url,
                        "cached": not force,
                        "discovered_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                    },
                    last_refresh_status="imported",
                    provider_errors=errors or None,
                )
            except HTTPException as exc:
                errors.append({"provider": provider.name, "url": url, "error": str(exc.detail)})
                continue
            imported += int(result.get("statements_imported") or 0)
            matched += int(result.get("matched_statements") or 0)
            unmatched += int(result.get("unmatched_statements") or 0)

    return {
        "sbom_id": sbom_id,
        "discovered_documents": discovered,
        "statements_imported": imported,
        "matched_statements": matched,
        "unmatched_statements": unmatched,
        "errors": errors,
    }


def _existing_discovered_document(db: Session, sbom_id: int, url: str) -> bool:
    return (
        db.execute(
            select(VexDocument.id)
            .where(VexDocument.sbom_id == sbom_id)
            .where(VexDocument.source_type == "discovered")
            .where(VexDocument.source_url == url)
        ).first()
        is not None
    )


def _load_sbom_json(sbom: SBOMSource) -> dict[str, Any] | None:
    if not sbom.sbom_data:
        return None
    try:
        payload = json.loads(sbom.sbom_data)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _urls_from_external_references(refs: Any) -> list[str]:
    urls: list[str] = []
    for ref in refs or []:
        if not isinstance(ref, dict):
            continue
        kind = str(ref.get("type") or ref.get("category") or ref.get("comment") or "").lower()
        url = ref.get("url") or ref.get("locator") or ref.get("reference")
        if not isinstance(url, str):
            continue
        if any(token in kind for token in ("vex", "exploitability", "advisory", "security", "csaf")) or any(
            token in url.lower() for token in ("vex", "openvex", "csaf")
        ):
            urls.append(url)
    return urls


def _dedupe_safe_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    safe: list[str] = []
    for url in urls:
        if not _is_safe_public_http_url(url):
            continue
        cleaned = url.strip()
        if cleaned not in seen:
            seen.add(cleaned)
            safe.append(cleaned)
    return safe[:25]


def _is_safe_public_http_url(url: str) -> bool:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return False
    hostname = parsed.hostname.strip().lower().rstrip(".")
    if hostname in {"localhost", "metadata.google.internal"}:
        return False
    if hostname.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return True
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _looks_like_vex(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return (
        isinstance(payload.get("statements"), list)
        or isinstance(payload.get("vulnerabilities"), list)
        or (isinstance(payload.get("document"), dict) and isinstance(payload.get("product_tree"), dict))
    )


__all__ = [
    "CsafVexDiscoveryProvider",
    "DiscoveredVexDocument",
    "OpenVexDiscoveryProvider",
    "VendorVexDiscoveryProvider",
    "discover_and_import_vex_documents",
]
